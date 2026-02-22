#!/usr/bin/env python3
"""RDS Tag Manager - Add tags to RDS clusters and instances.

Features:
- List all RDS DB clusters and instances
- Filter by name prefix (optional)
- Multiple tagging modes:
  1. Interactive: prompt for key and value for each resource
  2. Fixed key: set tag key, ask value for each resource
  3. Auto: automatically set key and value for all resources
  
Uses utils.session for AWS authentication and utils.logger for logging.
"""
import argparse
import sys
from typing import List, Dict, Any

from utils.logger import logger_aws_toolkit
from utils.session import get_session
from tags.tag_utils import (
    filter_by_name,
    print_resource_info,
    mode_interactive,
    mode_fixed_key,
    mode_auto
)


logger = logger_aws_toolkit()


def list_rds_clusters(rds_client, prefix: str = None, suffix: str = None, contains: str = None) -> List[Dict[str, Any]]:
    """List all RDS clusters, optionally filtered by name pattern."""
    logger.info('Listing RDS clusters')
    try:
        paginator = rds_client.get_paginator('describe_db_clusters')
        clusters = []
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_id = cluster['DBClusterIdentifier']
                if not filter_by_name(cluster_id, prefix, suffix, contains):
                    continue
                clusters.append({
                    'arn': cluster['DBClusterArn'],
                    'identifier': cluster_id,
                    'type': 'cluster',
                    'engine': cluster.get('Engine', 'unknown'),
                    'status': cluster.get('Status', 'unknown')
                })
        logger.info(f'Found {len(clusters)} RDS clusters')
        return clusters
    except Exception as e:
        logger.error(f'Error listing RDS clusters: {e}')
        return []


def list_rds_instances(rds_client, prefix: str = None, suffix: str = None, contains: str = None) -> List[Dict[str, Any]]:
    """List all RDS instances, optionally filtered by name pattern."""
    logger.info('Listing RDS instances')
    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        instances = []
        for page in paginator.paginate():
            for instance in page['DBInstances']:
                instance_id = instance['DBInstanceIdentifier']
                if not filter_by_name(instance_id, prefix, suffix, contains):
                    continue
                instances.append({
                    'arn': instance['DBInstanceArn'],
                    'identifier': instance_id,
                    'type': 'instance',
                    'engine': instance.get('Engine', 'unknown'),
                    'status': instance.get('DBInstanceStatus', 'unknown')
                })
        logger.info(f'Found {len(instances)} RDS instances')
        return instances
    except Exception as e:
        logger.error(f'Error listing RDS instances: {e}')
        return []


def get_current_tags(rds_client, resource: Dict[str, Any]) -> Dict[str, str]:
    """Get current tags for an RDS resource."""
    try:
        response = rds_client.list_tags_for_resource(ResourceName=resource['arn'])
        return {tag['Key']: tag['Value'] for tag in response.get('TagList', [])}
    except Exception as e:
        logger.error(f"Error getting tags for {resource['arn']}: {e}")
        return {}


def add_tags_to_resource(rds_client, resource: Dict[str, Any], tags: Dict[str, str]) -> bool:
    """Add tags to an RDS resource."""
    try:
        tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
        rds_client.add_tags_to_resource(
            ResourceName=resource['arn'],
            Tags=tag_list
        )
        logger.info(f"Successfully added tags to {resource['arn']}")
        return True
    except Exception as e:
        logger.error(f"Error adding tags to {resource['arn']}: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Add tags to RDS clusters and instances',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode - prompt for key and value for each resource
  %(prog)s --mode interactive
  
  # Fixed key mode - set key, ask value for each resource
  %(prog)s --mode fixed-key --key Environment
  
  # Auto mode - set key and value for all resources
  %(prog)s --mode auto --key Owner --value DevOps
  
  # Filter by name prefix
  %(prog)s --mode interactive --prefix prod-
  
  # Include only clusters or only instances
  %(prog)s --mode auto --key Backup --value enabled --clusters-only
  %(prog)s --mode auto --key Backup --value enabled --instances-only
        """
    )
    parser.add_argument('--mode', required=True, 
                        choices=['interactive', 'fixed-key', 'auto'],
                        help='Tagging mode')
    parser.add_argument('--key', help='Tag key (required for fixed-key and auto modes)')
    parser.add_argument('--value', help='Tag value (required for auto mode)')
    
    # Filter options
    parser.add_argument('--prefix', help='Filter resources by name prefix')
    parser.add_argument('--suffix', help='Filter resources by name suffix')
    parser.add_argument('--contains', help='Filter resources by name containing this string')
    
    parser.add_argument('--clusters-only', action='store_true', help='Only process DB clusters')
    parser.add_argument('--instances-only', action='store_true', help='Only process DB instances')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', help='AWS region name')
    parser.add_argument('--yes', action='store_true', help='Skip confirmation in auto mode')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode == 'fixed-key' and not args.key:
        parser.error("--key is required for fixed-key mode")
    if args.mode == 'auto' and (not args.key or not args.value):
        parser.error("--key and --value are required for auto mode")
    if args.clusters_only and args.instances_only:
        parser.error("Cannot specify both --clusters-only and --instances-only")
    
    # Get AWS session
    try:
        session = get_session(
            region_name=args.region if args.region else None,
            profile_name=args.profile if args.profile else None
        )
        rds_client = session.client('rds')
        logger.info('AWS session established')
    except Exception as e:
        logger.error(f'Failed to establish AWS session: {e}')
        print(f'ERROR: Failed to establish AWS session: {e}', file=sys.stderr)
        return 1
    
    # List resources
    resources = []
    if not args.instances_only:
        resources.extend(list_rds_clusters(rds_client, args.prefix, args.suffix, args.contains))
    if not args.clusters_only:
        resources.extend(list_rds_instances(rds_client, args.prefix, args.suffix, args.contains))
    
    if not resources:
        print('No resources found')
        return 0
    
    print(f'\nFound {len(resources)} resource(s)')
    
    # Create wrapper functions for the shared mode functions
    def get_tags_wrapper(resource):
        return get_current_tags(rds_client, resource)
    
    def add_tags_wrapper(resource, tags):
        return add_tags_to_resource(rds_client, resource, tags)
    
    # Execute tagging based on mode
    failures = 0
    if args.mode == 'interactive':
        failures = mode_interactive(resources, get_tags_wrapper, add_tags_wrapper)
    elif args.mode == 'fixed-key':
        failures = mode_fixed_key(resources, args.key, get_tags_wrapper, add_tags_wrapper)
    elif args.mode == 'auto':
        failures = mode_auto(resources, args.key, args.value, add_tags_wrapper, args.yes)
    
    if failures > 0:
        print(f'\n{failures} resource(s) failed to tag')
        return 2
    
    print('\nAll operations completed successfully')
    return 0


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
