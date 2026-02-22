#!/usr/bin/env python3
"""EC2 Tag Manager - Add tags to EC2 instances, volumes, and snapshots.

Features:
- List EC2 instances, volumes, and/or snapshots
- Filter by name prefix, suffix, or contains pattern
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


def list_ec2_instances(ec2_client, prefix: str = None, suffix: str = None, contains: str = None) -> List[Dict[str, Any]]:
    """List all EC2 instances, optionally filtered by name pattern."""
    logger.info('Listing EC2 instances')
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        instances = []
        
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Get name from tags
                    name = None
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    name = tags.get('Name', instance_id)
                    
                    if not filter_by_name(name, prefix, suffix, contains):
                        continue
                    
                    instances.append({
                        'id': instance_id,
                        'identifier': name,
                        'type': 'instance',
                        'instance_type': instance.get('InstanceType', 'unknown'),
                        'state': instance.get('State', {}).get('Name', 'unknown'),
                        'tags': tags
                    })
        
        logger.info(f'Found {len(instances)} EC2 instances')
        return instances
    except Exception as e:
        logger.error(f'Error listing EC2 instances: {e}')
        return []


def list_ec2_volumes(ec2_client, prefix: str = None, suffix: str = None, contains: str = None) -> List[Dict[str, Any]]:
    """List all EC2 volumes, optionally filtered by name pattern."""
    logger.info('Listing EC2 volumes')
    try:
        paginator = ec2_client.get_paginator('describe_volumes')
        volumes = []
        
        for page in paginator.paginate():
            for volume in page['Volumes']:
                volume_id = volume['VolumeId']
                
                # Get name from tags
                tags = {tag['Key']: tag['Value'] for tag in volume.get('Tags', [])}
                name = tags.get('Name', volume_id)
                
                if not filter_by_name(name, prefix, suffix, contains):
                    continue
                
                volumes.append({
                    'id': volume_id,
                    'identifier': name,
                    'type': 'volume',
                    'size': f"{volume.get('Size', 0)} GB",
                    'state': volume.get('State', 'unknown'),
                    'tags': tags
                })
        
        logger.info(f'Found {len(volumes)} EC2 volumes')
        return volumes
    except Exception as e:
        logger.error(f'Error listing EC2 volumes: {e}')
        return []


def list_ec2_snapshots(ec2_client, owner_id: str, prefix: str = None, suffix: str = None, contains: str = None) -> List[Dict[str, Any]]:
    """List EC2 snapshots owned by account, optionally filtered by name pattern."""
    logger.info('Listing EC2 snapshots')
    try:
        paginator = ec2_client.get_paginator('describe_snapshots')
        snapshots = []
        
        for page in paginator.paginate(OwnerIds=[owner_id]):
            for snapshot in page['Snapshots']:
                snapshot_id = snapshot['SnapshotId']
                
                # Get name from tags
                tags = {tag['Key']: tag['Value'] for tag in snapshot.get('Tags', [])}
                name = tags.get('Name', snapshot_id)
                
                if not filter_by_name(name, prefix, suffix, contains):
                    continue
                
                snapshots.append({
                    'id': snapshot_id,
                    'identifier': name,
                    'type': 'snapshot',
                    'size': f"{snapshot.get('VolumeSize', 0)} GB",
                    'state': snapshot.get('State', 'unknown'),
                    'tags': tags
                })
        
        logger.info(f'Found {len(snapshots)} EC2 snapshots')
        return snapshots
    except Exception as e:
        logger.error(f'Error listing EC2 snapshots: {e}')
        return []


def get_current_tags(resource: Dict[str, Any]) -> Dict[str, str]:
    """Get current tags for a resource."""
    return resource.get('tags', {})


def add_tags_to_resource(ec2_client, resource: Dict[str, Any], tags: Dict[str, str]) -> bool:
    """Add tags to an EC2 resource."""
    try:
        tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
        ec2_client.create_tags(
            Resources=[resource['id']],
            Tags=tag_list
        )
        logger.info(f"Successfully added tags to {resource['id']}")
        return True
    except Exception as e:
        logger.error(f"Error adding tags to {resource['id']}: {e}")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Add tags to EC2 instances, volumes, and snapshots',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode - prompt for key and value for each resource
  %(prog)s --mode interactive --instances
  
  # Fixed key mode - set key, ask value for each resource
  %(prog)s --mode fixed-key --key Environment --instances --volumes
  
  # Auto mode - set key and value for all resources
  %(prog)s --mode auto --key Owner --value DevOps --instances
  
  # Filter by name patterns
  %(prog)s --mode interactive --prefix prod- --instances
  %(prog)s --mode interactive --suffix -db --volumes
  %(prog)s --mode interactive --contains staging --instances
  
  # Combine multiple resource types
  %(prog)s --mode auto --key Backup --value enabled --instances --volumes --snapshots
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
    
    # Resource type options
    parser.add_argument('--instances', action='store_true', help='Process EC2 instances')
    parser.add_argument('--volumes', action='store_true', help='Process EC2 volumes')
    parser.add_argument('--snapshots', action='store_true', help='Process EC2 snapshots')
    
    # AWS options
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', help='AWS region name')
    parser.add_argument('--yes', action='store_true', help='Skip confirmation in auto mode')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.mode == 'fixed-key' and not args.key:
        parser.error("--key is required for fixed-key mode")
    if args.mode == 'auto' and (not args.key or not args.value):
        parser.error("--key and --value are required for auto mode")
    if not (args.instances or args.volumes or args.snapshots):
        parser.error("At least one resource type must be specified: --instances, --volumes, or --snapshots")
    
    # Get AWS session
    try:
        session = get_session(
            region_name=args.region if args.region else None,
            profile_name=args.profile if args.profile else None
        )
        ec2_client = session.client('ec2')
        logger.info('AWS session established')
    except Exception as e:
        logger.error(f'Failed to establish AWS session: {e}')
        print(f'ERROR: Failed to establish AWS session: {e}', file=sys.stderr)
        return 1
    
    # Get account ID for snapshots
    account_id = None
    if args.snapshots:
        try:
            sts_client = session.client('sts')
            account_id = sts_client.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f'Failed to get account ID: {e}')
            print(f'ERROR: Failed to get account ID for snapshot listing: {e}', file=sys.stderr)
            return 1
    
    # List resources
    resources = []
    if args.instances:
        resources.extend(list_ec2_instances(ec2_client, args.prefix, args.suffix, args.contains))
    if args.volumes:
        resources.extend(list_ec2_volumes(ec2_client, args.prefix, args.suffix, args.contains))
    if args.snapshots:
        resources.extend(list_ec2_snapshots(ec2_client, account_id, args.prefix, args.suffix, args.contains))
    
    if not resources:
        print('No resources found')
        return 0
    
    print(f'\nFound {len(resources)} resource(s)')
    
    # Create wrapper functions for the shared mode functions
    def get_tags_wrapper(resource):
        return get_current_tags(resource)
    
    def add_tags_wrapper(resource, tags):
        return add_tags_to_resource(ec2_client, resource, tags)
    
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
