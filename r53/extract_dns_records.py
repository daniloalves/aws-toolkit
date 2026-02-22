#!/usr/bin/env python3
"""Route53 DNS Record Extraction Tool

Extract DNS records from a specific Route53 hosted zone and save to file.
Output format: RecordName\tType\tValue(s)

Features:
- Extract records from one hosted zone by name or ID
- Auto-generated timestamped output files
- Pagination support for large zones (>300 records)
- Tab-delimited format matching existing r53/output.txt

Uses utils.session for AWS authentication and utils.logger for logging.

Exit codes:
 - 0: success (records extracted and written)
 - 1: error (AWS API failure, file I/O error, invalid arguments)

Examples:
    # Extract zone by name
    python r53/extract_dns_records.py --zone-name example.com

    # Extract zone by ID
    python r53/extract_dns_records.py --zone-id Z1234567890ABC

    # Use specific AWS profile and region
    python r53/extract_dns_records.py --zone-name example.com --profile prod --region us-east-1
"""
import argparse
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from botocore.exceptions import ClientError

from utils.logger import logger_aws_toolkit
from utils.session import get_session


logger = logger_aws_toolkit()


def find_hosted_zone_by_name(r53_client, zone_name: str) -> Optional[Dict[str, str]]:
    """Find a hosted zone by its domain name.

    Args:
        r53_client: Boto3 Route53 client
        zone_name: Domain name (e.g., 'example.com' or 'example.com.')

    Returns:
        Dict with zone_id and zone_name, or None if not found
    """
    logger.info(f'Searching for hosted zone: {zone_name}')

    # Ensure zone name ends with dot
    if not zone_name.endswith('.'):
        zone_name = zone_name + '.'

    try:
        # List all hosted zones
        paginator = r53_client.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                if zone['Name'] == zone_name:
                    zone_id = zone['Id'].split('/')[-1]  # Extract ID from '/hostedzone/Z123'
                    logger.info(f'Found zone: {zone_name} (ID: {zone_id})')
                    return {
                        'zone_id': zone_id,
                        'zone_name': zone['Name'],
                        'is_private': zone.get('Config', {}).get('PrivateZone', False)
                    }

        logger.warning(f'Hosted zone not found: {zone_name}')
        return None

    except ClientError as e:
        logger.error(f'AWS API error while listing hosted zones: {e}')
        return None
    except Exception as e:
        logger.error(f'Unexpected error while listing hosted zones: {e}')
        return None


def validate_zone_id(zone_id: str) -> str:
    """Validate and normalize hosted zone ID.

    Args:
        zone_id: Zone ID (may include '/hostedzone/' prefix)

    Returns:
        Normalized zone ID (just the ID part)

    Raises:
        ValueError: If zone ID format is invalid
    """
    # Remove '/hostedzone/' prefix if present
    if '/' in zone_id:
        zone_id = zone_id.split('/')[-1]

    # Zone IDs should start with 'Z' and be alphanumeric
    if not zone_id or not zone_id[0] == 'Z' or not zone_id[1:].replace('-', '').isalnum():
        raise ValueError(f'Invalid zone ID format: {zone_id}')

    return zone_id


def extract_record_values(record: Dict[str, Any]) -> str:
    """Extract and format values from a DNS record.

    Args:
        record: Route53 ResourceRecordSet dict

    Returns:
        Tab-delimited string of values, or 'None' if no values
    """
    # Handle alias records
    if 'AliasTarget' in record:
        alias_dns = record['AliasTarget'].get('DNSName', 'Unknown')
        return alias_dns

    # Handle standard resource records
    if 'ResourceRecords' in record:
        values = []
        for rr in record['ResourceRecords']:
            value = rr.get('Value', '')

            # For MX records, include priority if present
            if record['Type'] == 'MX' and ' ' in value:
                values.append(value)
            else:
                values.append(value)

        if values:
            return '\t'.join(values)

    return 'None'


def list_dns_records(r53_client, zone_id: str) -> List[Dict[str, str]]:
    """Extract all DNS records from a hosted zone.

    Args:
        r53_client: Boto3 Route53 client
        zone_id: Hosted zone ID

    Returns:
        List of dicts with keys: 'name', 'type', 'values'
    """
    logger.info(f'Extracting DNS records from zone: {zone_id}')

    records = []

    try:
        # Use paginator to handle zones with many records
        paginator = r53_client.get_paginator('list_resource_record_sets')
        page_iterator = paginator.paginate(HostedZoneId=zone_id)

        for page in page_iterator:
            for record_set in page['ResourceRecordSets']:
                name = record_set.get('Name', '')
                record_type = record_set.get('Type', '')
                values = extract_record_values(record_set)

                # Route53 Alias records are stored as A/AAAA but resolve to
                # a hostname (ELB, CloudFront, etc.), not a raw IP address.
                # Reclassify as CNAME so comparisons with other providers
                # (e.g. Cloudflare) are accurate.
                if 'AliasTarget' in record_set and record_type in ('A', 'AAAA'):
                    record_type = 'CNAME'

                records.append({
                    'name': name,
                    'type': record_type,
                    'values': values
                })

        logger.info(f'Extracted {len(records)} DNS records from zone {zone_id}')
        return records

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'NoSuchHostedZone':
            logger.error(f'Hosted zone not found: {zone_id}')
        elif error_code == 'AccessDenied':
            print(e)
            logger.error(f'Access denied to zone {zone_id}. Check IAM permissions.')
        elif error_code == 'Throttling':
            logger.error(f'API throttling detected for zone {zone_id}. Try again later.')
        else:
            logger.error(f'AWS API error extracting records from {zone_id}: {error_code} - {e}')
        return []
    except Exception as e:
        logger.error(f'Unexpected error extracting records from {zone_id}: {e}')
        return []


def format_dns_record(record: Dict[str, str]) -> str:
    """Format a DNS record for output.

    Args:
        record: Dict with 'name', 'type', 'values'

    Returns:
        Tab-delimited string: name\ttype\tvalues
    """
    return f"{record['name']}\t{record['type']}\t{record['values']}"


def generate_output_filename(zone_name: str, base_dir: str = None) -> str:
    """Generate timestamped output filename.

    Args:
        zone_name: Zone name (e.g., 'example.com.')
        base_dir: Base directory for output (default: r53/)

    Returns:
        Full path to output file
    """
    if base_dir is None:
        # Get the directory where this script is located
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = script_dir

    # Remove trailing dot from zone name for filename
    zone_name_clean = zone_name.rstrip('.')

    # Generate timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Create filename
    filename = f'r53_records_{zone_name_clean}_{timestamp}.txt'
    output_path = os.path.join(base_dir, filename)

    logger.debug(f'Generated output filename: {output_path}')
    return output_path


def write_records_to_file(records: List[Dict[str, str]], output_path: str) -> bool:
    """Write DNS records to file.

    Args:
        records: List of record dicts
        output_path: Path to output file

    Returns:
        True if successful, False otherwise
    """
    logger.info(f'Writing {len(records)} records to {output_path}')

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for record in records:
                formatted = format_dns_record(record)
                f.write(formatted + '\n')

        logger.info(f'Successfully wrote records to {output_path}')
        return True

    except PermissionError:
        logger.error(f'Permission denied writing to {output_path}')
        print(f'ERROR: Cannot write to {output_path}. Check permissions.', file=sys.stderr)
        return False
    except IOError as e:
        logger.error(f'I/O error writing to {output_path}: {e}')
        print(f'ERROR: Failed to write to {output_path}: {e}', file=sys.stderr)
        return False
    except Exception as e:
        logger.error(f'Unexpected error writing to {output_path}: {e}')
        print(f'ERROR: Failed to write to {output_path}: {e}', file=sys.stderr)
        return False


def main() -> int:
    """Main function for CLI usage.

    Returns:
        Exit code (0=success, 1=error)
    """
    parser = argparse.ArgumentParser(
        description='Extract Route53 DNS records from a specific hosted zone',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract zone by name
  %(prog)s --zone-name example.com

  # Extract zone by ID
  %(prog)s --zone-id Z1234567890ABC

  # Use specific AWS profile and region
  %(prog)s --zone-name example.com --profile prod --region us-east-1

Output:
  Auto-generated file: r53/r53_records_{zone_name}_{timestamp}.txt
  Format: RecordName\\tType\\tValue(s)

IAM Permissions Required:
  - route53:ListHostedZones
  - route53:ListResourceRecordSets
        """
    )

    # Zone selection (mutually exclusive)
    zone_group = parser.add_mutually_exclusive_group(required=True)
    zone_group.add_argument('--zone-id', help='Hosted zone ID (e.g., Z1234567890ABC)')
    zone_group.add_argument('--zone-name', help='Hosted zone name (e.g., example.com)')

    # AWS configuration
    parser.add_argument('--profile', '-p', help='AWS profile name (optional)')
    parser.add_argument('--region', '-r', help='AWS region name (optional)')

    args = parser.parse_args()

    logger.info(f'Starting DNS record extraction')

    # Initialize AWS session
    try:
        session_kwargs = {}
        if args.profile:
            session_kwargs['profile_name'] = args.profile
        if args.region:
            session_kwargs['region_name'] = args.region

        if session_kwargs:
            session = get_session(**session_kwargs)
        else:
            session = get_session()

        r53_client = session.client('route53')
        logger.debug('AWS Route53 client initialized')
    except Exception as e:
        logger.error(f'Failed to initialize AWS session: {e}')
        print(f'ERROR: Failed to initialize AWS session: {e}', file=sys.stderr)
        print('Check your AWS credentials and configuration.', file=sys.stderr)
        return 1

    # Determine zone ID
    zone_info = None

    if args.zone_id:
        # Validate and use provided zone ID
        try:
            zone_id = validate_zone_id(args.zone_id)
            zone_info = {
                'zone_id': zone_id,
                'zone_name': zone_id  # Use ID as placeholder for filename
            }
            logger.info(f'Using zone ID: {zone_id}')
        except ValueError as e:
            logger.error(f'Invalid zone ID: {e}')
            print(f'ERROR: {e}', file=sys.stderr)
            return 1

    elif args.zone_name:
        # Find zone by name
        zone_info = find_hosted_zone_by_name(r53_client, args.zone_name)
        if not zone_info:
            print(f'ERROR: Hosted zone not found: {args.zone_name}', file=sys.stderr)
            print('Run "aws route53 list-hosted-zones" to see available zones.', file=sys.stderr)
            return 1

    # Extract DNS records
    records = list_dns_records(r53_client, zone_info['zone_id'])

    if not records:
        logger.warning('No DNS records found or error occurred')
        print('No DNS records extracted. Check logs for details.', file=sys.stderr)
        return 1

    # Generate output filename
    output_path = generate_output_filename(zone_info['zone_name'])

    # Write records to file
    success = write_records_to_file(records, output_path)

    if not success:
        return 1

    # Print summary
    print(f'Successfully extracted {len(records)} DNS records')
    print(f'Output file: {output_path}')
    logger.info(f'DNS extraction completed successfully. Output: {output_path}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
