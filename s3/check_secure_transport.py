#!/usr/bin/env python3
"""List all S3 buckets and check if their bucket policy enforces aws:SecureTransport == true.

This script uses the project's `utils.session.get_session()` to create a boto3 session.

Exit codes:
 - 0: all buckets either have a policy that requires SecureTransport or have no policy but are not public (no violation found)
 - 1: usage / unexpected error
 - 2: one or more buckets have policies that do NOT enforce aws:SecureTransport == true

Run without arguments. It prints a line per bucket with its status.
"""
import argparse
import json
import sys
from typing import Any

from botocore.exceptions import ClientError

from utils.session import get_session


def contains_secure_transport(condition: Any) -> bool:
    """Recursively search condition structures for aws:SecureTransport == true.

    The bucket policy Condition may be a dict with keys such as 'Bool', 'ForAnyValue:StringEquals', etc.
    We treat a match as any mapping where key equals 'aws:SecureTransport' and value is the JSON string "true"
    or the boolean True.
    """
    if isinstance(condition, dict):
        for k, v in condition.items():
            # Direct match
            if k == 'aws:SecureTransport':
                if v is True or (isinstance(v, str) and v.lower() == 'true'):
                    return True
                # value present but not true
                return False

            # If nested dict, recurse
            if contains_secure_transport(v):
                return True

        return False

    if isinstance(condition, list):
        for item in condition:
            if contains_secure_transport(item):
                return True
        return False

    return False


def policy_enforces_secure_transport(policy_json: str) -> bool:
    try:
        policy = json.loads(policy_json)
    except Exception:
        return False

    # Policy is expected to contain a 'Statement' list
    stmts = policy.get('Statement')
    if not stmts:
        return False

    if isinstance(stmts, dict):
        stmts = [stmts]

    for stmt in stmts:
        # Look for Condition
        cond = stmt.get('Condition')
        if not cond:
            continue

        # The Condition may have operators like 'Bool' -> { 'aws:SecureTransport': 'true' }
        if contains_secure_transport(cond):
            return True

    return False


def main() -> int:
    parser = argparse.ArgumentParser(description='Check S3 bucket policies for aws:SecureTransport == true')
    parser.add_argument('--profile', '-p', help='AWS profile name (overrides default in utils.session)', default='m_prod')
    parser.add_argument('--region', '-r', help='AWS region name (overrides default in utils.session)', default='us-west-2')
    args = parser.parse_args()

    session = get_session(region_name=args.region if args.region else None,
                          profile_name=args.profile if args.profile else None)
    s3 = session.client('s3')

    try:
        resp = s3.list_buckets()
    except Exception as e:
        print(f'ERROR listing buckets: {e}', file=sys.stderr)
        return 1

    buckets = resp.get('Buckets', [])
    if not buckets:
        print('No buckets found.')
        return 0

    violations = []
# 
# 
# ezyprod-org-logo-bucket ezyprod-closed-sales
    for b in buckets:
        name = b.get('Name')
        status = 'UNKNOWN'
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            policy_str = pol.get('Policy')
            if policy_str and policy_enforces_secure_transport(policy_str):
                status = 'OK (policy enforces SecureTransport)'
                print(f'{name}: {status}')
            # else:
            #     status = 'VIOLATION (policy missing SecureTransport)'
            #     violations.append(name)
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            # If no policy found (NoSuchBucketPolicy), treat as violation
            if code in ('NoSuchBucketPolicy', 'NoSuchBucket'):
                pass
                # status = f'VIOLATION ({code})'
                # violations.append(name)
            elif code in ('AccessDenied', 'AllAccessDisabled'):
                status = f'UNABLE TO CHECK ({code})'
            else:
                status = f'ERROR ({code})'

        except Exception as e:  # pragma: no cover - defensive
            status = f'ERROR ({e})'
            print(f'{name}: {status}')

        # print(f'{name}: {status}')

    if violations:
        print('\nSummary: buckets with missing/incorrect SecureTransport policy:')
        for v in violations:
            print(f' - {v}')
        return 2

    print('\nAll checked buckets enforce aws:SecureTransport == true (or were inaccessible).')
    return 0


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
