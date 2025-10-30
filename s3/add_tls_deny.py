#!/usr/bin/env python3
"""Add or merge a TLS deny statement to S3 bucket policies.

This script will add the following statement to the target bucket policy if it's not present
or will replace an existing statement with Sid 'TLSVerification':

{
    "Sid": "TLSVerification",
    "Principal": "*",
    "Effect": "Deny",
    "Action": ["s3:*"],
    "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
}

Usage: run with --bucket BUCKET or --all to process all buckets. Supports --profile and --region.
"""
import argparse
import json
import sys
from typing import Dict, Any, List, Tuple

from botocore.exceptions import ClientError

try:
    from ..utils.session import get_session
except Exception:  # pragma: no cover - allow direct execution
    from utils.session import get_session


TLS_STATEMENT_TEMPLATE: Dict[str, Any] = {
    "Sid": "TLSVerification",
    "Principal": "*",
    "Effect": "Deny",
    "Action": ["s3:*"] ,
    "Resource": [],  # to be filled with bucket ARNs
    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
}


def load_policy(s3, bucket: str) -> Dict[str, Any]:
    try:
        resp = s3.get_bucket_policy(Bucket=bucket)
        policy = json.loads(resp['Policy'])
        return policy
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code')
        if code == 'NoSuchBucketPolicy':
            return {"Version": "2012-10-17", "Statement": []}
        raise


def save_policy(s3, bucket: str, policy: Dict[str, Any]) -> None:
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def make_tls_statement(bucket: str) -> Dict[str, Any]:
    stmt = json.loads(json.dumps(TLS_STATEMENT_TEMPLATE))
    stmt['Resource'] = [f'arn:aws:s3:::{bucket}/*']
    return stmt


def ensure_tls_statement(policy: Dict[str, Any], bucket: str) -> Tuple[Dict[str, Any], bool]:
    """Ensure the TLS statement exists in policy. Returns (new_policy, changed).
    If a statement with Sid TLSVerification exists, it will be replaced. Otherwise appended.
    """
    stmts = policy.get('Statement')
    if stmts is None:
        policy['Statement'] = []
        stmts = policy['Statement']

    if isinstance(stmts, dict):
        stmts = [stmts]

    changed = False
    new_stmt = make_tls_statement(bucket)

    # Look for existing by Sid
    for i, s in enumerate(stmts):
        if s.get('Sid') == 'TLSVerification':
            # If identical, no change
            if s == new_stmt:
                return policy, False
            stmts[i] = new_stmt
            changed = True
            break

    if not changed:
        stmts.append(new_stmt)
        changed = True

    policy['Statement'] = stmts
    if 'Version' not in policy:
        policy['Version'] = '2012-10-17'

    return policy, changed


def process_bucket(s3, bucket: str) -> bool:
    try:
        policy = load_policy(s3, bucket)
    except ClientError as e:
        print(f'{bucket}: unable to load policy: {e}', file=sys.stderr)
        return False

    new_policy, changed = ensure_tls_statement(policy, bucket)
    if not changed:
        print(f'{bucket}: already has TLSVerification (no change)')
        return True

    try:
        save_policy(s3, bucket, new_policy)
        print(f'{bucket}: TLSVerification statement added/updated')
        return True
    except ClientError as e:
        print(f'{bucket}: failed to save policy: {e}', file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description='Add TLS deny statement to S3 bucket policies')
    parser.add_argument('--bucket', '-b', help='Bucket name to modify')
    parser.add_argument('--all', action='store_true', help='Modify all buckets')
    parser.add_argument('--profile', '-p', help='AWS profile name', default=None)
    parser.add_argument('--region', '-r', help='AWS region name', default=None)
    args = parser.parse_args()

    if not args.bucket and not args.all:
        print('Specify --bucket BUCKET or --all', file=sys.stderr)
        return 1

    session = get_session(region_name=args.region if args.region else None,
                          profile_name=args.profile if args.profile else None)
    s3 = session.client('s3')

    buckets: List[str] = []
    if args.all:
        resp = s3.list_buckets()
        buckets = [b['Name'] for b in resp.get('Buckets', [])]
    else:
        buckets = [args.bucket]

    success = True
    for b in buckets:
        ok = process_bucket(s3, b)
        success = success and ok

    return 0 if success else 2


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
