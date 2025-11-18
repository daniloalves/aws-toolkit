#!/usr/bin/env python3
"""List all S3 buckets and analyze their bucket policies for aws:SecureTransport conditions.

This script identifies buckets with different SecureTransport configurations:
- Buckets that enforce SecureTransport == true (secure)
- Buckets that allow SecureTransport == false (insecure)
- Buckets with mixed conditions
- Buckets with no SecureTransport conditions

This script uses the project's `utils.session.get_session()` to create a boto3 session.

Exit codes:
 - 0: all buckets have proper SecureTransport enforcement (SecureTransport == true)
 - 1: usage / unexpected error
 - 2: one or more buckets have insecure or missing SecureTransport policies

Run with --profile and --region options to specify AWS credentials and region.
"""
import argparse
import json
import sys
from typing import Any, Tuple

from botocore.exceptions import ClientError

from utils.session import get_session


def contains_secure_transport(condition: Any) -> Tuple[bool, str]:
    """Recursively search condition structures for aws:SecureTransport.

    The bucket policy Condition may be a dict with keys such as 'Bool', 'ForAnyValue:StringEquals', etc.
    Returns a tuple (found, value) where:
    - found: True if aws:SecureTransport key was found
    - value: "true", "false", or "unknown" indicating the value found
    """
    if isinstance(condition, dict):
        for k, v in condition.items():
            # Direct match
            if k == 'aws:SecureTransport':
                if v is True or (isinstance(v, str) and v.lower() == 'true'):
                    return True, "true"
                elif v is False or (isinstance(v, str) and v.lower() == 'false'):
                    return True, "false"
                else:
                    return True, "unknown"

            # If nested dict, recurse
            found, value = contains_secure_transport(v)
            if found:
                return found, value

        return False, "not_found"

    if isinstance(condition, list):
        for item in condition:
            found, value = contains_secure_transport(item)
            if found:
                return found, value
        return False, "not_found"

    return False, "not_found"

    def find_secure_transport_statements(policy: dict) -> list:
        """
        Find all statements with aws:SecureTransport condition.
        Returns a list of tuples: (effect, value) where value is 'true', 'false', or 'unknown'.
        """
        stmts = policy.get('Statement')
        if not stmts:
            return []
        if isinstance(stmts, dict):
            stmts = [stmts]
        results = []
        for stmt in stmts:
            cond = stmt.get('Condition')
            effect = stmt.get('Effect', '').lower()
            if not cond:
                continue
            found, value = _find_secure_transport_in_condition(cond)
            if found:
                results.append((effect, value))
        return results

    def _find_secure_transport_in_condition(condition: Any) -> Tuple[bool, str]:
        """Recursively search for aws:SecureTransport in a condition dict/list."""
        if isinstance(condition, dict):
            for k, v in condition.items():
                if k == 'aws:SecureTransport':
                    if v is True or (isinstance(v, str) and v.lower() == 'true'):
                        return True, "true"
                    elif v is False or (isinstance(v, str) and v.lower() == 'false'):
                        return True, "false"
                    else:
                        return True, "unknown"
                found, value = _find_secure_transport_in_condition(v)
                if found:
                    return found, value
            return False, "not_found"
        if isinstance(condition, list):
            for item in condition:
                found, value = _find_secure_transport_in_condition(item)
                if found:
                    return found, value
            return False, "not_found"
        return False, "not_found"


def analyze_secure_transport_policy(policy_json: str) -> Tuple[bool, str]:
    """
    Analyze policy for SecureTransport conditions and their effect.
    Returns (has_secure_transport, status):
      - has_secure_transport: True if any aws:SecureTransport condition was found
      - status: 'safe_deny', 'unsafe_allow', 'enforced_true', 'none', 'parse_error', or 'mixed'
    """
    try:
        policy = json.loads(policy_json)
    except Exception:
        return False, "parse_error"

    # Policy is expected to contain a 'Statement' list
    stmts = policy.get('Statement')
    if not stmts:
        return False, "none"

    if isinstance(stmts, dict):
        stmts = [stmts]

    found_deny_false = False
    found_allow_false = False
    found_allow_true = False
    
    for stmt in stmts:
        # Look for Condition
        cond = stmt.get('Condition')
        effect = stmt.get('Effect', '').lower()
        if not cond:
            continue

        # The Condition may have operators like 'Bool' -> { 'aws:SecureTransport': 'true' }
        found, value = contains_secure_transport(cond)
        if found:
            if value == "false" and effect == "deny":
                found_deny_false = True
            elif value == "false" and effect == "allow":
                found_allow_false = True
            elif value == "true" and effect == "allow":
                found_allow_true = True

    # If any statement allows insecure (false), it's unsafe
    if found_allow_false:
        return True, "unsafe_allow"
    # If any statement denies insecure (false), it's safe
    if found_deny_false:
        return True, "safe_deny"
    # If only allow true, it's also safe (enforces TLS)
    if found_allow_true:
        return True, "enforced_true"
    # If mixed or unknown, report mixed
    return True, "mixed"


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
    
    for b in buckets:
        name = b.get('Name')
        status = 'UNKNOWN'
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            policy_str = pol.get('Policy')
            if policy_str:
                has_transport, transport_status = analyze_secure_transport_policy(policy_str)
                if transport_status == "safe_deny":
                    status = 'SAFE (policy denies SecureTransport == false)'
                elif transport_status == "enforced_true":
                    status = 'SAFE (policy allows only SecureTransport == true)'
                elif transport_status == "unsafe_allow":
                    status = 'UNSAFE (policy allows SecureTransport == false)'
                    violations.append(name)
                elif transport_status == "mixed":
                    status = 'MIXED (policy has conflicting SecureTransport conditions)'
                    violations.append(name)
                elif transport_status == "none":
                    status = 'VIOLATION (policy exists but no SecureTransport condition)'
                    violations.append(name)
                else:  # parse_error
                    status = 'ERROR (unable to parse policy)'
                    violations.append(name)
            else:
                status = 'VIOLATION (no policy found)'
                violations.append(name)
        except ClientError as e:
            code = e.response.get('Error', {}).get('Code')
            # If no policy found (NoSuchBucketPolicy), treat as violation
            if code in ('NoSuchBucketPolicy', 'NoSuchBucket'):
                status = f'VIOLATION ({code})'
                violations.append(name)
            elif code in ('AccessDenied', 'AllAccessDisabled'):
                status = f'UNABLE TO CHECK ({code})'
            else:
                status = f'ERROR ({code})'
                violations.append(name)
        except Exception as e:  # pragma: no cover - defensive
            status = f'ERROR ({e})'
            violations.append(name)

        print(f'{name}: {status}')

    if violations:
        print('\nSummary: buckets with insecure or missing SecureTransport policies:')
        for v in violations:
            print(f' - {v}')
        return 2

    print('\nAll checked buckets properly enforce aws:SecureTransport == true.')
    return 0


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
