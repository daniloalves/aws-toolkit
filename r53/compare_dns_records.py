#!/usr/bin/env python3
"""Compare DNS records between a Cloudflare export and a Route53 export.

Filters applied to both files:
- TXT records whose value contains 'external-dns/owner' are excluded

Cloudflare-specific normalisation:
- Section comment lines (starting with ';;') are skipped
- '; cf_tags=...' annotations are stripped from record values

Value normalisation (applied to both files):
- Record names: lowercase, trailing dot removed
- Record values: lowercase, trailing dot removed

Output sections:
- Only in Cloudflare  (present in CF, missing in R53)
- Only in Route53     (present in R53, missing in CF)
- In both             (exact match on name + type + value)

Examples:
    python r53/compare_dns_records.py cloudflare.txt r53_records.txt
    python r53/compare_dns_records.py cloudflare.txt r53_records.txt --output diff.txt
"""
import argparse
import os
import sys
from typing import Set, Tuple

# (name, type, value)
RecordSet = Set[Tuple[str, str, str]]


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _norm_name(name: str) -> str:
    return name.rstrip('.').lower()


def _norm_value(value: str) -> str:
    return value.rstrip('.').lower()


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_cloudflare(filepath: str) -> RecordSet:
    """Parse a Cloudflare DNS export file.

    Expected line format (BIND-style):
        name  TTL  IN  type  value [; cf_tags=cf-proxied:...]
    """
    records: RecordSet = set()

    with open(filepath, encoding='utf-8') as fh:
        for raw in fh:
            line = raw.strip()

            # Skip blank lines and section comments (;; A Records, etc.)
            if not line or line.startswith(';'):
                continue

            # Strip cf_tags annotation before splitting
            if '; cf_tags=' in line:
                line = line[:line.index('; cf_tags=')].strip()

            parts = line.split('\t')
            # Minimum: name  TTL  IN  type  value
            if len(parts) < 5:
                continue

            name = _norm_name(parts[0])
            record_type = parts[3].upper()
            value = _norm_value('\t'.join(parts[4:]).strip())

            if record_type == 'TXT' and 'external-dns/owner' in value:
                continue

            records.add((name, record_type, value))

    return records


def parse_r53(filepath: str) -> RecordSet:
    """Parse a Route53 DNS export file produced by extract_dns_records.py.

    Expected line format:
        name  type  value [value ...]
    """
    records: RecordSet = set()

    with open(filepath, encoding='utf-8') as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue

            parts = line.split('\t')
            if len(parts) < 3:
                continue

            name = _norm_name(parts[0])
            record_type = parts[1].upper()
            value = _norm_value('\t'.join(parts[2:]).strip())

            if record_type == 'TXT' and 'external-dns/owner' in value:
                continue

            records.add((name, record_type, value))

    return records


# ---------------------------------------------------------------------------
# Comparison & reporting
# ---------------------------------------------------------------------------

def _fmt_record(name: str, record_type: str, value: str) -> str:
    return f"{name}\t{record_type}\t{value}"


def compare(cf_records: RecordSet, r53_records: RecordSet) -> dict:
    only_cf  = sorted(cf_records  - r53_records)
    only_r53 = sorted(r53_records - cf_records)
    common   = sorted(cf_records  & r53_records)
    return {'only_cf': only_cf, 'only_r53': only_r53, 'common': common}


def build_report(result: dict, cf_file: str, r53_file: str) -> str:
    lines = []

    header = f"DNS Comparison: {os.path.basename(cf_file)} vs {os.path.basename(r53_file)}"
    lines.append(header)
    lines.append('=' * len(header))
    lines.append(f"  Only in Cloudflare : {len(result['only_cf'])}")
    lines.append(f"  Only in Route53    : {len(result['only_r53'])}")
    lines.append(f"  In both            : {len(result['common'])}")
    lines.append('')

    lines.append('--- Only in Cloudflare (missing from Route53) ---')
    if result['only_cf']:
        lines.append('NAME\tTYPE\tVALUE')
        for rec in result['only_cf']:
            lines.append(_fmt_record(*rec))
    else:
        lines.append('(none)')
    lines.append('')

    lines.append('--- Only in Route53 (missing from Cloudflare) ---')
    if result['only_r53']:
        lines.append('NAME\tTYPE\tVALUE')
        for rec in result['only_r53']:
            lines.append(_fmt_record(*rec))
    else:
        lines.append('(none)')
    lines.append('')

    lines.append('--- In both ---')
    if result['common']:
        lines.append('NAME\tTYPE\tVALUE')
        for rec in result['common']:
            lines.append(_fmt_record(*rec))
    else:
        lines.append('(none)')

    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description='Compare Cloudflare and Route53 DNS export files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument('cloudflare_file', help='Cloudflare DNS export (BIND format)')
    parser.add_argument('r53_file', help='Route53 DNS export (extract_dns_records.py output)')
    parser.add_argument('--output', '-o', help='Write report to this file (default: stdout)')

    args = parser.parse_args()

    for path in (args.cloudflare_file, args.r53_file):
        if not os.path.exists(path):
            print(f'ERROR: File not found: {path}', file=sys.stderr)
            return 1

    cf_records  = parse_cloudflare(args.cloudflare_file)
    r53_records = parse_r53(args.r53_file)

    result = compare(cf_records, r53_records)
    report = build_report(result, args.cloudflare_file, args.r53_file)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as fh:
            fh.write(report + '\n')
        print(f'Report written to: {args.output}')
        print(f'  Only in Cloudflare: {len(result["only_cf"])}')
        print(f'  Only in Route53   : {len(result["only_r53"])}')
        print(f'  In both           : {len(result["common"])}')
    else:
        print(report)

    return 0


if __name__ == '__main__':
    sys.exit(main())
