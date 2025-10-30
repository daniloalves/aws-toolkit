#!/usr/bin/env bash
#
# count-rds-aurora-like.sh
#
# Count AWS Aurora and RDS resources whose identifiers match a pattern.
# Supports multiple regions and AWS profiles.
#
# Usage examples:
#   ./count-rds-aurora-like.sh --pattern "prod-" --region ap-southeast-2
#   ./count-rds-aurora-like.sh --pattern "billing" --all-regions --profile myprofile
#

set -euo pipefail

PATTERN=""
REGION=""
ALL_REGIONS=false
PROFILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pattern|-p) PATTERN="${2:-}"; shift 2 ;;
    --region|-r)  REGION="${2:-}";  shift 2 ;;
    --all-regions) ALL_REGIONS=true; shift ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '1,120p' "$0"; exit 0 ;;
    *)
      echo "Unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$PATTERN" ]]; then
  echo "ERROR: --pattern is required (e.g., --pattern prod-)" >&2
  exit 1
fi

if $ALL_REGIONS && [[ -n "$REGION" ]]; then
  echo "ERROR: Use either --region or --all-regions, not both." >&2
  exit 1
fi

# AWS CLI base command with profile if provided
AWS="aws"
if [[ -n "$PROFILE" ]]; then
  AWS="aws --profile $PROFILE"
fi

# Resolve regions
if $ALL_REGIONS; then
  REGIONS=($($AWS ec2 describe-regions --query 'Regions[].RegionName' --output text))
else
  REGIONS=("${REGION:-$($AWS configure get region)}")
  if [[ -z "${REGIONS[0]}" ]]; then
    echo "ERROR: No region set. Use --region, --all-regions, or set a default with 'aws configure'." >&2
    exit 1
  fi
fi

total_aurora_clusters=0
total_aurora_instances=0
total_rds_instances=0

echo "Pattern (case-insensitive): \"$PATTERN\""
echo "Regions: ${REGIONS[*]}"
echo "AWS Profile: ${PROFILE:-default}"
echo

for r in "${REGIONS[@]}"; do
  # Aurora clusters
  acount=$($AWS rds describe-db-clusters --region "$r" \
    --query 'DBClusters' --output json \
    | jq -r --arg pat "$PATTERN" '
      [ .[] 
        | select(.Engine | startswith("aurora"))
        | select(.DBClusterIdentifier | test($pat;"i"))
      ] | length')

  # Aurora instances
  aicount=$($AWS rds describe-db-instances --region "$r" \
    --query 'DBInstances' --output json \
    | jq -r --arg pat "$PATTERN" '
      [ .[]
        | select(.Engine | startswith("aurora"))
        | select(.DBInstanceIdentifier | test($pat;"i"))
      ] | length')

  # RDS instances (non-Aurora)
  rcount=$($AWS rds describe-db-instances --region "$r" \
    --query 'DBInstances' --output json \
    | jq -r --arg pat "$PATTERN" '
      [ .[]
        | select((.Engine | startswith("aurora")) | not)
        | select(.DBInstanceIdentifier | test($pat;"i"))
      ] | length')

  printf "%-18s  Aurora clusters: %3d   Aurora instances: %3d   RDS instances: %3d\n" "$r" "$acount" "$aicount" "$rcount"

  total_aurora_clusters=$((total_aurora_clusters + acount))
  total_aurora_instances=$((total_aurora_instances + aicount))
  total_rds_instances=$((total_rds_instances + rcount))
done

echo
echo "================== TOTALS =================="
printf "Aurora clusters:  %d\n" "$total_aurora_clusters"
printf "Aurora instances: %d\n" "$total_aurora_instances"
printf "RDS instances:    %d\n" "$total_rds_instances"
echo "============================================"