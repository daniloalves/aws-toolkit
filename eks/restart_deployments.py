#!/usr/bin/env python3
"""List and restart Kubernetes deployments running on a specific node.

Features:
- List deployments that currently have pods scheduled on a node
- Restart deployments by namespace/name using `kubectl rollout restart`
- Options:
  - `--node` NODE_NAME (required)
  - `--all` restart all found deployments without confirmation
  - `--yes` same as `--all`
  - `--use-aws-auth` refresh EKS token using AWS CLI (uses utils.session for credentials)

This script uses `kubectl` available in PATH. Logs are written with `utils.logger.logger_aws_toolkit`.
"""
import argparse
import json
import shlex
import subprocess
import sys
from typing import List, Tuple

from utils.logger import logger_aws_toolkit
from utils.session import get_session


logger = logger_aws_toolkit()


def run(cmd: List[str]) -> Tuple[int, str, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate()
        return p.returncode, out.strip(), err.strip()
    except Exception as e:
        return 1, '', str(e)


def aws_refresh_eks_token(cluster_name: str, region: str, profile: str = None) -> bool:
    """Use AWS CLI to get EKS token and update kubeconfig (requires aws CLI installed).

    Uses `aws eks update-kubeconfig --name <cluster> --region <region> [--profile <profile>]`
    """
    cmd = ['aws', 'eks', 'update-kubeconfig', '--name', cluster_name, '--region', region]
    if profile:
        cmd += ['--profile', profile]
    logger.info('Refreshing kubeconfig via AWS CLI')
    rc, out, err = run(cmd)
    if rc != 0:
        logger.error(f'aws eks update-kubeconfig failed: {err or out}')
        return False
    logger.info('kubeconfig updated')
    return True


def list_deployments_on_node(node: str) -> List[Tuple[str, str]]:
    """Return list of (namespace, deployment) that have pods on the given node."""
    # Get pods on node
    rc, out, err = run(['kubectl', 'get', 'pods', '--all-namespaces', '-o', 'json', '--field-selector', f'spec.nodeName={node}'])
    if rc != 0:
        logger.error(f'kubectl get pods failed: {err or out}')
        return []

    try:
        pods = json.loads(out)
    except Exception as e:
        logger.error(f'failed to parse kubectl output: {e}')
        return []

    deployments = set()
    for item in pods.get('items', []):
        ns = item['metadata'].get('namespace')
        # ownerReferences can point to ReplicaSet which references Deployment
        owners = item['metadata'].get('ownerReferences') or []
        for o in owners:
            if o.get('kind') == 'ReplicaSet':
                # ReplicaSet name is <deploy>-<hash>; use kubectl to get owner chain
                rs_name = o.get('name')
                # fetch replicaset to find owner (Deployment)
                rc2, out2, err2 = run(['kubectl', 'get', 'replicaset', rs_name, '-n', ns, '-o', 'json'])
                if rc2 != 0:
                    continue
                try:
                    rs = json.loads(out2)
                except Exception:
                    continue
                rs_owners = rs.get('metadata', {}).get('ownerReferences') or []
                for ro in rs_owners:
                    if ro.get('kind') == 'Deployment':
                        deployments.add((ns, ro.get('name')))
            elif o.get('kind') == 'Deployment':
                deployments.add((ns, o.get('name')))

    return sorted(list(deployments))


def restart_deployment(namespace: str, deployment: str) -> bool:
    cmd = ['kubectl', 'rollout', 'restart', 'deployment', deployment, '-n', namespace]
    rc, out, err = run(cmd)
    if rc != 0:
        logger.error(f'failed to restart {namespace}/{deployment}: {err or out}')
        return False
    logger.info(f'restarted {namespace}/{deployment}')
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description='List and restart deployments running on a specific node')
    parser.add_argument('--node', '-n', required=True, help='Node name')
    parser.add_argument('--all', action='store_true', help='Restart all deployments without confirmation')
    parser.add_argument('--yes', action='store_true', help='Alias for --all')
    parser.add_argument('--use-aws-auth', action='store_true', help='Refresh kubeconfig using AWS EKS auth (aws cli)')
    parser.add_argument('--cluster', help='EKS cluster name (required if --use-aws-auth)')
    parser.add_argument('--region', help='AWS region (required if --use-aws-auth)')
    parser.add_argument('--profile', help='AWS profile for auth (optional)')
    args = parser.parse_args()

    if args.use_aws_auth:
        if not args.cluster or not args.region:
            logger.error('--cluster and --region are required when using --use-aws-auth')
            return 1
        # Ensure AWS session is available
        try:
            get_session(region_name=args.region, profile_name=args.profile)
        except Exception as e:
            logger.error(f'failed to establish AWS session: {e}')
            return 1
        ok = aws_refresh_eks_token(args.cluster, args.region, args.profile)
        if not ok:
            return 1

    deployments = list_deployments_on_node(args.node)
    if not deployments:
        print('No deployments found on node')
        return 0

    print('Deployments found:')
    for ns, d in deployments:
        print(f' - {ns}/{d}')

    failures = []
    if args.all or args.yes:
        for ns, d in deployments:
            ok = restart_deployment(ns, d)
            if not ok:
                failures.append(f'{ns}/{d}')
    else:
        # Interactive: prompt per deployment and restart immediately on confirmation
        remaining = list(deployments)
        for ns, d in remaining:
            resp = input(f'Restart {ns}/{d}? [y/N/a (all)]: ').strip().lower()
            if resp in ('y', 'yes'):
                ok = restart_deployment(ns, d)
                if not ok:
                    failures.append(f'{ns}/{d}')
            elif resp in ('a', 'all'):
                # restart this and all remaining without further confirmation
                ok = restart_deployment(ns, d)
                if not ok:
                    failures.append(f'{ns}/{d}')
                idx = remaining.index((ns, d))
                for ns2, d2 in remaining[idx+1:]:
                    ok2 = restart_deployment(ns2, d2)
                    if not ok2:
                        failures.append(f'{ns2}/{d2}')
                break
            else:
                # no
                continue

    if failures:
        print('\nSome restarts failed:')
        for f in failures:
            print(' -', f)
        return 2

    print('\nAll selected deployments restarted.')
    return 0


if __name__ == '__main__':
    rc = main()
    sys.exit(rc)
