"""Common utilities for AWS resource tagging scripts."""
from typing import Dict, Any, List, Callable
from utils.logger import logger_aws_toolkit


logger = logger_aws_toolkit()


def filter_by_name(name: str, prefix: str = None, suffix: str = None, contains: str = None) -> bool:
    """Filter resource name by prefix, suffix, or contains pattern.
    
    Args:
        name: Resource name to filter
        prefix: Match if name starts with this string
        suffix: Match if name ends with this string
        contains: Match if name contains this string
    
    Returns:
        True if name matches the filter criteria (or no filters specified)
    """
    if prefix and not name.startswith(prefix):
        return False
    if suffix and not name.endswith(suffix):
        return False
    if contains and contains not in name:
        return False
    return True


def print_resource_info(resource: Dict[str, Any], extra_fields: List[str] = None):
    """Pretty print resource information.
    
    Args:
        resource: Resource dict with 'type', 'identifier' keys
        extra_fields: Optional list of additional field keys to display
    """
    print(f"\n  {resource.get('type', 'RESOURCE').upper()}: {resource['identifier']}")
    
    # Display common fields
    if 'engine' in resource:
        print(f"    Engine: {resource['engine']}", end='')
    if 'status' in resource:
        print(f", Status: {resource['status']}")
    elif 'state' in resource:
        print(f", State: {resource['state']}")
    else:
        print()
    
    # Display extra fields if provided
    if extra_fields:
        for field in extra_fields:
            if field in resource:
                print(f"    {field.title()}: {resource[field]}")


def add_tags_generic(
    client,
    resource_identifier: str,
    tags: Dict[str, str],
    tag_function: str,
    resource_param: str
) -> bool:
    """Generic function to add tags to AWS resources.
    
    Args:
        client: Boto3 client for the service
        resource_identifier: Resource ID/ARN
        tags: Dict of tag key-value pairs
        tag_function: Name of the tag function (e.g., 'create_tags', 'add_tags_to_resource')
        resource_param: Parameter name for resource ID (e.g., 'Resources', 'ResourceName')
    
    Returns:
        True if successful, False otherwise
    """
    try:
        tag_list = [{'Key': k, 'Value': v} for k, v in tags.items()]
        tag_method = getattr(client, tag_function)
        
        kwargs = {resource_param: resource_identifier, 'Tags': tag_list}
        if resource_param == 'Resources':
            kwargs['Resources'] = [resource_identifier]
        
        tag_method(**kwargs)
        logger.info(f'Successfully added tags to {resource_identifier}')
        return True
    except Exception as e:
        logger.error(f'Error adding tags to {resource_identifier}: {e}')
        return False


def mode_interactive(
    resources: List[Dict[str, Any]],
    get_tags_fn: Callable,
    add_tags_fn: Callable
) -> int:
    """Interactive mode: prompt for key and value for each resource.
    
    Args:
        resources: List of resource dicts
        get_tags_fn: Function to get current tags (takes resource dict, returns dict)
        add_tags_fn: Function to add tags (takes resource dict, tags dict, returns bool)
    
    Returns:
        Number of failures
    """
    failures = 0
    for resource in resources:
        print_resource_info(resource)
        current_tags = get_tags_fn(resource)
        if current_tags:
            print(f"    Current tags: {current_tags}")
        
        response = input(f"  Add tag to this resource? [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            continue
        
        key = input(f"  Enter tag key: ").strip()
        if not key:
            print("  Skipped (empty key)")
            continue
        
        value = input(f"  Enter tag value: ").strip()
        
        if add_tags_fn(resource, {key: value}):
            print(f"  ✓ Tagged {resource['identifier']}: {key}={value}")
        else:
            print(f"  ✗ Failed to tag {resource['identifier']}")
            failures += 1
    
    return failures


def mode_fixed_key(
    resources: List[Dict[str, Any]],
    tag_key: str,
    get_tags_fn: Callable,
    add_tags_fn: Callable
) -> int:
    """Fixed key mode: use provided key, prompt for value for each resource.
    
    Args:
        resources: List of resource dicts
        tag_key: Fixed tag key to use
        get_tags_fn: Function to get current tags (takes resource dict, returns dict)
        add_tags_fn: Function to add tags (takes resource dict, tags dict, returns bool)
    
    Returns:
        Number of failures
    """
    failures = 0
    for resource in resources:
        print_resource_info(resource)
        current_tags = get_tags_fn(resource)
        if current_tags:
            print(f"    Current tags: {current_tags}")
            if tag_key in current_tags:
                print(f"    Note: Key '{tag_key}' already exists with value '{current_tags[tag_key]}'")
        
        value = input(f"  Enter value for tag '{tag_key}' (or press Enter to skip): ").strip()
        if not value:
            print("  Skipped")
            continue
        
        if add_tags_fn(resource, {tag_key: value}):
            print(f"  ✓ Tagged {resource['identifier']}: {tag_key}={value}")
        else:
            print(f"  ✗ Failed to tag {resource['identifier']}")
            failures += 1
    
    return failures


def mode_auto(
    resources: List[Dict[str, Any]],
    tag_key: str,
    tag_value: str,
    add_tags_fn: Callable,
    skip_confirm: bool = False
) -> int:
    """Auto mode: apply same key and value to all resources.
    
    Args:
        resources: List of resource dicts
        tag_key: Tag key to apply
        tag_value: Tag value to apply
        add_tags_fn: Function to add tags (takes resource dict, tags dict, returns bool)
        skip_confirm: Skip confirmation prompt
    
    Returns:
        Number of failures
    """
    failures = 0
    
    if not skip_confirm:
        print(f"\nWill add tag '{tag_key}={tag_value}' to {len(resources)} resource(s):")
        for resource in resources:
            print(f"  - {resource.get('type', 'resource')}: {resource['identifier']}")
        
        response = input(f"\nProceed? [y/N]: ").strip().lower()
        if response not in ('y', 'yes'):
            print("Cancelled")
            return 0
    
    for resource in resources:
        if add_tags_fn(resource, {tag_key: tag_value}):
            print(f"✓ Tagged {resource['identifier']}: {tag_key}={tag_value}")
        else:
            print(f"✗ Failed to tag {resource['identifier']}")
            failures += 1
    
    return failures
