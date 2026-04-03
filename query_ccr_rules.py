#!/usr/bin/env python3
"""
Query OpenShift ComplianceCheckResult (CCR) resources for rules.

This script converts snake_case rule names to kebab-case and queries
the OpenShift CCR resources to find matching compliance check results.
"""

import json
import subprocess
from typing import List, Dict, Optional


class CCRError(Exception):
    """Base exception for CCR-related errors."""
    pass


class CCRConnectionError(CCRError):
    """Raised when connection to OpenShift cluster fails."""
    pass


class CCRCommandError(CCRError):
    """Raised when oc command execution fails."""
    pass


def snake_case_to_kebab_case(snake_case_name: str) -> str:
    """
    Convert a snake_case string to kebab-case.
    
    Args:
        snake_case_name: The snake_case string to convert (e.g., "usbguard_allow_hid_and_hub")
        
    Returns:
        The kebab-case string (e.g., "usbguard-allow-hid-and-hub")
    """
    return snake_case_name.replace('_', '-')


def get_ccr_resources(namespace: str = "openshift-compliance", timeout: int = 30) -> List[Dict[str, str]]:
    """
    Execute `oc get ccr` command and parse the output.
    
    Args:
        namespace: The namespace to query (default: openshift-compliance)
        timeout: Command timeout in seconds (default: 30)
        
    Returns:
        List of CCR resource dictionaries with 'name' and 'status' keys
        
    Raises:
        CCRConnectionError: If unable to connect to OpenShift cluster
        CCRCommandError: If oc command fails
    """
    try:
        result = subprocess.run(
            ["oc", "get", "ccr", "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            stderr = result.stderr.strip().lower()
            stdout = result.stdout.strip().lower()
            
            if "connection refused" in stderr or "connection refused" in stdout:
                raise CCRConnectionError(
                    "Connection refused. Ensure the OpenShift cluster is running and accessible."
                )
            elif "couldn't get current server API group list" in stderr:
                raise CCRConnectionError(
                    "Cluster API not responding. Ensure the cluster is running and accessible."
                )
            else:
                raise CCRCommandError(f"oc command failed: {result.stderr.strip()}")
        
        ccr_data = json.loads(result.stdout)
        
        if "items" not in ccr_data:
            return []
        
        resources = []
        for item in ccr_data["items"]:
            ccr_name = item.get("metadata", {}).get("name", "")
            status = item.get("status", "")
            resources.append({"name": ccr_name, "status": status})
        
        return resources
        
    except subprocess.TimeoutExpired:
        raise CCRCommandError(f"oc command timed out after {timeout} seconds")
    except FileNotFoundError:
        raise CCRCommandError("'oc' command not found. Ensure OpenShift CLI is installed.")
    except json.JSONDecodeError as e:
        raise CCRCommandError(f"Failed to parse JSON output: {e}")


def find_matching_ccr_names(
    kebab_rule_name: str,
    ccr_resources: List[Dict[str, str]],
    case_sensitive: bool = False
) -> List[Dict[str, str]]:
    """
    Find CCR names that end with the kebab-case rule name (suffix matching).
    
    This uses suffix matching to prevent duplicate matches when rules share common prefixes.
    For example, with rules "configure_network_policies" and "configure_network_policies_namespaces",
    the CCR "ocp4-stig-configure-network-policies-namespaces" will only match the second rule,
    not both.
    
    Args:
        kebab_rule_name: The kebab-case rule name to search for (e.g., "configure-network-policies")
        ccr_resources: List of CCR resource dictionaries
        case_sensitive: Whether to perform case-sensitive matching (default: False)
        
    Returns:
        List of matching CCR resource dictionaries with 'name' and 'status' keys
    """
    matching_ccr_resources = []
    search_term = kebab_rule_name if case_sensitive else kebab_rule_name.lower()
    
    for ccr in ccr_resources:
        ccr_name = ccr.get("name", "")
        compare_name = ccr_name if case_sensitive else ccr_name.lower()
        
        # Use suffix matching: CCR name must end with the rule name
        if ccr_name and compare_name.endswith(search_term):
            matching_ccr_resources.append(ccr)
    
    return matching_ccr_resources


def query_ccr_for_rule(
    snake_case_rule_name: str,
    namespace: str = "openshift-compliance",
    case_sensitive: bool = False,
    verbose: bool = True
) -> List[Dict[str, str]]:
    """
    Convert snake_case rule name to kebab-case and query CCR resources for matches.
    
    Args:
        snake_case_rule_name: The snake_case rule name (e.g., "usbguard_allow_hid_and_hub")
        namespace: The namespace to query (default: openshift-compliance)
        case_sensitive: Whether to perform case-sensitive matching (default: False)
        verbose: Whether to print progress messages (default: True)
        
    Returns:
        List of matching CCR resource dictionaries with 'name' and 'status' keys
        
    Raises:
        CCRConnectionError: If unable to connect to OpenShift cluster
        CCRCommandError: If oc command fails
    """
    kebab_rule_name = snake_case_to_kebab_case(snake_case_rule_name)
    
    if verbose:
        print(f"Searching for rule: '{kebab_rule_name}'")
    
    ccr_resources = get_ccr_resources(namespace)
    
    if verbose:
        print(f"Found {len(ccr_resources)} CCR resources in namespace '{namespace}'")
    
    return find_matching_ccr_names(kebab_rule_name, ccr_resources, case_sensitive)


def main():
    """Main function to demonstrate CCR querying."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Query OpenShift CCR resources for matching rules.'
    )
    parser.add_argument(
        'rule_name',
        help='Snake_case rule name to search for (e.g., usbguard_allow_hid_and_hub)'
    )
    parser.add_argument(
        '--namespace', '-n',
        default='openshift-compliance',
        help='OpenShift namespace to query (default: openshift-compliance)'
    )
    parser.add_argument(
        '--case-sensitive',
        action='store_true',
        help='Perform case-sensitive matching'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress progress messages'
    )
    
    args = parser.parse_args()
    
    try:
        matching_ccr_resources = query_ccr_for_rule(
            args.rule_name,
            namespace=args.namespace,
            case_sensitive=args.case_sensitive,
            verbose=not args.quiet
        )
        
        if matching_ccr_resources:
            print(f"\nFound {len(matching_ccr_resources)} matching CCR(s):")
            for ccr in matching_ccr_resources:
                print(f"  - {ccr['name']} (Status: {ccr['status']})")
        else:
            print(f"\nNo matching CCRs found for rule: {args.rule_name}")
            
    except (CCRConnectionError, CCRCommandError) as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
