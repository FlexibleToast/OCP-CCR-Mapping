#!/usr/bin/env python3
"""
Query OpenShift ComplianceCheckResult (CCR) resources for rules.

This script converts snake_case rule names to kebab-case and queries
the OpenShift CCR resources to find matching compliance check results.
"""

import subprocess
import re
from typing import List, Optional


def snake_case_to_kebab_case(snake_case_name: str) -> str:
    """
    Convert a snake_case string to kebab-case.
    
    Args:
        snake_case_name: The snake_case string to convert (e.g., "usbguard_allow_hid_and_hub")
        
    Returns:
        The kebab-case string (e.g., "usbguard-allow-hid-and-hub")
    """
    # Replace underscores with hyphens
    return snake_case_name.replace('_', '-')


def get_ccr_resources(namespace: str = "openshift-compliance") -> List[dict]:
    """
    Execute `oc get ccr` command and parse the output.
    
    Args:
        namespace: The namespace to query (default: openshift-compliance)
        
    Returns:
        List of CCR resource dictionaries with 'name' and 'status' keys
    """
    try:
        # Execute oc get ccr command
        result = subprocess.run(
            ["oc", "get", "ccr", "-n", namespace, "-o", "json"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"Error executing oc get ccr: {result.stderr}")
            return []
        
        # Parse JSON output
        import json
        ccr_data = json.loads(result.stdout)
        
        # Extract items from the JSON structure
        if "items" in ccr_data:
            resources = []
            for item in ccr_data["items"]:
                # Extract CCR name from metadata
                ccr_name = item.get("metadata", {}).get("name", "")
                
                # Extract status from the top-level status field
                status = item.get("status", "")
                
                # Create a simplified dictionary with name and status
                resources.append({
                    "name": ccr_name,
                    "status": status
                })
            return resources
        return []
        
    except subprocess.TimeoutExpired:
        print("Error: oc command timed out")
        return []
    except FileNotFoundError:
        print("Error: 'oc' command not found. Ensure OpenShift CLI is installed.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}")
        return []
    except Exception as e:
        print(f"Error executing oc command: {e}")
        return []


def find_matching_ccr_names(kebab_rule_name: str, ccr_resources: List[dict]) -> List[dict]:
    """
    Find CCR names that contain the kebab-case rule name.
    
    Args:
        kebab_rule_name: The kebab-case rule name to search for
        ccr_resources: List of CCR resource dictionaries
        
    Returns:
        List of matching CCR resource dictionaries with 'name' and 'status' keys
    """
    matching_ccr_resources = []
    
    for ccr in ccr_resources:
        # Extract the name from the CCR resource
        ccr_name = ccr.get("name", "")
        
        if ccr_name and kebab_rule_name in ccr_name:
            matching_ccr_resources.append(ccr)
    
    return matching_ccr_resources


def query_ccr_for_rule(snake_case_rule_name: str, namespace: str = "openshift-compliance") -> List[dict]:
    """
    Convert snake_case rule name to kebab-case and query CCR resources for matches.
    
    Args:
        snake_case_rule_name: The snake_case rule name (e.g., "usbguard_allow_hid_and_hub")
        namespace: The namespace to query (default: openshift-compliance)
        
    Returns:
        List of matching CCR resource dictionaries with 'name' and 'status' keys
    """
    # Convert snake_case to kebab-case
    kebab_rule_name = snake_case_to_kebab_case(snake_case_rule_name)
    
    print(f"Converting '{snake_case_rule_name}' to kebab-case: '{kebab_rule_name}'")
    
    # Get all CCR resources
    ccr_resources = get_ccr_resources(namespace)
    print(f"Retrieved {len(ccr_resources)} CCR resources from namespace '{namespace}'")
    
    # Find matching CCR resources
    matching_ccr_resources = find_matching_ccr_names(kebab_rule_name, ccr_resources)
    
    return matching_ccr_resources


def main():
    """Main function to demonstrate CCR querying."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python query_ccr_rules.py <snake_case_rule_name>")
        print("Example: python query_ccr_rules.py usbguard_allow_hid_and_hub")
        return
    
    snake_case_rule_name = sys.argv[1]
    
    # Query CCR resources for the rule
    matching_ccr_resources = query_ccr_for_rule(snake_case_rule_name)
    
    # Print results
    if matching_ccr_resources:
        print(f"\nFound {len(matching_ccr_resources)} matching CCR(s):")
        for ccr in matching_ccr_resources:
            print(f"  - {ccr['name']} (Status: {ccr['status']})")
    else:
        print(f"\nNo matching CCRs found for rule: {snake_case_rule_name}")


if __name__ == '__main__':
    main()
