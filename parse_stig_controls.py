#!/usr/bin/env python3
"""
Parse stig_ocp4.yml and extract controls with their associated rules.

This script loads a STIG YAML file and creates a dictionary mapping control IDs
to their associated rules.
"""

import yaml
from pathlib import Path
import requests


def load_yaml_file(url: str = "https://raw.githubusercontent.com/ComplianceAsCode/content/refs/heads/master/controls/stig_ocp4.yml") -> dict:
    """Load and parse a YAML file from a URL or local path."""
    if url.startswith(('http://', 'https://')):
        # Fetch from URL
        response = requests.get(url)
        response.raise_for_status()
        return yaml.safe_load(response.text)
    else:
        # Load from local file
        with open(url, 'r') as f:
            return yaml.safe_load(f)


def extract_controls_to_rules(yaml_data: dict) -> dict:
    """
    Extract control IDs and their associated rules from parsed YAML data.
    
    Args:
        yaml_data: Parsed YAML data containing controls list
        
    Returns:
        Dictionary mapping control IDs to lists of rule names
    """
    controls_map = {}
    
    # Navigate to the controls list
    controls = yaml_data.get('controls', [])
    
    for control in controls:
        control_id = control.get('id')
        rules = control.get('rules', [])
        
        if control_id:
            # Extract just the rule names (strings) from the rules list
            rule_names = [rule for rule in rules if isinstance(rule, str)]
            controls_map[control_id] = rule_names
    
    return controls_map


def main():
    """Main function to parse the STIG file and output results."""
    # Use the GitHub URL by default
    yaml_url = "https://raw.githubusercontent.com/ComplianceAsCode/content/refs/heads/master/controls/stig_ocp4.yml"
    
    # Load and parse the YAML file from URL
    yaml_data = load_yaml_file(yaml_url)
    
    # Extract controls and their rules
    controls_map = extract_controls_to_rules(yaml_data)
    
    # Print results
    print(f"Parsed {len(controls_map)} controls from {yaml_url}")
    print("\nControls and their rules:")
    print("-" * 60)
    
    for control_id, rules in sorted(controls_map.items()):
        print(f"\n{control_id}:")
        for rule in rules:
            print(f"  - {rule}")
    
    # Also output as Python dictionary for programmatic use
    print("\n" + "=" * 60)
    print("Python dictionary representation:")
    print("=" * 60)
    print(controls_map)
    
    # Return the dictionary for use by other modules
    return controls_map


if __name__ == '__main__':
    main()
