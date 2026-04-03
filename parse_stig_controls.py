#!/usr/bin/env python3
"""
Parse stig_ocp4.yml and extract controls with their associated rules.

This script loads a STIG YAML file and creates a dictionary mapping control IDs
to their associated rules.
"""

import yaml
import requests
from typing import Dict, List, Any
from pathlib import Path


class YAMLParseError(Exception):
    """Raised when YAML parsing fails."""
    pass


class YAMLLoadError(Exception):
    """Raised when loading YAML from URL or file fails."""
    pass


def load_yaml_file(source: str = "https://raw.githubusercontent.com/ComplianceAsCode/content/refs/heads/master/controls/stig_ocp4.yml") -> dict:
    """
    Load and parse a YAML file from a URL or local path.
    
    Args:
        source: URL or local file path to the YAML file
        
    Returns:
        Parsed YAML data as a dictionary
        
    Raises:
        YAMLLoadError: If the file cannot be loaded
        YAMLParseError: If the YAML cannot be parsed
    """
    try:
        if source.startswith(('http://', 'https://')):
            # Fetch from URL
            response = requests.get(source, timeout=30)
            response.raise_for_status()
            yaml_content = response.text
        else:
            # Load from local file
            path = Path(source)
            if not path.exists():
                raise YAMLLoadError(f"File not found: {source}")
            yaml_content = path.read_text(encoding='utf-8')
        
        return yaml.safe_load(yaml_content)
    
    except requests.RequestException as e:
        raise YAMLLoadError(f"Failed to fetch YAML from URL: {e}")
    except yaml.YAMLError as e:
        raise YAMLParseError(f"Failed to parse YAML: {e}")


def extract_controls_to_rules(yaml_data: dict) -> Dict[str, List[str]]:
    """
    Extract control IDs and their associated rules from parsed YAML data.
    
    Args:
        yaml_data: Parsed YAML data containing controls list
        
    Returns:
        Dictionary mapping control IDs to lists of rule names
    """
    controls_map: Dict[str, List[str]] = {}
    
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
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Parse STIG YAML file and extract controls with rules.'
    )
    parser.add_argument(
        'source',
        nargs='?',
        default="https://raw.githubusercontent.com/ComplianceAsCode/content/refs/heads/master/controls/stig_ocp4.yml",
        help='URL or local path to STIG YAML file'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress detailed output'
    )
    
    args = parser.parse_args()
    
    try:
        # Load and parse the YAML file
        yaml_data = load_yaml_file(args.source)
        
        # Extract controls and their rules
        controls_map = extract_controls_to_rules(yaml_data)
        
        # Print results
        print(f"Parsed {len(controls_map)} controls from {args.source}")
        
        if not args.quiet:
            print("\nControls and their rules:")
            print("-" * 60)
            
            for control_id, rules in sorted(controls_map.items()):
                print(f"\n{control_id}:")
                for rule in rules:
                    print(f"  - {rule}")
        
        # Return the dictionary for use by other modules
        return controls_map
        
    except (YAMLLoadError, YAMLParseError) as e:
        print(f"Error: {e}")
        return None


if __name__ == '__main__':
    main()
