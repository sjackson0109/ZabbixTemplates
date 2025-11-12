#!/usr/bin/env python3
"""
Fix host references in graph items that were incorrectly set during template merge
"""

import yaml
import sys
from pathlib import Path


def fix_host_references(data, old_host, new_host):
    """
    Recursively find and fix all 'host' references in graph items
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if key == 'host' and value == old_host:
                data[key] = new_host
                print(f"  Fixed: {old_host} -> {new_host}")
            else:
                fix_host_references(value, old_host, new_host)
    elif isinstance(data, list):
        for item in data:
            fix_host_references(item, old_host, new_host)


def main():
    if len(sys.argv) != 4:
        print("Usage: python fix_host_references.py <template.yaml> <old_host> <new_host>")
        sys.exit(1)
    
    template_path = Path(sys.argv[1])
    old_host = sys.argv[2]
    new_host = sys.argv[3]
    
    if not template_path.exists():
        print(f"Error: File not found: {template_path}")
        sys.exit(1)
    
    # Load YAML
    with open(template_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    
    # Fix all host references
    print(f"Fixing host references: '{old_host}' -> '{new_host}'")
    fix_host_references(data, old_host, new_host)
    
    # Write back
    with open(template_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)
    
    print(f"✓ All host references fixed in: {template_path}")


if __name__ == '__main__':
    main()
