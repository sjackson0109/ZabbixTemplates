#!/usr/bin/env python3
"""
Replace all UUIDs in a Zabbix YAML template with valid UUIDv4 format (32 hex chars, no hyphens).

This script:
1. Loads the YAML template structure
2. Recursively finds all 'uuid' keys
3. Replaces each UUID with a new valid UUIDv4 (using uuid.uuid4().hex)
4. Writes back the template with proper formatting
5. Creates a backup of the original file

UUIDv4 format (without hyphens): xxxxxxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx
  - Position 12 (0-indexed): must be '4' (version 4)
  - Position 16 (0-indexed): must be '8', '9', 'a', or 'b' (variant bits 10xx)
"""

import uuid
import yaml
from pathlib import Path


def replace_all_uuids(data):
    """
    Recursively replace all UUID values with valid UUIDv4 in a nested structure.
    
    Args:
        data: Dictionary, list, or other data structure from parsed YAML
    
    UUIDs are replaced in-place for any key named 'uuid'.
    """
    if isinstance(data, dict):
        for key, value in list(data.items()):
            if key == 'uuid':
                # Replace with valid UUIDv4 without hyphens
                data[key] = uuid.uuid4().hex
            else:
                # Recurse into nested structures
                replace_all_uuids(value)
    elif isinstance(data, list):
        for item in data:
            replace_all_uuids(item)


def replace_uuids(file_path):
    """
    Replace all UUIDs in a YAML file with valid UUIDv4 values.
    
    Args:
        file_path: Path object pointing to the YAML template file
    
    Creates a backup file with .yaml.bak extension before modifying.
    """
    # Create backup file path
    backup_path = file_path.with_suffix('.yaml.bak')
    
    # Read and parse YAML
    with open(file_path, 'r', encoding='utf-8') as f:
        original_content = f.read()
        
    # Parse YAML structure
    data = yaml.safe_load(original_content)
    
    # Replace all UUIDs with valid UUIDv4
    replace_all_uuids(data)
    
    # Write backup of original
    backup_path.write_text(original_content, encoding='utf-8')
    
    # Write updated YAML
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=120)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python replace_all_uuids_in_yaml.py <file.yaml>")
        print()
        print("Replaces all UUIDs in the YAML template with valid UUIDv4 values.")
        print("Creates a backup at <file.yaml.bak> before modifying.")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    
    if not file_path.exists():
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    
    if not file_path.suffix in ['.yaml', '.yml']:
        print(f"Warning: File does not have .yaml or .yml extension: {file_path}")
    
    replace_uuids(file_path)
    print(f"✓ UUIDs replaced with valid UUIDv4 in: {file_path}")
    print(f"✓ Backup created at: {file_path.with_suffix('.yaml.bak')}")