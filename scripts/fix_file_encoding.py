#!/usr/bin/env python3
"""
Fix YAML file encoding and line endings for Zabbix templates
Removes BOM and converts to LF line endings
"""
import os
import sys
import glob
import shutil

def fix_file_encoding_and_lineendings(filepath, backup=True):
    """Remove BOM and convert to LF line endings"""
    
    # Create backup if requested
    if backup:
        backup_path = filepath + '.bak'
        shutil.copy2(filepath, backup_path)
        print(f"  Backup created: {os.path.basename(backup_path)}")
    
    # Read with BOM detection
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Remove BOM if present
    if content.startswith(b'\xef\xbb\xbf'):
        content = content[3:]
        print(f"  Removed UTF-8 BOM")
    
    # Decode and normalize line endings
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        print(f"  ERROR: Could not decode as UTF-8")
        return False
    
    # Convert CRLF to LF
    if '\r\n' in text_content:
        text_content = text_content.replace('\r\n', '\n')
        print(f"  Converted CRLF to LF")
    
    # Write back as UTF-8 without BOM
    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text_content)
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_file_encoding.py <pattern> [--no-backup]")
        print("Example: python fix_file_encoding.py templates/*.yaml")
        sys.exit(1)
    
    pattern = sys.argv[1]
    backup = '--no-backup' not in sys.argv
    
    files = glob.glob(pattern)
    
    print("Fixing File Encoding and Line Endings")
    print("=" * 50)
    print(f"Pattern: {pattern}")
    print(f"Backup: {'Yes' if backup else 'No'}")
    print(f"Files found: {len(files)}")
    print()
    
    fixed_count = 0
    
    for filepath in sorted(files):
        filename = os.path.basename(filepath)
        print(f"Processing: {filename}")
        
        if fix_file_encoding_and_lineendings(filepath, backup):
            fixed_count += 1
        
        print()
    
    print("=" * 50)
    print(f"Successfully processed: {fixed_count}/{len(files)} files")
    
    if backup:
        print("\nTo remove backup files: del *.bak")
        print("To restore from backup: copy file.yaml.bak file.yaml")

if __name__ == "__main__":
    main()