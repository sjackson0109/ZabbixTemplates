import re
import uuid
from pathlib import Path

def replace_uuids(file_path):
    # Create backup file path
    backup_path = file_path.with_suffix('.yaml.bak')
    
    # Read original content
    with open(file_path, 'r') as f:
        content = f.readlines()
    
    # Create new content with replaced UUIDs
    new_content = []
    uuid_pattern = re.compile(r'^(\s*uuid:\s*)[a-fA-F0-9-]+')
    
    for line in content:
        if line.strip().startswith('uuid:'):
            # Generate new UUIDv4 without hyphens
            new_uuid = uuid.uuid4().hex
            # Replace existing UUID while preserving indentation
            new_line = re.sub(uuid_pattern, rf'\g<1>{new_uuid}', line)
            new_content.append(new_line)
        else:
            new_content.append(line)
    
    # Write backup
    Path(backup_path).write_text(''.join(content))
    
    # Write new file
    with open(file_path, 'w') as f:
        f.writelines(new_content)

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python uuid_replace.py <file.yaml>")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"Error: File {file_path} not found")
        sys.exit(1)
    
    replace_uuids(file_path)
    print(f"UUIDs replaced in {file_path}. Backup created at {file_path.with_suffix('.yaml.bak')}")