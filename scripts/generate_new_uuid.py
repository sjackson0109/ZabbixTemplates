import uuid
import re
import argparse

def generate_zabbix_uuid():
    """Generate a single UUID that meets Zabbix requirements."""
    while True:
        new_uuid = str(uuid.uuid4()).replace('-', '')
        # Check position 13 is '4' and position 17 is '8','9','a','b'
        if new_uuid[12] == '4' and new_uuid[16] in '89ab':
            return new_uuid

def main():
    parser = argparse.ArgumentParser(description='Generate Zabbix-compatible UUIDs')
    parser.add_argument('-n', '--number', type=int, default=1, 
                        help='Number of UUIDs to generate (default: 1)')
    
    args = parser.parse_args()
    
    for _ in range(args.number):
        print(generate_zabbix_uuid())

if __name__ == '__main__':
    main()