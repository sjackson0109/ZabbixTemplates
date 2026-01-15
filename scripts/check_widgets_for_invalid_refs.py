#!/usr/bin/env python3
"""
Script to extract item keys and widget field keys from Zabbix template
"""

import yaml
import sys

def extract_items_and_keys(template_file):
    """Extract all items, triggers, graphs and their keys from template"""
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
    
    items = []
    
    # Extract items from templates
    for template in data.get('zabbix_export', {}).get('templates', []):
        # Regular items
        for item in template.get('items', []):
            items.append({
                'type': 'ITEM',
                'name': item.get('name', ''),
                'key': item.get('key', '')
            })
        
        # Discovery rules and item prototypes
        for discovery in template.get('discovery_rules', []):
            items.append({
                'type': 'DISCOVERY_RULE',
                'name': discovery.get('name', ''),
                'key': discovery.get('key', '')
            })
            
            for prototype in discovery.get('item_prototypes', []):
                items.append({
                    'type': 'ITEM_PROTOTYPE',
                    'name': prototype.get('name', ''),
                    'key': prototype.get('key', '')
                })
    
    return items

def extract_widget_keys(template_file):
    """Extract all widget field keys from dashboard"""
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
    
    widget_keys = []
    
    # Extract dashboard widget keys
    for template in data.get('zabbix_export', {}).get('templates', []):
        for dashboard in template.get('dashboards', []):
            for page in dashboard.get('pages', []):
                for widget in page.get('widgets', []):
                    widget_name = widget.get('name', 'Unnamed Widget')
                    widget_type = widget.get('type', 'Unknown')
                    
                    for field in widget.get('fields', []):
                        if field.get('type') == 'ITEM' and field.get('name') == 'itemid':
                            value = field.get('value', {})
                            if isinstance(value, dict) and 'key' in value:
                                widget_keys.append({
                                    'widget_name': widget_name,
                                    'widget_type': widget_type,
                                    'key': value['key']
                                })
    
    return widget_keys

def main():
    template_file = '/root/media/data/usr/lib/zabbix/templates/web_health.yaml'
    
    print("=" * 80)
    print("TABLE 1: ITEMS, TRIGGERS, GRAPHS, PROTOTYPES")
    print("=" * 80)
    print(f"{'Type':<20} {'Name':<50} {'Key'}")
    print("-" * 80)
    
    items = extract_items_and_keys(template_file)
    for item in items:
        print(f"{item['type']:<20} {item['name']:<50} {item['key']}")
    
    print("\n" + "=" * 80)
    print("TABLE 2: DASHBOARD WIDGET FIELD KEYS")
    print("=" * 80)
    print(f"{'Widget Name':<30} {'Widget Type':<15} {'Key'}")
    print("-" * 80)
    
    widget_keys = extract_widget_keys(template_file)
    for widget in widget_keys:
        print(f"{widget['widget_name']:<30} {widget['widget_type']:<15} {widget['key']}")
    
    print("\n" + "=" * 80)
    print("CROSS-REFERENCE ANALYSIS")
    print("=" * 80)
    
    # Create set of valid keys
    valid_keys = set(item['key'] for item in items)
    
    # Check for mismatches
    mismatches = []
    for widget in widget_keys:
        if widget['key'] not in valid_keys:
            mismatches.append(widget)
    
    if mismatches:
        print("MISMATCHED KEYS FOUND:")
        print("-" * 40)
        for mismatch in mismatches:
            print(f"Widget: {mismatch['widget_name']}")
            print(f"  Type: {mismatch['widget_type']}")
            print(f"  Key: {mismatch['key']}")
            print(f"  Status: KEY NOT FOUND IN ITEMS")
            print()
    else:
        print("All widget keys match existing item keys.")

if __name__ == '__main__':
    main()