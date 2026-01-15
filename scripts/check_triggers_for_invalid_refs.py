#!/usr/bin/env python3
"""
Script to check trigger expressions vs available items
"""

import yaml
import re

def extract_expression_references(template_file):
    """Extract all item references from trigger expressions"""
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
    
    expression_refs = []
    
    # Extract from regular triggers
    for template in data.get('zabbix_export', {}).get('templates', []):
        template_name = template.get('template', '')
        
        for item in template.get('items', []):
            for trigger in item.get('triggers', []):
                expression = trigger.get('expression', '')
                # Find all references like last(/Template Name/item.key)
                refs = re.findall(r'last\(/([^/]+)/([^)]+)\)', expression)
                for ref in refs:
                    expression_refs.append({
                        'trigger_name': trigger.get('name', ''),
                        'expression': expression,
                        'referenced_template': ref[0],
                        'referenced_key': ref[1],
                        'actual_template': template_name
                    })
                
                # Also check find() function references
                refs = re.findall(r'find\(/([^/]+)/([^,)]+)', expression)
                for ref in refs:
                    expression_refs.append({
                        'trigger_name': trigger.get('name', ''),
                        'expression': expression,
                        'referenced_template': ref[0],
                        'referenced_key': ref[1],
                        'actual_template': template_name
                    })
        
        # Extract from trigger prototypes
        for discovery in template.get('discovery_rules', []):
            for prototype in discovery.get('item_prototypes', []):
                for trigger in prototype.get('trigger_prototypes', []):
                    expression = trigger.get('expression', '')
                    refs = re.findall(r'last\(/([^/]+)/([^)]+)\)', expression)
                    for ref in refs:
                        expression_refs.append({
                            'trigger_name': trigger.get('name', ''),
                            'expression': expression,
                            'referenced_template': ref[0],
                            'referenced_key': ref[1],
                            'actual_template': template_name
                        })
    
    return expression_refs

def extract_available_items(template_file):
    """Extract all available items and their keys"""
    with open(template_file, 'r') as f:
        data = yaml.safe_load(f)
    
    items = {}
    
    for template in data.get('zabbix_export', {}).get('templates', []):
        template_name = template.get('template', '')
        items[template_name] = []
        
        # Regular items
        for item in template.get('items', []):
            items[template_name].append(item.get('key', ''))
        
        # Item prototypes
        for discovery in template.get('discovery_rules', []):
            for prototype in discovery.get('item_prototypes', []):
                items[template_name].append(prototype.get('key', ''))
    
    return items

def main():
    template_file = '/root/media/data/usr/lib/zabbix/templates/web_health.yaml'
    
    print("=" * 100)
    print("TRIGGER EXPRESSION ANALYSIS")
    print("=" * 100)
    
    expression_refs = extract_expression_references(template_file)
    available_items = extract_available_items(template_file)
    
    print(f"{'Trigger Name':<50} {'Referenced Template':<20} {'Referenced Key':<40} {'Status'}")
    print("-" * 140)
    
    mismatches = []
    
    for ref in expression_refs:
        # Check if template name matches
        template_match = ref['referenced_template'] == ref['actual_template']
        
        # Check if key exists in the referenced template
        key_exists = False
        if ref['referenced_template'] in available_items:
            key_exists = ref['referenced_key'] in available_items[ref['referenced_template']]
        
        status = "✅ OK"
        if not template_match:
            status = "❌ TEMPLATE MISMATCH"
            mismatches.append(ref)
        elif not key_exists:
            status = "❌ KEY NOT FOUND"
            mismatches.append(ref)
        
        print(f"{ref['trigger_name']:<50} {ref['referenced_template']:<20} {ref['referenced_key']:<40} {status}")
    
    if mismatches:
        print("\n" + "=" * 100)
        print("DETAILED MISMATCH ANALYSIS")
        print("=" * 100)
        
        for i, mismatch in enumerate(mismatches, 1):
            print(f"\n{i}. Trigger: {mismatch['trigger_name']}")
            print(f"   Expression: {mismatch['expression']}")
            print(f"   Referenced Template: '{mismatch['referenced_template']}'")
            print(f"   Actual Template: '{mismatch['actual_template']}'")
            print(f"   Referenced Key: '{mismatch['referenced_key']}'")
            
            if mismatch['referenced_template'] != mismatch['actual_template']:
                print(f"   ❌ Problem: Template name mismatch!")
                print(f"      Should be: '{mismatch['actual_template']}'")
            
            if mismatch['referenced_template'] in available_items:
                if mismatch['referenced_key'] not in available_items[mismatch['referenced_template']]:
                    print(f"   ❌ Problem: Key not found in template!")
                    print(f"      Available keys in '{mismatch['referenced_template']}':")
                    for key in available_items[mismatch['referenced_template']]:
                        if key:  # Skip empty keys
                            print(f"        - {key}")
    else:
        print("\n✅ All trigger expressions reference valid items!")
    
    print(f"\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"Total expressions analyzed: {len(expression_refs)}")
    print(f"Mismatches found: {len(mismatches)}")
    
    if available_items:
        for template_name, keys in available_items.items():
            print(f"\nTemplate '{template_name}' has {len([k for k in keys if k])} items:")
            for key in keys:
                if key:  # Skip empty keys
                    print(f"  - {key}")

if __name__ == '__main__':
    main()