import yaml
from yaml import YAMLError
import sys
import re
import io

# Configure stdout to use UTF-8 encoding to support Unicode emojis
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Supported Zabbix versions and their schema formats
SUPPORTED_VERSIONS = {
    '4.0': 'Zabbix 6.0',
    '5.0': 'Zabbix 6.4+ (including 6.7)',
    '6.0': 'Zabbix 7.0+',
    '7.0': 'Zabbix 7.0+ (direct)',
    '7.2': 'Zabbix 7.2',
    '7.4': 'Zabbix 7.4'
}

def validate_zabbix_uuid(value):
    """
    Validate UUID in Zabbix format - must be a valid UUIDv4 as 32-character hex string without hyphens
    
    UUIDv4 format (with hyphens): xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    - Position 12 (13th char): must be '4' (version 4)
    - Position 16 (17th char): must be '8', '9', 'a', or 'b' (variant bits 10xx)
    
    Zabbix removes hyphens, so: xxxxxxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx
    - Position 12: must be '4'
    - Position 16: must be '8', '9', 'a', 'A', 'b', or 'B'
    """
    # Must be a string
    if not isinstance(value, str):
        return False
    
    # Must be exactly 32 characters long
    if len(value) != 32:
        return False
    
    # Must contain only hexadecimal characters (case-insensitive)
    if not re.match(r'^[a-fA-F0-9]{32}$', value):
        return False
    
    # Check UUIDv4 structure
    # Position 12 (0-indexed) must be '4' (version 4)
    if value[12] != '4':
        return False
    
    # Position 16 (0-indexed) must be one of '8', '9', 'a', 'b', 'A', 'B' (variant 10xx)
    if value[16].lower() not in ['8', '9', 'a', 'b']:
        return False
    
    return True

def validate_zabbix_schema(yaml_data, file_content):
    errors = []
    version = None
    lines = file_content.splitlines()
    
    # Check required top-level structure
    if 'zabbix_export' not in yaml_data:
        errors.append("Missing required top-level 'zabbix_export' key")
        return errors, None
    
    export_data = yaml_data['zabbix_export']
    
    # Check version
    if 'version' not in export_data:
        errors.append("Missing required 'version' field in zabbix_export")
    else:
        version = str(export_data['version'])
        if version not in SUPPORTED_VERSIONS:
            expected = ", ".join([f"'{v}' ({desc})" for v, desc in SUPPORTED_VERSIONS.items()])
            errors.append(f"Unsupported version: '{version}'. Expected one of: {expected}")
    
    # Check templates section
    if 'templates' not in export_data:
        errors.append("Missing required 'templates' section")
    else:
        templates = export_data['templates']
        
        # Normalize templates to list
        if isinstance(templates, dict):
            templates = [templates]
        elif not isinstance(templates, list):
            errors.append("'templates' should be a list or dictionary")
            templates = []
        
        for idx, template in enumerate(templates):
            # Determine template structure based on version and content
            template_data = None
            prefix = f"templates[{idx}]"
            
            # New schema (5.0/6.0/7.0) - template is direct dictionary
            if version in ['5.0', '6.0', '7.0']:
                template_data = template
            # Old schema (4.0) - nested 'template' key
            elif 'template' in template and isinstance(template['template'], dict):
                template_data = template['template']
                prefix += ".template"
            # Fallback: if 'template' key exists but isn't a dict, try direct access
            elif 'template' in template:
                template_data = template
            else:
                # Try to find required fields in the template dictionary
                if any(field in template for field in ['name', 'groups', 'items']):
                    template_data = template
                else:
                    errors.append(f"{prefix}: Could not determine template structure")
                    continue
            
            # Get line number for this template
            template_line = find_line_number(lines, template_data) or 0
            
            # Validate template fields
            required_fields = ['name', 'groups']
            for field in required_fields:
                if field not in template_data:
                    line = find_line_number(lines, template_data.get(field, template_data)) or template_line
                    errors.append(f"Line ~{line}: {prefix}: Missing required field - '{field}'")
            
            # Validate groups structure
            if 'groups' in template_data:
                groups = template_data['groups']
                if not isinstance(groups, (list, dict)):
                    line = find_line_number(lines, groups) or template_line
                    errors.append(f"Line ~{line}: {prefix}.groups: Should be list/dict, found {type(groups).__name__}")
                else:
                    group_list = groups if isinstance(groups, list) else [groups]
                    for group_idx, group in enumerate(group_list):
                        if 'name' not in group:
                            line = find_line_number(lines, group) or find_line_number(lines, groups) or template_line
                            errors.append(f"Line ~{line}: {prefix}.groups[{group_idx}]: Missing 'name' attribute")
            
            # Validate items (items cannot have *_prototypes, only regular versions)
            if 'items' in template_data:
                items = template_data['items']
                
                # Normalize items
                if isinstance(items, dict):
                    items = [items]
                elif not isinstance(items, list):
                    line = find_line_number(lines, items) or template_line
                    errors.append(f"Line ~{line}: {prefix}.items: Should be list/dict")
                    items = []
                
                for item_idx, item in enumerate(items):
                    item_prefix = f"{prefix}.items[{item_idx}]"
                    
                    # Check for invalid *_prototypes under items (prototypes only valid in discovery_rules)
                    invalid_prototypes = {
                        'item_prototypes': 'items',
                        'trigger_prototypes': 'triggers',
                        'graph_prototypes': 'graphs',
                        'host_prototypes': 'hosts'
                    }
                    
                    for proto_key, correct_key in invalid_prototypes.items():
                        if proto_key in item:
                            line = find_line_number(lines, item) or template_line
                            errors.append(f"Line ~{line}: {item_prefix}: Invalid tag '{proto_key}' - items can only have '{correct_key}', not '{proto_key}'. Prototypes (*_prototypes) are only valid inside discovery_rules.")
            
            # Validate graphs (graphs cannot have graph_prototypes)
            if 'graphs' in template_data:
                graphs = template_data['graphs']
                
                # Normalize graphs
                if isinstance(graphs, dict):
                    graphs = [graphs]
                elif not isinstance(graphs, list):
                    line = find_line_number(lines, graphs) or template_line
                    errors.append(f"Line ~{line}: {prefix}.graphs: Should be list/dict")
                    graphs = []
                
                for graph_idx, graph in enumerate(graphs):
                    graph_prefix = f"{prefix}.graphs[{graph_idx}]"
                    
                    # Check for invalid graph_prototypes under graphs
                    if 'graph_prototypes' in graph:
                        line = find_line_number(lines, graph) or template_line
                        errors.append(f"Line ~{line}: {graph_prefix}: Invalid tag 'graph_prototypes' - graphs section cannot contain 'graph_prototypes'. Graph prototypes are only valid inside discovery_rules.")
            
            # Validate triggers (triggers cannot have trigger_prototypes)
            if 'triggers' in template_data:
                triggers = template_data['triggers']
                
                # Normalize triggers
                if isinstance(triggers, dict):
                    triggers = [triggers]
                elif not isinstance(triggers, list):
                    line = find_line_number(lines, triggers) or template_line
                    errors.append(f"Line ~{line}: {prefix}.triggers: Should be list/dict")
                    triggers = []
                
                for trigger_idx, trigger in enumerate(triggers):
                    trigger_prefix = f"{prefix}.triggers[{trigger_idx}]"
                    
                    # Check for invalid trigger_prototypes under triggers
                    if 'trigger_prototypes' in trigger:
                        line = find_line_number(lines, trigger) or template_line
                        errors.append(f"Line ~{line}: {trigger_prefix}: Invalid tag 'trigger_prototypes' - triggers section cannot contain 'trigger_prototypes'. Trigger prototypes are only valid inside discovery_rules.")
            
            # Validate discovery rules
            if 'discovery_rules' in template_data:
                discovery_rules = template_data['discovery_rules']
                
                # Normalize discovery rules
                if isinstance(discovery_rules, dict):
                    discovery_rules = [discovery_rules]
                elif not isinstance(discovery_rules, list):
                    line = find_line_number(lines, discovery_rules) or template_line
                    errors.append(f"Line ~{line}: {prefix}.discovery_rules: Should be list/dict")
                    discovery_rules = []
                
                for rule_idx, rule in enumerate(discovery_rules):
                    rule_prefix = f"{prefix}.discovery_rules[{rule_idx}]"
                    
                    # Handle different rule structures
                    rule_data = None
                    if 'discovery_rule' in rule and isinstance(rule['discovery_rule'], dict):
                        rule_data = rule['discovery_rule']
                    else:
                        rule_data = rule
                    
                    # Validate item prototypes
                    if rule_data and 'item_prototypes' in rule_data:
                        prototypes = rule_data['item_prototypes']
                        
                        # Normalize prototypes
                        if isinstance(prototypes, dict):
                            prototypes = [prototypes]
                        elif not isinstance(prototypes, list):
                            line = find_line_number(lines, prototypes) or find_line_number(lines, rule_data) or template_line
                            errors.append(f"Line ~{line}: {rule_prefix}.item_prototypes: Should be list/dict")
                        
                        # Check for invalid triggers in item_prototypes (should be trigger_prototypes)
                        for proto_idx, proto in enumerate(prototypes) if isinstance(prototypes, list) else []:
                            if 'triggers' in proto:
                                line = find_line_number(lines, proto) or find_line_number(lines, rule_data) or template_line
                                errors.append(f"Line ~{line}: {rule_prefix}.item_prototypes[{proto_idx}]: Invalid tag 'triggers' - item prototypes inside discovery rules should use 'trigger_prototypes', not 'triggers'.")
    
    # Validate UUID formats (strict 32-char hex without hyphens)
    def check_uuids(data, path=""):
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if key == 'uuid' or key.endswith('_uuid'):
                    if not validate_zabbix_uuid(value):
                        line = find_line_number(lines, data) or find_line_number(lines, value) or 0
                        msg = f"Line ~{line}: Invalid UUIDv4 format at '{current_path}': '{value}'\n"
                        msg += "     Zabbix requires valid UUIDv4 as 32 hexadecimal characters WITHOUT hyphens.\n"
                        msg += "     UUIDv4 structure: xxxxxxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx\n"
                        msg += "       - Character at position 13 must be '4' (version 4)\n"
                        msg += "       - Character at position 17 must be '8', '9', 'a', or 'b' (variant bits)"
                        errors.append(msg)
                check_uuids(value, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                check_uuids(item, f"{path}[{i}]")
    
    check_uuids(export_data)
    
    # Validate item references in graphs and triggers
    errors.extend(validate_item_references(export_data, lines))
    
    return errors, version

def validate_item_references(export_data, lines):
    """
    Validate that all item references in graphs and triggers point to items that exist in the template.
    Checks:
    - Graph items reference existing item keys
    - Graph prototypes reference existing item prototype keys
    - Trigger expressions reference existing item keys
    - Trigger prototypes reference existing item prototype keys
    """
    errors = []
    
    if 'templates' not in export_data:
        return errors
    
    templates = export_data['templates']
    if not isinstance(templates, list):
        templates = [templates]
    
    for template_idx, template in enumerate(templates):
        if not isinstance(template, dict):
            continue
        
        template_name = template.get('template', template.get('name', 'Unknown'))
        
        # Collect all item keys
        item_keys = set()
        if 'items' in template and isinstance(template['items'], list):
            for item in template['items']:
                if isinstance(item, dict) and 'key' in item:
                    item_keys.add(item['key'])
        
        # Validate regular graphs
        if 'graphs' in template and isinstance(template['graphs'], list):
            for graph_idx, graph in enumerate(template['graphs']):
                if not isinstance(graph, dict):
                    continue
                graph_name = graph.get('name', f'Graph {graph_idx}')
                if 'graph_items' in graph and isinstance(graph['graph_items'], list):
                    for gi_idx, graph_item in enumerate(graph['graph_items']):
                        if not isinstance(graph_item, dict) or 'item' not in graph_item:
                            continue
                        item_ref = graph_item['item']
                        if isinstance(item_ref, dict):
                            ref_host = item_ref.get('host')
                            ref_key = item_ref.get('key')
                            if ref_host and ref_key:
                                # Check if host matches template name
                                if ref_host != template_name:
                                    line = find_line_number(lines, graph) or 0
                                    errors.append(f"Line ~{line}: Graph '{graph_name}' references host '{ref_host}' but template name is '{template_name}'")
                                # Check if item key exists
                                if ref_key not in item_keys:
                                    line = find_line_number(lines, graph) or 0
                                    errors.append(f"Line ~{line}: Graph '{graph_name}' references non-existent item key '{ref_key}'")
        
        # Validate discovery rules and their prototypes
        if 'discovery_rules' in template and isinstance(template['discovery_rules'], list):
            for rule_idx, rule in enumerate(template['discovery_rules']):
                if not isinstance(rule, dict):
                    continue
                rule_name = rule.get('name', f'Discovery rule {rule_idx}')
                
                # Collect all item prototype keys in this discovery rule
                item_proto_keys = set()
                if 'item_prototypes' in rule and isinstance(rule['item_prototypes'], list):
                    for item_proto in rule['item_prototypes']:
                        if isinstance(item_proto, dict) and 'key' in item_proto:
                            item_proto_keys.add(item_proto['key'])
                
                # Validate graph prototypes
                if 'graph_prototypes' in rule and isinstance(rule['graph_prototypes'], list):
                    for gp_idx, graph_proto in enumerate(rule['graph_prototypes']):
                        if not isinstance(graph_proto, dict):
                            continue
                        gp_name = graph_proto.get('name', f'Graph prototype {gp_idx}')
                        if 'graph_items' in graph_proto and isinstance(graph_proto['graph_items'], list):
                            for gi_idx, graph_item in enumerate(graph_proto['graph_items']):
                                if not isinstance(graph_item, dict) or 'item' not in graph_item:
                                    continue
                                item_ref = graph_item['item']
                                if isinstance(item_ref, dict):
                                    ref_host = item_ref.get('host')
                                    ref_key = item_ref.get('key')
                                    if ref_host and ref_key:
                                        # Check if host matches template name
                                        if ref_host != template_name:
                                            line = find_line_number(lines, graph_proto) or 0
                                            errors.append(f"Line ~{line}: Discovery rule '{rule_name}', graph prototype '{gp_name}' references host '{ref_host}' but template name is '{template_name}'")
                                        # Check if item prototype key exists
                                        if ref_key not in item_proto_keys:
                                            line = find_line_number(lines, graph_proto) or 0
                                            errors.append(f"Line ~{line}: Discovery rule '{rule_name}', graph prototype '{gp_name}' references non-existent item prototype key '{ref_key}'")
                
                # Validate trigger prototypes
                if 'trigger_prototypes' in rule and isinstance(rule['trigger_prototypes'], list):
                    for tp_idx, trigger_proto in enumerate(rule['trigger_prototypes']):
                        if not isinstance(trigger_proto, dict):
                            continue
                        tp_name = trigger_proto.get('name', f'Trigger prototype {tp_idx}')
                        expression = trigger_proto.get('expression', '')
                        if expression:
                            # Extract item keys from expression (simplified regex)
                            # Matches patterns like: /template_name/item_key
                            item_refs = re.findall(r'/([^/]+)/([^/\)\],\s]+)', expression)
                            for ref_template, ref_key in item_refs:
                                # Check if template matches
                                if ref_template != template_name:
                                    line = find_line_number(lines, trigger_proto) or 0
                                    errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' references template '{ref_template}' but template name is '{template_name}'")
                                # Check if item prototype key exists
                                if ref_key not in item_proto_keys:
                                    line = find_line_number(lines, trigger_proto) or 0
                                    errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' references non-existent item prototype key '{ref_key}'")
        
        # Validate regular triggers
        if 'triggers' in template and isinstance(template['triggers'], list):
            for trigger_idx, trigger in enumerate(template['triggers']):
                if not isinstance(trigger, dict):
                    continue
                trigger_name = trigger.get('name', f'Trigger {trigger_idx}')
                expression = trigger.get('expression', '')
                if expression:
                    # Extract item keys from expression
                    item_refs = re.findall(r'/([^/]+)/([^/\)\],\s]+)', expression)
                    for ref_template, ref_key in item_refs:
                        # Check if template matches
                        if ref_template != template_name:
                            line = find_line_number(lines, trigger) or 0
                            errors.append(f"Line ~{line}: Trigger '{trigger_name}' references template '{ref_template}' but template name is '{template_name}'")
                        # Check if item key exists
                        if ref_key not in item_keys:
                            line = find_line_number(lines, trigger) or 0
                            errors.append(f"Line ~{line}: Trigger '{trigger_name}' references non-existent item key '{ref_key}'")
    
    return errors

def find_line_number(lines, search_value, current_index=0):
    """Find approximate line number for a value in YAML content"""
    if isinstance(search_value, dict):
        # Use the first key for searching
        if search_value:
            search_value = next(iter(search_value.keys()))
        else:
            return None
    
    if not isinstance(search_value, str):
        return None
        
    for i in range(current_index, len(lines)):
        if search_value in lines[i]:
            return i + 1
    return None

def validate_yaml_file(file_path):
    try:
        # Try different encodings to handle various file formats
        encodings_to_try = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']
        file_content = None
        used_encoding = None
        
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as file:
                    file_content = file.read()
                    used_encoding = encoding
                    break
            except UnicodeDecodeError:
                continue
        
        if file_content is None:
            print(f"❌ Could not decode file with any supported encoding: {encodings_to_try}")
            return False
            
        if used_encoding != 'utf-8':
            print(f"⚠️  Warning: File decoded using {used_encoding} encoding (not UTF-8)")
            
        yaml_data = yaml.safe_load(file_content)
            
        # Basic YAML syntax is valid, now check Zabbix schema
        schema_errors, version = validate_zabbix_schema(yaml_data, file_content)
        
        if not schema_errors:
            if version in SUPPORTED_VERSIONS:
                print(f"[PASS] Valid YAML ({SUPPORTED_VERSIONS[version]} schema)")
            else:
                print(f"[PASS] Valid YAML (version: {version if version else 'unknown'})")
            return True
        else:
            print(f"[FAIL] Found {len(schema_errors)} validation errors:")
            for i, error in enumerate(schema_errors, 1):
                # Format multi-line errors with proper indentation
                if '\n' in error:
                    parts = error.split('\n')
                    print(f"{i:3d}. {parts[0]}")
                    for part in parts[1:]:
                        print(f"     {part}")
                else:
                    print(f"{i:3d}. {error}")
            return False
            
    except YAMLError as e:
        print(f"❌ YAML syntax error: {e}")
        if hasattr(e, 'problem_mark'):
            mark = e.problem_mark
            print(f"Error position: line {mark.line + 1}, column {mark.column + 1}")
        return False
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_zabbix_yaml.py <path_to_yaml_file>")
        print(f"Supports Zabbix export versions: {', '.join(SUPPORTED_VERSIONS.keys())}")
        sys.exit(1)
    
    file_path = sys.argv[1]
    print(f"Validating {file_path}...")
    success = validate_yaml_file(file_path)
    
    sys.exit(0 if success else 1)