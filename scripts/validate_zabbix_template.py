import yaml
from yaml import YAMLError
import sys
import re

# Supported Zabbix versions and their schema formats
SUPPORTED_VERSIONS = {
    '4.0': 'Zabbix 6.0',
    '5.0': 'Zabbix 6.4+ (including 6.7)',
    '6.0': 'Zabbix 7.0+',
    '7.0': 'Zabbix 7.0+ (direct)'
}

def validate_zabbix_uuid(value):
    """Validate UUID in Zabbix format - 32-character hex string without hyphens"""
    # Must be a string
    if not isinstance(value, str):
        return False
    
    # Must be exactly 32 characters long
    if len(value) != 32:
        return False
    
    # Must contain only hexadecimal characters (case-insensitive)
    if not re.match(r'^[a-fA-F0-9]{32}$', value):
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
    
    # Validate UUID formats (strict 32-char hex without hyphens)
    def check_uuids(data, path=""):
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                if key == 'uuid' or key.endswith('_uuid'):
                    if not validate_zabbix_uuid(value):
                        line = find_line_number(lines, data) or find_line_number(lines, value) or 0
                        msg = f"Line ~{line}: Invalid UUID format at '{current_path}': '{value}'\n"
                        msg += "     Zabbix requires exactly 32 hexadecimal characters (0-9, a-f) WITHOUT hyphens"
                        errors.append(msg)
                check_uuids(value, current_path)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                check_uuids(item, f"{path}[{i}]")
    
    check_uuids(export_data)
    
    return errors, version

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
        with open(file_path, 'r') as file:
            file_content = file.read()
            yaml_data = yaml.safe_load(file_content)
            
        # Basic YAML syntax is valid, now check Zabbix schema
        schema_errors, version = validate_zabbix_schema(yaml_data, file_content)
        
        if not schema_errors:
            if version in SUPPORTED_VERSIONS:
                print(f"✅ Valid YAML ({SUPPORTED_VERSIONS[version]} schema)")
            else:
                print(f"✅ Valid YAML (version: {version if version else 'unknown'})")
            return True
        else:
            print(f"❌ Found {len(schema_errors)} validation errors:")
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