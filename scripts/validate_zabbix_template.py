import yaml
from yaml import YAMLError
import sys
import uuid
from collections import defaultdict

def validate_zabbix_schema(yaml_data):
    errors = []
    
    # Check required top-level structure
    if 'zabbix_export' not in yaml_data:
        errors.append("Missing required top-level 'zabbix_export' key")
        return errors
    
    export_data = yaml_data['zabbix_export']
    
    # Check version
    if 'version' not in export_data:
        errors.append("Missing required 'version' field in zabbix_export")
    elif export_data['version'] != "4.0":
        errors.append(f"Unsupported version: {export_data['version']}. Expected '4.0' for Zabbix 6.0")
    
    # Check templates section
    if 'templates' not in export_data:
        errors.append("Missing required 'templates' section")
    else:
        templates = export_data['templates']
        if not isinstance(templates, list) and not isinstance(templates, dict):
            errors.append("'templates' should be a list or dictionary")
        else:
            template_list = templates if isinstance(templates, list) else [templates]
            for template in template_list:
                if 'template' not in template:
                    errors.append("Template missing required 'template' key")
                else:
                    template_data = template['template']
                    
                    # Check template has required fields
                    required_template_fields = ['template', 'name', 'description', 'groups']
                    for field in required_template_fields:
                        if field not in template_data:
                            errors.append(f"Template missing required field: {field}")
                    
                    # Check discovery rules if present
                    if 'discovery_rules' in template_data:
                        discovery_rules = template_data['discovery_rules']
                        if not isinstance(discovery_rules, list) and not isinstance(discovery_rules, dict):
                            errors.append("'discovery_rules' should be a list or dictionary")
                        else:
                            rule_list = discovery_rules if isinstance(discovery_rules, list) else [discovery_rules]
                            for rule in rule_list:
                                if 'discovery_rule' not in rule:
                                    errors.append("Discovery rule missing required 'discovery_rule' key")
                                else:
                                    rule_data = rule['discovery_rule']
                                    
                                    # Check item prototypes
                                    if 'item_prototypes' in rule_data:
                                        item_prototypes = rule_data['item_prototypes']
                                        if not isinstance(item_prototypes, list) and not isinstance(item_prototypes, dict):
                                            errors.append("'item_prototypes' should be a list or dictionary")
    
    # Check UUIDs (if present)
    def check_uuids(data, path=""):
        if isinstance(data, dict):
            for key, value in data.items():
                if key == 'uuid' or key.endswith('_uuid'):
                    try:
                        uuid.UUID(value)
                    except (ValueError, AttributeError):
                        errors.append(f"Invalid UUID format at {path}.{key}: {value}")
                check_uuids(value, f"{path}.{key}" if path else key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                check_uuids(item, f"{path}[{i}]")
    
    check_uuids(export_data)
    
    return errors

def validate_yaml_file(file_path):
    try:
        with open(file_path, 'r') as file:
            yaml_data = yaml.safe_load(file)
            
        # Basic YAML syntax is valid, now check Zabbix schema
        schema_errors = validate_zabbix_schema(yaml_data)
        
        if not schema_errors:
            print("✅ YAML syntax is valid and complies with Zabbix v6.0 schema")
            return True
        else:
            print("❌ Found schema validation errors:")
            for error in schema_errors:
                print(f"  - {error}")
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
        sys.exit(1)
    
    file_path = sys.argv[1]
    print(f"Validating {file_path}...")
    success = validate_yaml_file(file_path)
    
    sys.exit(0 if success else 1)