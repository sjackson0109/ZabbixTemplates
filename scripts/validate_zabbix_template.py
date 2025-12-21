import sys
import re
import io

# --- Custom YAML Loader (no PyYAML) ---
class SimpleYAMLLoader:
    def __init__(self, text):
        self.lines = text.splitlines()
        self.pos = 0
        self.length = len(self.lines)

    def load(self):
        # Only supports top-level mapping and lists (sufficient for Zabbix template structure)
        result = {}
        stack = [(result, -1)]  # (current_dict_or_list, indent_level)
        for idx, line in enumerate(self.lines):
            if not line.strip() or line.strip().startswith('#'):
                continue
            indent = len(line) - len(line.lstrip(' '))
            content = line.lstrip(' ')
            # Pop stack to correct parent for current indent
            while stack and indent <= stack[-1][1]:
                stack.pop()
            parent = stack[-1][0]
            # Key-value pair
            if ':' in content and not content.startswith('- '):
                key, val = content.split(':', 1)
                key = key.strip()
                val = val.strip()
                # If value is empty, treat as nested mapping or list
                if not val:
                    # Look ahead: if next non-empty line is more indented and starts with '-', treat as list
                    new_obj = {}
                    lookahead = idx + 1
                    while lookahead < self.length:
                        next_line = self.lines[lookahead]
                        if not next_line.strip() or next_line.strip().startswith('#'):
                            lookahead += 1
                            continue
                        next_indent = len(next_line) - len(next_line.lstrip(' '))
                        if next_indent > indent and next_line.lstrip(' ').startswith('- '):
                            new_obj = []
                        break
                    if isinstance(parent, dict):
                        parent[key] = new_obj
                        stack.append((new_obj, indent))
                else:
                    # Scalar value
                    # Remove all leading/trailing single or double quotes (including doubled)
                    while (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
                        val = val[1:-1]
                    if isinstance(parent, dict):
                        parent[key] = val
            elif content.startswith('- '):
                # List item
                val = content[2:].strip()
                if isinstance(parent, list):
                    # If it's a mapping, parse as dict
                    if ':' in val:
                        k, v = val.split(':', 1)
                        k = k.strip()
                        v = v.strip()
                        item = {k: v}
                        parent.append(item)
                        stack.append((item, indent))
                    else:
                        parent.append(val)
        return result

def load_yaml(text):
    loader = SimpleYAMLLoader(text)
    return loader.load()

# --- End Custom YAML Loader ---

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

# Zabbix field enum values
ITEM_TYPES = {
    '0': 'ZABBIX_PASSIVE', 'ZABBIX_PASSIVE': '0',
    '2': 'TRAP', 'TRAP': '2',
    '3': 'SIMPLE', 'SIMPLE': '3',
    '5': 'INTERNAL', 'INTERNAL': '5',
    '7': 'ZABBIX_ACTIVE', 'ZABBIX_ACTIVE': '7',
    '10': 'EXTERNAL', 'EXTERNAL': '10',
    '11': 'ODBC', 'ODBC': '11',
    '12': 'IPMI', 'IPMI': '12',
    '13': 'SSH', 'SSH': '13',
    '14': 'TELNET', 'TELNET': '14',
    '15': 'CALCULATED', 'CALCULATED': '15',
    '16': 'JMX', 'JMX': '16',
    '17': 'SNMP_TRAP', 'SNMP_TRAP': '17',
    '18': 'DEPENDENT', 'DEPENDENT': '18',
    '19': 'HTTP_AGENT', 'HTTP_AGENT': '19',
    '20': 'SNMP_AGENT', 'SNMP_AGENT': '20',
    '21': 'ITEM_TYPE_SCRIPT', 'ITEM_TYPE_SCRIPT': '21',
    '22': 'ITEM_TYPE_BROWSER', 'ITEM_TYPE_BROWSER': '22'
}

VALUE_TYPES = {
    '0': 'FLOAT', 'FLOAT': '0',
    '1': 'CHAR', 'CHAR': '1',
    '2': 'LOG', 'LOG': '2',
    '3': 'UNSIGNED', 'UNSIGNED': '3',
    '4': 'TEXT', 'TEXT': '4',
    '5': 'BINARY', 'BINARY': '5'
}

TRIGGER_PRIORITIES = {
    '0': 'NOT_CLASSIFIED', 'NOT_CLASSIFIED': '0',
    '1': 'INFO', 'INFO': '1',
    '2': 'WARNING', 'WARNING': '2',
    '3': 'AVERAGE', 'AVERAGE': '3',
    '4': 'HIGH', 'HIGH': '4',
    '5': 'DISASTER', 'DISASTER': '5'
}

STATUS_VALUES = {
    '0': 'ENABLED', 'ENABLED': '0',
    '1': 'DISABLED', 'DISABLED': '1'
}

TRIGGER_TYPES = {
    '0': 'SINGLE', 'SINGLE': '0',
    '1': 'MULTIPLE', 'MULTIPLE': '1'
}

MANUAL_CLOSE_VALUES = {
    '0': 'NO', 'NO': '0',
    '1': 'YES', 'YES': '1'
}

RECOVERY_MODES = {
    '0': 'EXPRESSION', 'EXPRESSION': '0',
    '1': 'RECOVERY_EXPRESSION', 'RECOVERY_EXPRESSION': '1',
    '2': 'NONE', 'NONE': '2'
}

def validate_item_key(key):
    """
    Validate Zabbix item key format: key[param1,param2,...]
    Returns: '(is_valid, error_message)'
    """
    if not isinstance(key, str):
        return False, "Item key must be a string"
    
    # Check for unmatched brackets
    open_count = key.count('[')
    close_count = key.count(']')
    
    if open_count != close_count:
        return False, f"Unmatched brackets: {open_count} '[' but {close_count} ']'"
    
    # Basic structure check: alphanumeric, dots, underscores, brackets
    if not re.match(r'^[a-zA-Z0-9._]+(\[.*\])?$', key):
        return False, "Invalid characters in item key"
    
    # Check bracket pairing
    depth = 0
    for i, char in enumerate(key):
        if char == '[':
            depth += 1
        elif char == ']':
            depth -= 1
            if depth < 0:
                return False, f"Closing bracket ']' at position {i} without opening bracket"
    
    if depth != 0:
        return False, "Unclosed brackets in item key"
    
    return True, None

def validate_time_unit(value):
    """
    Validate Zabbix time unit format: number + suffix (s/m/h/d/w) or user macro
    Returns: '(is_valid, error_message)'
    """
    if not isinstance(value, str):
        return False, "Time unit must be a string"
    
    # Allow user macros
    if re.match(r'^\{[^}]+\}$', value):
        return True, None
    
    # Allow numeric-only values (interpreted as seconds)
    if re.match(r'^\d+$', value):
        return True, None
    
    # Check for valid time unit format: <number><suffix>
    if not re.match(r'^\d+[smhdw]$', value):
        return False, "Invalid time unit format. Expected: <number><suffix> where suffix is s/m/h/d/w or a user macro"
    
    return True, None

def validate_snmp_oid(oid):
    """
    Validate SNMP OID format: numeric (1.3.6.1...) or symbolic (IF-MIB::ifInOctets.{#SNMPINDEX})
    Returns: '(is_valid, error_message)'
    """
    if not isinstance(oid, str):
        return False, "SNMP OID must be a string"

    # Allow special SNMP get/walk/discovery OID formats
    if oid.startswith('get[') or oid.startswith('walk[') or oid.startswith('discovery['):
        return True, None

    # Remove LLD macros for validation
    oid_clean = re.sub(r'\{#[^}]+\}', '', oid).rstrip('.')

    # Accept numeric OIDs
    if re.match(r'^\.?[0-9]+(\.[0-9]+)*$', oid_clean):
        return True, None

    # Accept symbolic OIDs in various formats
    if re.match(r'^[A-Za-z0-9\-]+::[a-zA-Z0-9_]+(\.[^ ]+)?$', oid_clean):
        return True, None

    return False, (
        "Invalid SNMP OID format. Expected: numeric.dotted.notation (e.g., 1.3.6.1.2.1.1.1.0), "
        "symbolic (e.g., IF-MIB::ifInOctets.{#SNMPINDEX}), or get[]/walk[]/discovery[] format"
    )

def validate_enum_value(value, enum_dict, field_name):
    """
    Validate enum value against allowed values
    Returns: '(is_valid, error_message)'
    """
    if value is None:
        return True, None  # Optional fields
    
    value_str = str(value)
    if value_str not in enum_dict:
        # Show only the unique enum names for readability
        enum_values = set()
        for k, v in enum_dict.items():
            enum_values.add(v if k.isdigit() else k)
        allowed = ", ".join([f"'{v}'" for v in sorted(enum_values)])
        return False, f"Invalid {field_name}: '{value}'. Allowed values: {allowed}"
    
    return True, None

def parse_trigger_expression(expression):
    """
    Parse trigger expression to extract item references.
    Returns list of (template_name, item_key) tuples.
    
    Handles complex expressions with:
    - Math operations: +, -, *, /, ()
    - Logical operations: and, or, not, <, >, =, <>
    - Functions: last(), avg(), min(), max(), etc.
    - Nested expressions
    - Item keys with parameters: item[param1,param2,...]
    """
    if not isinstance(expression, str):
        return []
    
    # Remove whitespace and newlines for parsing
    expr = ' '.join(expression.split())
    
    matches = []
    
    # Find all function calls with /template/item pattern
    # We need to manually parse to handle nested brackets correctly
    func_pattern = r'(last|avg|min|max|sum|count|delta|nodata|date|time|now|change|diff|str|regexp|iregexp|band|forecast|timeleft|percentile)\s*\('
    
    for func_match in re.finditer(func_pattern, expr):
        func_start = func_match.end()
        
        # Skip whitespace after opening paren
        while func_start < len(expr) and expr[func_start].isspace():
            func_start += 1
        
        # Check if this is a /template/item reference
        if func_start >= len(expr) or expr[func_start] != '/':
            continue
        
        # Parse /template/item
        func_start += 1  # Skip the first /
        
        # Find template name (up to next /)
        template_end = expr.find('/', func_start)
        if template_end == -1:
            continue
        
        template_name = expr[func_start:template_end].strip()
        
        # Now extract the item key - need to handle brackets carefully
        item_start = template_end + 1
        item_end = item_start
        bracket_depth = 0
        
        while item_end < len(expr):
            char = expr[item_end]
            
            if char == '[':
                bracket_depth += 1
                item_end += 1
            elif char == ']':
                bracket_depth -= 1
                item_end += 1
                # If we've closed all brackets, check if we're done
                if bracket_depth == 0:
                    # Peek ahead - if next char is ) or , (outside function), we're done
                    if item_end >= len(expr) or expr[item_end] in ',)':
                        break
            elif char in ',)' and bracket_depth == 0:
                # Found end of item key (comma or close paren outside brackets)
                break
            else:
                item_end += 1
        
        item_key = expr[item_start:item_end].strip()
        
        if item_key:
            matches.append((template_name, item_key))
    
    return matches

def validate_yaml_multiline_strings(file_content):
    """
    Check for improperly terminated multi-line strings in YAML
    Returns: 'list of (line_number, error_message) tuples'
    """
    errors = []
    lines = file_content.splitlines()
    
    in_string = False
    string_start = None
    quote_char = None
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            continue
        
        # Check for string starts
        if not in_string:
            # Look for field: ' or field: "
            if re.search(r':\s*["\']', line):
                # Check if string is closed on same line
                if "'" in line:
                    singles = line.count("'")
                    # Odd number means unclosed
                    if singles % 2 == 1:
                        # Check if it continues on next line (legitimate multi-line)
                        if i < len(lines):
                            next_line = lines[i].strip()
                            if next_line and not next_line.startswith('-') and not next_line.startswith('}'):
                                # This might be intentional multi-line
                                continue
                        in_string = True
                        string_start = i
                        quote_char = "'"
                elif '"' in line:
                    doubles = line.count('"')
                    if doubles % 2 == 1:
                        if i < len(lines):
                            next_line = lines[i].strip()
                            if next_line and not next_line.startswith('-') and not next_line.startswith('}'):
                                continue
                        in_string = True
                        string_start = i
                        quote_char = '"'
        else:
            # We're in a multi-line string, look for closing quote
            if quote_char in line:
                in_string = False
                string_start = None
                quote_char = None
    
    if in_string and string_start:
        errors.append((string_start, f"Unclosed string starting at line {string_start} (expecting closing {quote_char})"))
    
    return errors

def validate_yaml_unquoted_strings(file_content):
    """
    Check for unquoted string values in YAML (e.g., name: value instead of name: 'value')
    Returns: 'list of (line_number, error_message) tuples'
    """
    errors = []
    pattern = re.compile(r'^(\s*[\w\-]+:)\s+([^\'\"\[\{\d\s][^#]*)$')
    lines = file_content.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        # Skip comments, empty lines, and block indicators
        if not stripped or stripped.startswith('#') or stripped.endswith('|') or stripped.endswith('>'):
            continue
        # Only check lines with a colon (key: value)
        if ':' in line:
            # Find the value part
            match = re.match(r'^(\s*[\w\-]+:)\s+(.+)$', line)
            if match:
                key, value = match.groups()
                value = value.strip()
                # Ignore if value starts with a quote, bracket, brace, digit, or is empty
                if value and not (value[0] in "'\"[{0123456789" or value.startswith('null') or value.startswith('true') or value.startswith('false')):
                    # Only warn if value contains spaces (likely a string needing quotes)
                    if ' ' in value:
                        errors.append((i, f"Unquoted string value for {key} on line {i}: {value}"))
    return errors

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
    warnings = []
    version = None
    lines = file_content.splitlines()

    # Validate dashboard widget fields: only type, name, value allowed
    def check_widget_fields_and_filter(dashboards, parent_path):
        if not isinstance(dashboards, list):
            return
        for d_idx, dashboard in enumerate(dashboards):
            if not isinstance(dashboard, dict):
                continue
            pages = dashboard.get('pages')
            if not isinstance(pages, list):
                continue
            for p_idx, page in enumerate(pages):
                if not isinstance(page, dict):
                    continue
                widgets = page.get('widgets')
                if not isinstance(widgets, list):
                    continue
                for w_idx, widget in enumerate(widgets):
                    if not isinstance(widget, dict):
                        continue
                    # Check for invalid 'filter' attribute
                    if 'filter' in widget:
                        errors.append(f"{parent_path}[{d_idx}].pages[{p_idx}].widgets[{w_idx}]: Invalid attribute 'filter' in widget. Widgets do not support a 'filter' attribute.")
                    fields = widget.get('fields')
                    if isinstance(fields, list):
                        for f_idx, field in enumerate(fields):
                            if isinstance(field, dict):
                                invalid = [k for k in field.keys() if k not in ('type', 'name', 'value')]
                                if invalid:
                                    errors.append(f"{parent_path}[{d_idx}].pages[{p_idx}].widgets[{w_idx}].fields[{f_idx}]: Invalid field attribute(s): {', '.join(invalid)}. Only 'type', 'name', and 'value' are allowed.")

    # Helper to check attribute order and presence for uuid/name
    def check_uuid_name_order(section, section_name, parent_path):
        if not isinstance(section, list):
            return
        for idx, obj in enumerate(section):
            if not isinstance(obj, dict):
                continue
            keys = list(obj.keys())
            path = f"{parent_path}[{idx}]"
            if len(keys) < 2:
                errors.append(f"{section_name} {path}: Must have at least 'uuid' and 'name' attributes as the first two keys.")
                continue
            if keys[0] != 'uuid' or keys[1] != 'name':
                errors.append(f"{section_name} {path}: The first attribute must be 'uuid' and the second must be 'name'. Found: {keys[:2]}")

    # Only run this check if dashboards exist
    dashboards = None
    export_data = yaml_data.get('zabbix_export') if 'zabbix_export' in yaml_data else None
    if export_data and 'dashboards' in export_data:
        dashboards = export_data['dashboards']
    if dashboards:
        check_uuid_name_order(dashboards, 'dashboard', 'dashboards')
        if isinstance(dashboards, list):
            for d_idx, dashboard in enumerate(dashboards):
                if not isinstance(dashboard, dict):
                    continue
                # Pages
                pages = dashboard.get('pages')
                if pages:
                    check_uuid_name_order(pages, 'page', f'dashboards[{d_idx}].pages')
                    if isinstance(pages, list):
                        for p_idx, page in enumerate(pages):
                            if not isinstance(page, dict):
                                continue
                            # Widgets
                            widgets = page.get('widgets')
                            if widgets:
                                check_uuid_name_order(widgets, 'widget', f'dashboards[{d_idx}].pages[{p_idx}].widgets')

        # Validate widget fields for all dashboards
        check_widget_fields_and_filter(dashboards, 'dashboards')
    
    # Check for multi-line string issues
    string_errors = validate_yaml_multiline_strings(file_content)
    for line_num, msg in string_errors:
        warnings.append(f"Line {line_num}: {msg}")

    # Check for unquoted string values
    unquoted_errors = validate_yaml_unquoted_strings(file_content)
    for line_num, msg in unquoted_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check required top-level structure
    if 'zabbix_export' not in yaml_data:
        # Only error if the file looks like YAML (not Python or other source)
        if not file_content.lstrip().startswith('import') and not file_content.lstrip().startswith('#!'):
            errors.append("Missing required top-level 'zabbix_export' key")
        return errors, warnings, None
    
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
            
            # Validate items
            if 'items' in template_data:
                validate_items(template_data['items'], f"{prefix}.items", lines, template_line, errors, warnings)
            
            # Validate graphs
            if 'graphs' in template_data:
                validate_graphs(template_data['graphs'], f"{prefix}.graphs", lines, template_line, errors)
            
            # Validate triggers
            if 'triggers' in template_data:
                validate_triggers(template_data['triggers'], f"{prefix}.triggers", lines, template_line, errors, warnings)
            
            # Validate discovery rules
            if 'discovery_rules' in template_data:
                validate_discovery_rules(template_data['discovery_rules'], f"{prefix}.discovery_rules", lines, template_line, errors, warnings)
    
    # Validate UUID formats
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
    ref_errors = validate_item_references(export_data, lines)
    errors.extend(ref_errors)
    
    return errors, warnings, version

def validate_items(items, prefix, lines, template_line, errors, warnings):
    """Validate items section"""
    if isinstance(items, dict):
        items = [items]
    elif not isinstance(items, list):
        line = find_line_number(lines, items) or template_line
        errors.append(f"Line ~{line}: {prefix}: Should be list/dict")
        return
    
    for item_idx, item in enumerate(items):
        item_prefix = f"{prefix}[{item_idx}]"
        
        if not isinstance(item, dict):
            continue
        
        # Validate item key
        if 'key' in item:
            is_valid, error_msg = validate_item_key(item['key'])
            if not is_valid:
                line = find_line_number(lines, item) or template_line
                errors.append(f"Line ~{line}: {item_prefix}: Invalid item key '{item['key']}': {error_msg}")
        
        # Validate time units
        for field in ['delay', 'history', 'trends']:
            if field in item:
                is_valid, error_msg = validate_time_unit(item[field])
                if not is_valid:
                    line = find_line_number(lines, item) or template_line
                    errors.append(f"Line ~{line}: {item_prefix}: Invalid {field} value '{item[field]}': {error_msg}")
        
        # Validate SNMP OID
        if 'snmp_oid' in item:
            is_valid, error_msg = validate_snmp_oid(item['snmp_oid'])
            if not is_valid:
                line = find_line_number(lines, item) or template_line
                errors.append(f"Line ~{line}: {item_prefix}: Invalid SNMP OID '{item['snmp_oid']}': {error_msg}")
        
        # Validate enum fields
        if 'type' in item:
            is_valid, error_msg = validate_enum_value(item['type'], ITEM_TYPES, 'item type')
            if not is_valid:
                line = find_line_number(lines, item) or template_line
                warnings.append(f"Line ~{line}: {item_prefix}: {error_msg}")
        
        if 'value_type' in item:
            is_valid, error_msg = validate_enum_value(item['value_type'], VALUE_TYPES, 'value type')
            if not is_valid:
                line = find_line_number(lines, item) or template_line
                warnings.append(f"Line ~{line}: {item_prefix}: {error_msg}")
        
        if 'status' in item:
            is_valid, error_msg = validate_enum_value(item['status'], STATUS_VALUES, 'status')
            if not is_valid:
                line = find_line_number(lines, item) or template_line
                warnings.append(f"Line ~{line}: {item_prefix}: {error_msg}")
        
        # Validate tags structure
        if 'tags' in item:
            if not isinstance(item['tags'], list):
                line = find_line_number(lines, item) or template_line
                errors.append(f"Line ~{line}: {item_prefix}: 'tags' must be a list")
            else:
                for tag_idx, tag in enumerate(item['tags']):
                    if not isinstance(tag, dict):
                        continue
                    
                    # Tags should only have 'tag' and 'value' fields
                    valid_tag_fields = {'tag', 'value'}
                    invalid_fields = set(tag.keys()) - valid_tag_fields
                    
                    if invalid_fields:
                        line = find_line_number(lines, tag) or template_line
                        errors.append(f"Line ~{line}: {item_prefix}.tags[{tag_idx}]: Invalid field(s) in tag: {', '.join(invalid_fields)}. "
                                    f"Tags can only contain 'tag' and 'value' fields. "
                                    f"Found trigger-like fields - did you mean to put this in 'triggers' section?")
                    
                    # Check required fields
                    if 'tag' not in tag:
                        line = find_line_number(lines, tag) or template_line
                        errors.append(f"Line ~{line}: {item_prefix}.tags[{tag_idx}]: Missing required field 'tag'")
                    if 'value' not in tag:
                        line = find_line_number(lines, tag) or template_line
                        errors.append(f"Line ~{line}: {item_prefix}.tags[{tag_idx}]: Missing required field 'value'")
        
        # Check for invalid *_prototypes under items
        invalid_prototypes = {
            'item_prototypes': 'items',
            'graph_prototypes': 'graphs',
            'host_prototypes': 'hosts'
        }
        
        for proto_key, correct_key in invalid_prototypes.items():
            if proto_key in item:
                line = find_line_number(lines, item) or template_line
                errors.append(f"Line ~{line}: {item_prefix}: Invalid tag '{proto_key}' - items can only have '{correct_key}', not '{proto_key}'. Prototypes (*_prototypes) are only valid inside discovery_rules.")

def validate_graphs(graphs, prefix, lines, template_line, errors):
    """Validate graphs section"""
    if isinstance(graphs, dict):
        graphs = [graphs]
    elif not isinstance(graphs, list):
        line = find_line_number(lines, graphs) or template_line
        errors.append(f"Line ~{line}: {prefix}: Should be list/dict")
        return
    
    for graph_idx, graph in enumerate(graphs):
        graph_prefix = f"{prefix}[{graph_idx}]"
        
        # Check for invalid graph_prototypes under graphs
        if 'graph_prototypes' in graph:
            line = find_line_number(lines, graph) or template_line
            errors.append(f"Line ~{line}: {graph_prefix}: Invalid tag 'graph_prototypes' - graphs section cannot contain 'graph_prototypes'. Graph prototypes are only valid inside discovery_rules.")

def validate_triggers(triggers, prefix, lines, template_line, errors, warnings):
    """Validate triggers section"""
    if isinstance(triggers, dict):
        triggers = [triggers]
    elif not isinstance(triggers, list):
        line = find_line_number(lines, triggers) or template_line
        errors.append(f"Line ~{line}: {prefix}: Should be list/dict")
        return
    
    for trigger_idx, trigger in enumerate(triggers):
        trigger_prefix = f"{prefix}[{trigger_idx}]"
        
        if not isinstance(trigger, dict):
            continue
        
        # Validate enum fields
        if 'priority' in trigger:
            is_valid, error_msg = validate_enum_value(trigger['priority'], TRIGGER_PRIORITIES, 'priority')
            if not is_valid:
                line = find_line_number(lines, trigger) or template_line
                warnings.append(f"Line ~{line}: {trigger_prefix}: {error_msg}")
        
        if 'status' in trigger:
            is_valid, error_msg = validate_enum_value(trigger['status'], STATUS_VALUES, 'status')
            if not is_valid:
                line = find_line_number(lines, trigger) or template_line
                warnings.append(f"Line ~{line}: {trigger_prefix}: {error_msg}")
        
        if 'type' in trigger:
            is_valid, error_msg = validate_enum_value(trigger['type'], TRIGGER_TYPES, 'type')
            if not is_valid:
                line = find_line_number(lines, trigger) or template_line
                warnings.append(f"Line ~{line}: {trigger_prefix}: {error_msg}")
        
        if 'manual_close' in trigger:
            is_valid, error_msg = validate_enum_value(trigger['manual_close'], MANUAL_CLOSE_VALUES, 'manual_close')
            if not is_valid:
                line = find_line_number(lines, trigger) or template_line
                warnings.append(f"Line ~{line}: {trigger_prefix}: {error_msg}")
        
        if 'recovery_mode' in trigger:
            is_valid, error_msg = validate_enum_value(trigger['recovery_mode'], RECOVERY_MODES, 'recovery_mode')
            if not is_valid:
                line = find_line_number(lines, trigger) or template_line
                warnings.append(f"Line ~{line}: {trigger_prefix}: {error_msg}")
        
        # Check for invalid trigger_prototypes under triggers
        if 'trigger_prototypes' in trigger:
            line = find_line_number(lines, trigger) or template_line
            errors.append(f"Line ~{line}: {trigger_prefix}: Invalid tag 'trigger_prototypes' - triggers section cannot contain 'trigger_prototypes'. Trigger prototypes are only valid inside discovery_rules.")

def validate_discovery_rules(discovery_rules, prefix, lines, template_line, errors, warnings):
    """Validate discovery rules section"""
    if isinstance(discovery_rules, dict):
        discovery_rules = [discovery_rules]
    elif not isinstance(discovery_rules, list):
        line = find_line_number(lines, discovery_rules) or template_line
        errors.append(f"Line ~{line}: {prefix}: Should be list/dict")
        return
    
    for rule_idx, rule in enumerate(discovery_rules):
        rule_prefix = f"{prefix}[{rule_idx}]"
        
        if not isinstance(rule, dict):
            continue
        
        # Handle different rule structures
        rule_data = None
        if 'discovery_rule' in rule and isinstance(rule['discovery_rule'], dict):
            rule_data = rule['discovery_rule']
        else:
            rule_data = rule
        
        # Validate time units in discovery rule
        for field in ['delay', 'lifetime']:
            if field in rule_data:
                is_valid, error_msg = validate_time_unit(rule_data[field])
                if not is_valid:
                    line = find_line_number(lines, rule_data) or template_line
                    errors.append(f"Line ~{line}: {rule_prefix}: Invalid {field} value '{rule_data[field]}': {error_msg}")
        
        # Validate item prototypes
        if rule_data and 'item_prototypes' in rule_data:
            validate_items(rule_data['item_prototypes'], f"{rule_prefix}.item_prototypes", lines, template_line, errors, warnings)
        
        # Validate trigger prototypes
        if rule_data and 'trigger_prototypes' in rule_data:
            validate_triggers(rule_data['trigger_prototypes'], f"{rule_prefix}.trigger_prototypes", lines, template_line, errors, warnings)

def validate_item_references(export_data, lines):
    """
    Validate that all item references in graphs and triggers point to items that exist in the template.
    Uses enhanced expression parser for complex trigger expressions.
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
                
                # Validate trigger prototypes using enhanced parser
                if 'trigger_prototypes' in rule and isinstance(rule['trigger_prototypes'], list):
                    for tp_idx, trigger_proto in enumerate(rule['trigger_prototypes']):
                        if not isinstance(trigger_proto, dict):
                            continue
                        tp_name = trigger_proto.get('name', f'Trigger prototype {tp_idx}')
                        
                        # Check both expression and recovery_expression
                        for expr_field in ['expression', 'recovery_expression']:
                            expression = trigger_proto.get(expr_field, '')
                            if expression:
                                item_refs = parse_trigger_expression(expression)
                                for ref_template, ref_key in item_refs:
                                    # Check if template matches
                                    if ref_template != template_name:
                                        line = find_line_number(lines, trigger_proto) or 0
                                        errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' {expr_field} references template '{ref_template}' but template name is '{template_name}'")
                                    # Check if item prototype key exists
                                    if ref_key not in item_proto_keys:
                                        line = find_line_number(lines, trigger_proto) or 0
                                        errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' {expr_field} references non-existent item prototype key '{ref_key}'")
                        
                        # Check dependencies
                        if 'dependencies' in trigger_proto and isinstance(trigger_proto['dependencies'], list):
                            for dep in trigger_proto['dependencies']:
                                if isinstance(dep, dict):
                                    dep_expr = dep.get('expression', '')
                                    if dep_expr:
                                        item_refs = parse_trigger_expression(dep_expr)
                                        for ref_template, ref_key in item_refs:
                                            if ref_template != template_name:
                                                line = find_line_number(lines, trigger_proto) or 0
                                                errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' dependency references template '{ref_template}' but template name is '{template_name}'")
                                            if ref_key not in item_proto_keys:
                                                line = find_line_number(lines, trigger_proto) or 0
                                                errors.append(f"Line ~{line}: Discovery rule '{rule_name}', trigger prototype '{tp_name}' dependency references non-existent item prototype key '{ref_key}'")
        
        # Validate regular triggers using enhanced parser
        if 'triggers' in template and isinstance(template['triggers'], list):
            for trigger_idx, trigger in enumerate(template['triggers']):
                if not isinstance(trigger, dict):
                    continue
                trigger_name = trigger.get('name', f'Trigger {trigger_idx}')
                
                # Check both expression and recovery_expression
                for expr_field in ['expression', 'recovery_expression']:
                    expression = trigger.get(expr_field, '')
                    if expression:
                        item_refs = parse_trigger_expression(expression)
                        for ref_template, ref_key in item_refs:
                            # Check if template matches
                            if ref_template != template_name:
                                line = find_line_number(lines, trigger) or 0
                                errors.append(f"Line ~{line}: Trigger '{trigger_name}' {expr_field} references template '{ref_template}' but template name is '{template_name}'")
                            # Check if item key exists
                            if ref_key not in item_keys:
                                line = find_line_number(lines, trigger) or 0
                                errors.append(f"Line ~{line}: Trigger '{trigger_name}' {expr_field} references non-existent item key '{ref_key}'")
    
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
            
        #yaml_data = yaml.safe_load(file_content)
        yaml_data = load_yaml(file_content)
            
        # Basic YAML syntax is valid, now check Zabbix schema
        schema_errors, schema_warnings, version = validate_zabbix_schema(yaml_data, file_content)
        
        has_errors = len(schema_errors) > 0
        has_warnings = len(schema_warnings) > 0
        
        if not has_errors and not has_warnings:
            if version in SUPPORTED_VERSIONS:
                print(f"✅ [PASS] Valid YAML ({SUPPORTED_VERSIONS[version]} schema)")
            else:
                print(f"✅ [PASS] Valid YAML (version: {version if version else 'unknown'})")
            return True
        else:
            if has_errors:
                print(f"❌ [FAIL] Found {len(schema_errors)} validation error(s)")
                print("\n=== ERRORS ===")
                for i, error in enumerate(schema_errors, 1):
                    # Format multi-line errors with proper indentation
                    if '\n' in error:
                        parts = error.split('\n')
                        print(f"{i:3d}. {parts[0]}")
                        for part in parts[1:]:
                            print(f"     {part}")
                    else:
                        print(f"{i:3d}. {error}")
            
            if has_warnings:
                print(f"\n⚠️  Found {len(schema_warnings)} warning(s)")
                print("\n=== WARNINGS ===")
                for i, warning in enumerate(schema_warnings, 1):
                    print(f"{i:3d}. {warning}")
            
            return not has_errors  # Return True if only warnings, False if errors
            
    except Exception as e:
        print(f"❌ YAML or parsing error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_zabbix_template_enhanced.py <path_to_yaml_file>")
        print(f"Supports Zabbix export versions: {', '.join(SUPPORTED_VERSIONS.keys())}")
        print("\nFeatures:")
        print("  ✓ YAML syntax validation")
        print("  ✓ Zabbix schema structure validation")
        print("  ✓ UUIDv4 format validation")
        print("  ✓ Item key syntax validation (bracket matching)")
        print("  ✓ Time unit format validation (1m, 5h, etc.)")
        print("  ✓ SNMP OID format validation")
        print("  ✓ Enum value validation (types, statuses, priorities)")
        print("  ✓ Item reference integrity (graphs and triggers)")
        print("  ✓ Enhanced trigger expression parsing")
        print("  ✓ Multi-line string validation")
        sys.exit(1)
    
    file_path = sys.argv[1]
    print(f"Validating {file_path}...")
    print("=" * 80)
    success = validate_yaml_file(file_path)
    print("=" * 80)
    
    sys.exit(0 if success else 1)
