import sys
import re
import io
import yaml  # PyYAML for proper YAML parsing

# Valid widget field types based on Zabbix 6.4+ documentation
VALID_WIDGET_FIELD_TYPES = {
    # Common field types
    'ITEM', 'STRING', 'INTEGER', 'DECIMAL', 'BOOLEAN',
    
    # Graph widget fields
    'GRAPH', 'GRAPH_ITEM', 'GRAPH_PROTOTYPE',
    
    # Problem widget fields  
    'SEVERITIES', 'PROBLEM_TAGS',
    
    # Data table fields
    'COLUMNS', 'COLUMN',
    
    # Host/Group fields
    'HOST', 'HOST_GROUP', 'HOST_GROUPS',
    
    # Time/refresh fields
    'TIME_PERIOD', 'REFRESH_INTERVAL',
    
    # Display fields
    'OVERRIDE', 'ADVANCED_CONFIG',
    
    # Map fields
    'MAP',
    
    # URL fields
    'URL',
    
    # Text fields
    'TEXT', 'HTML'
}

# Widget types that support specific field types
WIDGET_FIELD_COMPATIBILITY = {
    'GAUGE': {'ITEM', 'STRING', 'DECIMAL', 'BOOLEAN'},
    'GRAPH': {'ITEM', 'GRAPH_ITEM', 'STRING', 'INTEGER', 'BOOLEAN'},
    'DATA_TABLE': {'ITEM', 'COLUMNS', 'COLUMN', 'STRING', 'BOOLEAN'},
    'SINGLE_VALUE': {'ITEM', 'STRING', 'DECIMAL', 'BOOLEAN'},
    'TEXT': {'ITEM', 'STRING', 'HTML'},
    'PROBLEMS': {'ITEM', 'STRING', 'SEVERITIES', 'PROBLEM_TAGS', 'BOOLEAN'},
    'PROBLEMS_BY_SEVERITY': {'ITEM', 'STRING', 'SEVERITIES', 'PROBLEM_TAGS', 'BOOLEAN'},
    'TOP_HOSTS': {'ITEM', 'STRING', 'INTEGER', 'BOOLEAN'},
    'TRIGGER_OVERVIEW': {'HOST_GROUP', 'HOST_GROUPS', 'STRING', 'BOOLEAN'},
    'HONEYCOMB': {'ITEM', 'STRING', 'BOOLEAN'},
    'GRAPH_PROTOTYPE': {'STRING', 'BOOLEAN', 'GRAPH_PROTOTYPE'},  # Include GRAPH_PROTOTYPE field type
}


def load_yaml(content):
    """
    Load YAML content with proper error handling.
    Returns parsed YAML data or raises appropriate exceptions.
    """
    try:
        return yaml.safe_load(content)
    except yaml.YAMLError as e:
        # Provide more helpful error messages for common YAML issues
        error_msg = str(e)
        if "found character '\\t'" in error_msg:
            raise ValueError("YAML syntax error: Found tab character. Use spaces for indentation, not tabs.")
        elif "could not find expected" in error_msg:
            raise ValueError(f"YAML syntax error: Malformed structure. {error_msg}")
        elif "mapping values are not allowed here" in error_msg:
            raise ValueError("YAML syntax error: Incorrect indentation or structure. Check colon placement and spacing.")
        else:
            raise ValueError(f"YAML parsing error: {error_msg}")


# --- Custom YAML Loader (fallback if PyYAML unavailable) ---
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
    """Load YAML using PyYAML (preferred) or fallback to simple loader."""
    try:
        return yaml.safe_load(text)
    except Exception:
        # Fallback to simple loader if PyYAML fails
        loader = SimpleYAMLLoader(text)
        return loader.load()

# --- End Custom YAML Loader ---

# Configure stdout to use UTF-8 encoding to support Unicode emojis
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# Supported Zabbix versions and their schema formats
SUPPORTED_VERSIONS = {
    '4.0': 'Zabbix 4.0',
    '4.5': 'Zabbix 4.5',
    '5.0': 'Zabbix 5.0',
    '5.2': 'Zabbix 5.2',
    '5.4': 'Zabbix 5.4',
    '6.0': 'Zabbix 6.0',
    '7.0': 'Zabbix 7.0',
    '7.1': 'Zabbix 7.1',
    '7.2': 'Zabbix 7.2',
    '7.3': 'Zabbix 7.3',
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

# LLD filter condition operators
# These are the valid operators for discovery rule filter conditions
LLD_FILTER_CONDITION_OPERATORS = {
    '8': 'MATCHES_REGEX', 'MATCHES_REGEX': '8',
    '9': 'NOT_MATCHES_REGEX', 'NOT_MATCHES_REGEX': '9',
    '12': 'EXISTS', 'EXISTS': '12',
    '13': 'NOT_EXISTS', 'NOT_EXISTS': '13',
}

# Graph item draw types (for graph_items.drawtype)
GRAPH_DRAW_TYPES = {
    '0': 'SINGLE_LINE', 'SINGLE_LINE': '0',
    '1': 'FILLED_REGION', 'FILLED_REGION': '1',
    '2': 'BOLD_LINE', 'BOLD_LINE': '2',
    '3': 'DOTTED_LINE', 'DOTTED_LINE': '3',
    '4': 'DASHED_LINE', 'DASHED_LINE': '4',
    '5': 'GRADIENT_LINE', 'GRADIENT_LINE': '5'
}

# Graph item Y-axis side
GRAPH_YAXIS_SIDES = {
    '0': 'LEFT', 'LEFT': '0',
    '1': 'RIGHT', 'RIGHT': '1'
}

# Graph item calculation function
GRAPH_CALC_FNC = {
    '1': 'MIN', 'MIN': '1',
    '2': 'AVG', 'AVG': '2',
    '4': 'MAX', 'MAX': '4',
    '7': 'ALL', 'ALL': '7',
    '9': 'LAST', 'LAST': '9'
}

# Graph item type
GRAPH_ITEM_TYPES = {
    '0': 'SIMPLE', 'SIMPLE': '0',
    '2': 'GRAPH_SUM', 'GRAPH_SUM': '2'
}

# Graph types
GRAPH_TYPES = {
    '0': 'NORMAL', 'NORMAL': '0',
    '1': 'STACKED', 'STACKED': '1',
    '2': 'PIE', 'PIE': '2',
    '3': 'EXPLODED', 'EXPLODED': '3'
}

# Map field names to their allowed enum dictionaries
ZABBIX_ENUM_FIELDS = {
    # Graph item fields
    'drawtype': GRAPH_DRAW_TYPES,
    'yaxisside': GRAPH_YAXIS_SIDES,
    'calc_fnc': GRAPH_CALC_FNC,
    # Trigger fields
    'priority': TRIGGER_PRIORITIES,
    'manual_close': MANUAL_CLOSE_VALUES,
    'recovery_mode': RECOVERY_MODES,
    # Common fields
    'status': STATUS_VALUES,
    # Item fields
    # 'type': ITEM_TYPES,  # Conflicts with graph_item type, handle separately
    'value_type': VALUE_TYPES,
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

    # Remove LLD macros for validation and clean up resulting double dots
    oid_clean = re.sub(r'\{#[^}]+\}', '', oid)
    oid_clean = re.sub(r'\.+', '.', oid_clean)  # Replace multiple dots with single dot
    oid_clean = oid_clean.strip('.')  # Remove leading/trailing dots

    # Accept numeric OIDs
    if re.match(r'^[0-9]+(\.[0-9]+)*$', oid_clean):
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
    Check for unquoted string values in YAML that may cause parsing issues.
    Returns: 'list of (line_number, error_message) tuples'
    
    Only flags values that contain YAML-special characters that REQUIRE quoting:
    - Colon followed by space ': ' in value
    - Hash '#' that could be interpreted as comment
    - Special characters at start: & * ! | > [ ] { } @ `
    
    Does NOT flag simple unquoted strings like 'name: Some Value' which are valid YAML.
    """
    errors = []
    lines = file_content.splitlines()
    
    in_block_scalar = False
    block_scalar_indent = 0
    
    # Characters that require quoting if at start of value
    SPECIAL_START_CHARS = set('&*!|>[]{}@`')
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Calculate current line's indentation
        current_indent = len(line) - len(line.lstrip()) if line.strip() else 0
        
        # Check if we're exiting a block scalar (line has lower or equal indentation)
        if in_block_scalar:
            if stripped and current_indent <= block_scalar_indent:
                in_block_scalar = False
            else:
                # Still inside block scalar, skip this line
                continue
        
        # Skip comments and empty lines
        if not stripped or stripped.startswith('#'):
            continue
            
        # Check if this line starts a block scalar
        if stripped.endswith('|') or stripped.endswith('>') or \
           stripped.endswith('|-') or stripped.endswith('>-') or \
           stripped.endswith('|+') or stripped.endswith('>+'):
            in_block_scalar = True
            block_scalar_indent = current_indent
            continue
        
        # Only check lines with a colon (key: value)
        if ':' in line:
            # Find the value part
            match = re.match(r'^(\s*[\w\-]+:)\s+(.+)$', line)
            if match:
                key, value = match.groups()
                value = value.strip()
                # Skip if value is quoted, a bracket/brace, digit, null, true, false
                if value and not (value[0] in "'\"[{0123456789" or value in ('null', 'true', 'false')):
                    # Only flag if value has YAML-special issues:
                    # 1. Starts with special character
                    if value[0] in SPECIAL_START_CHARS:
                        errors.append((i, f"Unquoted value starting with special char '{value[0]}' for {key} on line {i}: {value}"))
                    # 2. Contains unquoted colon-space ': ' which may confuse YAML parser
                    elif ': ' in value:
                        errors.append((i, f"Unquoted value contains ': ' for {key} on line {i}: {value}"))
                    # 3. Contains '#' which may be interpreted as comment
                    # EXCEPT: Zabbix LLD macros like {#VARNAME} are valid
                    elif '#' in value:
                        # Check if all '#' are part of LLD macros {#...}
                        value_without_lld = re.sub(r'\{#[A-Z0-9_.]+\}', '', value)
                        if '#' in value_without_lld:
                            errors.append((i, f"Unquoted value contains '#' for {key} on line {i}: {value}"))
    return errors

# Fields that Zabbix expects as quoted strings, not bare integers
# These fields will cause import errors if passed as integers
ZABBIX_STRING_REQUIRED_FIELDS = {
    'width', 'height',           # Graph and widget dimensions
    'x', 'y',                    # Widget positions
    'delay',                     # Item/discovery check intervals
    'history', 'trends',         # Data retention periods
    'timeout',                   # Operation timeouts
    'port',                      # SNMP/network ports
    'lifetime', 'enabled_lifetime',  # LLD keep periods
    'snmp_oid',                  # SNMP OIDs must be strings
    'display_period',            # Dashboard slideshow period
    'auto_start',                # Dashboard slideshow auto-start (YES/NO)
}

def validate_string_required_fields(file_content):
    """
    Check for fields that Zabbix expects as strings but are written as bare integers or booleans.
    These cause "a character string is expected" import errors.
    
    Returns: list of (line_number, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    # Pattern: key: followed by bare integer (not quoted)
    # Matches: "  width: 900" but not "  width: '900'" or "  width: 1h"
    int_pattern = re.compile(r'^(\s*)([\w_]+):\s+(\d+)\s*$')
    
    # Pattern: key: followed by bare boolean (not quoted)
    # Matches: "  auto_start: true" but not "  auto_start: 'YES'"
    bool_pattern = re.compile(r'^(\s*)([\w_]+):\s+(true|false)\s*$', re.IGNORECASE)
    
    for line_num, line in enumerate(lines, 1):
        # Check for bare integers
        match = int_pattern.match(line)
        if match:
            indent, field_name, value = match.groups()
            if field_name in ZABBIX_STRING_REQUIRED_FIELDS:
                errors.append((
                    line_num,
                    f"Field '{field_name}' on line {line_num} has integer value {value} but Zabbix expects a quoted string. "
                    f"Change to: {field_name}: '{value}'"
                ))
        
        # Check for bare booleans
        match = bool_pattern.match(line)
        if match:
            indent, field_name, value = match.groups()
            if field_name in ZABBIX_STRING_REQUIRED_FIELDS:
                zabbix_value = 'YES' if value.lower() == 'true' else 'NO'
                errors.append((
                    line_num,
                    f"Field '{field_name}' on line {line_num} has boolean value {value} but Zabbix expects a quoted string. "
                    f"Change to: {field_name}: '{zabbix_value}'"
                ))
    
    return errors

def validate_enum_fields(file_content):
    """
    Check for fields that have a restricted set of allowed values (enums).
    Provides human-readable error messages when invalid values are found.
    
    Returns: list of (line_number, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    # Pattern: key: followed by an unquoted value (letters, numbers, underscores)
    # Matches: "  drawtype: LINE" or "  - drawtype: SINGLE_LINE" (with optional list marker)
    pattern = re.compile(r'^(\s*-?\s*)([\w_]+):\s+([A-Za-z_][A-Za-z0-9_]*)\s*$')
    
    for line_num, line in enumerate(lines, 1):
        match = pattern.match(line)
        if match:
            indent, field_name, value = match.groups()
            
            # Check if this field has an enum constraint
            if field_name in ZABBIX_ENUM_FIELDS:
                enum_dict = ZABBIX_ENUM_FIELDS[field_name]
                
                # Check if value is valid (either as key or as numeric value)
                if value not in enum_dict:
                    # Get the allowed string values (exclude numeric keys)
                    allowed_values = sorted([k for k in enum_dict.keys() if not k.isdigit()])
                    allowed_str = ', '.join(allowed_values)
                    
                    errors.append((
                        line_num,
                        f"Invalid {field_name} value '{value}'. "
                        f"Allowed values: {allowed_str}"
                    ))
    
    return errors

def validate_unexpected_tags(file_content):
    """
    Check for tags that are not allowed in certain contexts.
    For example, dashboard pages do not support 'uuid' tags.
    
    Returns: list of (line_number, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    # Track context - are we inside pages:?
    in_pages = False
    in_widgets = False
    pages_indent = 0
    widgets_indent = 0
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)
        
        # Detect entering pages: section
        if stripped.startswith('pages:'):
            in_pages = True
            pages_indent = current_indent
            in_widgets = False
            continue
        
        # Detect entering widgets: section (nested in pages)
        if in_pages and stripped.startswith('widgets:'):
            in_widgets = True
            widgets_indent = current_indent
            continue
        
        # Detect leaving pages context (less indented than pages:)
        if in_pages and current_indent <= pages_indent and stripped and not stripped.startswith('#'):
            in_pages = False
            in_widgets = False
        
        # Check for uuid inside pages but not inside widgets
        if in_pages and not in_widgets:
            if stripped.startswith('- uuid:') or (stripped.startswith('uuid:') and current_indent > pages_indent):
                # Check we're at page level (more indented than pages: but not in widgets)
                errors.append((
                    line_num,
                    f"Dashboard pages do not support 'uuid' tag. Remove the uuid from this page definition."
                ))
    
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


# Common Zabbix YAML tag misspellings and their correct forms
# Note: 'valuemap' (singular) is VALID inside items as a reference to a value map
# Only 'valuemaps' (plural) is used at template level to define value maps
ZABBIX_TAG_MISSPELLINGS = {
    'value_maps': 'valuemaps',
    'value_map': 'valuemaps',
    'template_group': 'template_groups',
    'templategroups': 'template_groups',
    'templategroup': 'template_groups',
    'discovery_rule': 'discovery_rules',
    'discoveryrules': 'discovery_rules',
    'discoveryrule': 'discovery_rules',
    'item_prototype': 'item_prototypes',
    'itemprototypes': 'item_prototypes',
    'itemprototype': 'item_prototypes',
    'trigger_prototype': 'trigger_prototypes',
    'triggerprototypes': 'trigger_prototypes',
    'triggerprototype': 'trigger_prototypes',
    'graph_prototype': 'graph_prototypes',
    'graphprototypes': 'graph_prototypes',
    'graphprototype': 'graph_prototypes',
    'host_prototype': 'host_prototypes',
    'hostprototypes': 'host_prototypes',
    'hostprototype': 'host_prototypes',
}

def validate_tag_spelling(file_content):
    """
    Check for common misspellings of Zabbix YAML tags.
    Returns a list of (line_num, error_message) tuples for any misspellings found.
    """
    errors = []
    lines = file_content.splitlines()
    
    # Pattern to match YAML keys (with optional leading dash for list items)
    key_pattern = re.compile(r'^(\s*-?\s*)([a-zA-Z_][a-zA-Z0-9_]*):\s*')
    
    for line_num, line in enumerate(lines, 1):
        match = key_pattern.match(line)
        if match:
            key = match.group(2)
            if key in ZABBIX_TAG_MISSPELLINGS:
                correct = ZABBIX_TAG_MISSPELLINGS[key]
                errors.append((
                    line_num,
                    f"Misspelled tag '{key}' - should be '{correct}'. "
                    f"This will cause import error: 'unexpected tag \"{key}\"'"
                ))
    
    return errors


def validate_lld_filter_operators(yaml_data, file_content):
    """
    Validate LLD filter condition operators.
    Returns a list of (line_num, error_message) tuples for invalid operators.
    
    Valid operators for LLD filter conditions are:
    - MATCHES_REGEX (8)
    - NOT_MATCHES_REGEX (9)
    - EXISTS (12)
    - NOT_EXISTS (13)
    """
    errors = []
    lines = file_content.splitlines()
    
    valid_operators = {'MATCHES_REGEX', 'NOT_MATCHES_REGEX', 'EXISTS', 'NOT_EXISTS', '8', '9', '12', '13'}
    
    def find_line_for_value(search_value, start_line=0):
        """Find the line number where a value appears."""
        for i, line in enumerate(lines[start_line:], start_line + 1):
            if search_value in line:
                return i
        return None
    
    def check_discovery_rules(discovery_rules, path):
        """Recursively check discovery rules for invalid filter operators."""
        if not isinstance(discovery_rules, list):
            return
        
        for rule_idx, rule in enumerate(discovery_rules):
            if not isinstance(rule, dict):
                continue
            
            rule_path = f"{path}[{rule_idx}]"
            
            # Check filter conditions
            if 'filter' in rule and isinstance(rule['filter'], dict):
                conditions = rule['filter'].get('conditions', [])
                if isinstance(conditions, list):
                    for cond_idx, condition in enumerate(conditions):
                        if isinstance(condition, dict) and 'operator' in condition:
                            operator = str(condition['operator'])
                            if operator not in valid_operators:
                                line_num = find_line_for_value(f"operator: {operator}")
                                if not line_num:
                                    line_num = find_line_for_value(operator)
                                errors.append((
                                    line_num or 0,
                                    f"Invalid LLD filter condition operator '{operator}' at {rule_path}.filter.conditions[{cond_idx}]. "
                                    f"Valid operators: MATCHES_REGEX, NOT_MATCHES_REGEX, EXISTS, NOT_EXISTS"
                                ))
    
    # Process templates
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if isinstance(template, dict) and 'discovery_rules' in template:
                check_discovery_rules(template['discovery_rules'], f"templates[{t_idx}].discovery_rules")
    
    return errors


def validate_dashboard_widget_filter(yaml_data, file_content):
    """
    Validate that 'filter' tag is not used inside dashboard widgets.
    The 'filter' tag is only valid in LLD discovery_rules, not in dashboard widgets.
    Returns a list of (line_num, error_message) tuples for invalid filter usage.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_widget_filter(widget_name, start_line=0):
        """Find the line number where filter appears after a widget definition."""
        in_widget = False
        widget_indent = 0
        for i, line in enumerate(lines[start_line:], start_line + 1):
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)
            
            # Check if we found the widget name
            if f"name: '{widget_name}'" in line or f'name: "{widget_name}"' in line:
                in_widget = True
                widget_indent = current_indent
                continue
            
            if in_widget:
                # If we hit a line with less or equal indent, we've left the widget
                if stripped and current_indent <= widget_indent and not stripped.startswith('-'):
                    in_widget = False
                    continue
                # Check for filter at this level
                if stripped.startswith('filter:'):
                    return i
        return None
    
    def check_widgets(widgets, path, dashboard_name, page_name):
        """Check widgets for invalid filter usage."""
        if not isinstance(widgets, list):
            return
        
        for w_idx, widget in enumerate(widgets):
            if not isinstance(widget, dict):
                continue
            
            widget_name = widget.get('name', f'widget[{w_idx}]')
            widget_path = f"{path}/widgets/widget({w_idx + 1})"
            
            if 'filter' in widget:
                # Find the line number
                line_num = find_line_for_widget_filter(widget_name)
                errors.append((
                    line_num or 0,
                    f"Invalid tag 'filter' in dashboard widget '{widget_name}' at {widget_path}. "
                    f"The 'filter' tag is not valid inside dashboard widgets in Zabbix 7.0"
                ))
    
    # Process templates -> dashboards -> pages -> widgets
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            dashboards = template.get('dashboards', [])
            if not isinstance(dashboards, list):
                continue
            
            for d_idx, dashboard in enumerate(dashboards):
                if not isinstance(dashboard, dict):
                    continue
                
                dashboard_name = dashboard.get('name', f'dashboard({d_idx + 1})')
                dashboard_path = f"/zabbix_export/templates/{template_name}/dashboards/dashboard({d_idx + 1})"
                pages = dashboard.get('pages', [])
                if not isinstance(pages, list):
                    continue
                
                for p_idx, page in enumerate(pages):
                    if not isinstance(page, dict):
                        continue
                    
                    page_name = page.get('name', f'page({p_idx + 1})')
                    page_path = f"{dashboard_path}/pages/page({p_idx + 1})"
                    widgets = page.get('widgets', [])
                    check_widgets(widgets, page_path, dashboard_name, page_name)
    
    return errors


def validate_item_prototype_filter(yaml_data, file_content):
    """
    Validate that 'filter' tag is not used inside item_prototypes.
    The 'filter' tag is only valid at the discovery_rule level, not in item_prototypes.
    Returns a list of (line_num, error_message) tuples for invalid filter usage.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_filter_in_item(item_name, discovery_rule_name):
        """Find the line number where filter appears inside an item_prototype."""
        in_discovery = False
        in_item_prototypes = False
        in_item = False
        item_indent = 0
        
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            current_indent = len(line) - len(stripped)
            
            # Track if we're in a discovery_rule
            if 'discovery_rules:' in line:
                in_discovery = True
                continue
            
            if in_discovery and 'item_prototypes:' in line:
                in_item_prototypes = True
                continue
            
            if in_item_prototypes:
                # Check if we found the item name
                if f"name: {item_name}" in line or f"name: '{item_name}'" in line or f'name: "{item_name}"' in line:
                    in_item = True
                    item_indent = current_indent
                    continue
                
                if in_item:
                    # If we hit a line with less or equal indent that's a new item, we've left the item
                    if stripped and current_indent <= item_indent and stripped.startswith('- '):
                        in_item = False
                        continue
                    # Check for filter at this level
                    if stripped == 'filter:' or stripped.startswith('filter:'):
                        return i
        return None
    
    def check_item_prototypes(item_prototypes, path, discovery_rule_name):
        """Check item_prototypes for invalid filter usage."""
        if not isinstance(item_prototypes, list):
            return
        
        for ip_idx, item_prototype in enumerate(item_prototypes):
            if not isinstance(item_prototype, dict):
                continue
            
            item_name = item_prototype.get('name', f'item_prototype[{ip_idx}]')
            item_path = f"{path}/item_prototypes/item_prototype({ip_idx + 1})"
            
            if 'filter' in item_prototype:
                # Find the line number
                line_num = find_line_for_filter_in_item(item_name, discovery_rule_name)
                errors.append((
                    line_num or 0,
                    f"Invalid tag 'filter' in item_prototype '{item_name}' at {item_path}. "
                    f"The 'filter' tag is only valid at the discovery_rule level, not inside item_prototypes."
                ))
    
    # Process templates -> discovery_rules -> item_prototypes
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            discovery_rules = template.get('discovery_rules', [])
            if not isinstance(discovery_rules, list):
                continue
            
            for dr_idx, discovery_rule in enumerate(discovery_rules):
                if not isinstance(discovery_rule, dict):
                    continue
                
                dr_name = discovery_rule.get('name', f'discovery_rule({dr_idx + 1})')
                dr_path = f"/zabbix_export/templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})"
                
                item_prototypes = discovery_rule.get('item_prototypes', [])
                check_item_prototypes(item_prototypes, dr_path, dr_name)
    
    return errors


def validate_graph_item_types(yaml_data, file_content):
    """
    Validate that graph prototypes only reference numeric items (FLOAT, UNSIGNED, etc.).
    TEXT and LOG items cannot be used in graphs.
    Returns a list of (line_num, error_message) tuples for invalid graph item references.
    """
    errors = []
    lines = file_content.splitlines()
    
    # Numeric value types that can be used in graphs
    NUMERIC_VALUE_TYPES = {'FLOAT', 'UNSIGNED', None}  # None = default (UNSIGNED)
    NON_NUMERIC_VALUE_TYPES = {'TEXT', 'LOG', 'CHAR'}
    
    def find_line_for_graph(graph_name):
        """Find the line number for a graph prototype by name."""
        for i, line in enumerate(lines, 1):
            if f"name: '{graph_name}'" in line or f'name: "{graph_name}"' in line or f"name: {graph_name}" in line:
                return i
        return 0
    
    def build_item_key_to_value_type_map(template):
        """Build a map of item keys to their value_types within a template."""
        key_to_type = {}
        
        # Check regular items
        items = template.get('items', [])
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    key = item.get('key')
                    value_type = item.get('value_type')
                    if key:
                        key_to_type[key] = value_type
        
        # Check item prototypes in discovery rules
        discovery_rules = template.get('discovery_rules', [])
        if isinstance(discovery_rules, list):
            for dr in discovery_rules:
                if isinstance(dr, dict):
                    item_prototypes = dr.get('item_prototypes', [])
                    if isinstance(item_prototypes, list):
                        for ip in item_prototypes:
                            if isinstance(ip, dict):
                                key = ip.get('key')
                                value_type = ip.get('value_type')
                                if key:
                                    key_to_type[key] = value_type
        
        return key_to_type
    
    def check_graph_prototypes(graph_prototypes, path, key_to_type, template_name):
        """Check graph prototypes for non-numeric item references."""
        if not isinstance(graph_prototypes, list):
            return
        
        for gp_idx, graph_proto in enumerate(graph_prototypes):
            if not isinstance(graph_proto, dict):
                continue
            
            graph_name = graph_proto.get('name', f'graph_prototype({gp_idx + 1})')
            graph_path = f"{path}/graph_prototypes/graph_prototype({gp_idx + 1})"
            
            graph_items = graph_proto.get('graph_items', [])
            if not isinstance(graph_items, list):
                continue
            
            for gi_idx, graph_item in enumerate(graph_items):
                if not isinstance(graph_item, dict):
                    continue
                
                item_ref = graph_item.get('item', {})
                if isinstance(item_ref, dict):
                    item_key = item_ref.get('key')
                    if item_key:
                        value_type = key_to_type.get(item_key)
                        if value_type in NON_NUMERIC_VALUE_TYPES:
                            line_num = find_line_for_graph(graph_name)
                            errors.append((
                                line_num,
                                f"Graph prototype '{graph_name}' at {graph_path} references non-numeric item "
                                f"'{item_key}' with value_type '{value_type}'. Graphs can only use numeric items "
                                f"(FLOAT, UNSIGNED)."
                            ))
    
    # Process templates -> discovery_rules -> graph_prototypes
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            
            # Build item key to value_type map for this template
            key_to_type = build_item_key_to_value_type_map(template)
            
            # Check discovery rules for graph_prototypes
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, discovery_rule in enumerate(discovery_rules):
                    if not isinstance(discovery_rule, dict):
                        continue
                    
                    dr_name = discovery_rule.get('name', f'discovery_rule({dr_idx + 1})')
                    dr_path = f"/zabbix_export/templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})"
                    
                    graph_prototypes = discovery_rule.get('graph_prototypes', [])
                    check_graph_prototypes(graph_prototypes, dr_path, key_to_type, template_name)
    
    return errors


def validate_invalid_export_tags(yaml_data, file_content):
    """
    Validate that zabbix_export doesn't contain invalid tags like 'date' or 'groups'.
    The 'date' tag is not valid in Zabbix 7.0 template imports.
    The 'groups' tag was replaced with 'template_groups' in Zabbix 6.0+.
    Returns a list of (line_num, error_message) tuples for invalid tags.
    """
    errors = []
    lines = file_content.splitlines()
    
    # Tags that are not valid in zabbix_export for import
    INVALID_EXPORT_TAGS = {'date', 'export_date'}
    
    # Tags that have been replaced with different names in Zabbix 7.0
    REPLACED_EXPORT_TAGS = {
        'groups': 'template_groups'  # 'groups' at zabbix_export level is now 'template_groups'
    }
    
    export_data = yaml_data.get('zabbix_export', {})
    
    for tag in INVALID_EXPORT_TAGS:
        if tag in export_data:
            # Find line number
            line_num = 0
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith(f'{tag}:'):
                    line_num = i
                    break
            errors.append((
                line_num,
                f"Invalid tag '{tag}' in zabbix_export. "
                f"The '{tag}' tag is not valid for Zabbix 7.0 template imports and should be removed."
            ))
    
    # Check for tags that have been replaced
    for old_tag, new_tag in REPLACED_EXPORT_TAGS.items():
        if old_tag in export_data:
            # Find line number - look for exact match at zabbix_export level (2 spaces)
            line_num = 0
            for i, line in enumerate(lines, 1):
                # Only match 'groups:' at the zabbix_export level (2 spaces indent)
                if line.startswith('  ' + old_tag + ':') and not line.startswith('    '):
                    line_num = i
                    break
            errors.append((
                line_num,
                f"Invalid tag '{old_tag}' in zabbix_export. "
                f"In Zabbix 7.0, '{old_tag}' at the zabbix_export level should be renamed to '{new_tag}'."
            ))
    
    return errors


def validate_lld_macro_in_prototypes(yaml_data, file_content):
    """
    Validate that item_prototypes contain at least one LLD macro ({#...}) in their key.
    Item prototypes must use LLD macros from the discovery rule, not user macros ({$...}).
    Returns a list of (line_num, error_message) tuples for missing LLD macros.
    """
    errors = []
    lines = file_content.splitlines()
    
    import re
    # LLD macros can contain letters, numbers, underscores, and dots (e.g., {#CLIENT.MAC.ADDR})
    LLD_MACRO_PATTERN = re.compile(r'\{#[A-Z0-9_.]+\}')
    USER_MACRO_PATTERN = re.compile(r'\{\$[A-Z0-9_]+\}')
    
    def find_line_for_item_key(item_key):
        """Find line number for an item by its key."""
        for i, line in enumerate(lines, 1):
            if f"key: {item_key}" in line or f"key: '{item_key}'" in line or f'key: "{item_key}"' in line:
                return i
        return 0
    
    def check_item_prototypes(item_prototypes, path, dr_name):
        """Check item prototypes for LLD macro usage."""
        if not isinstance(item_prototypes, list):
            return
        
        for ip_idx, item_proto in enumerate(item_prototypes):
            if not isinstance(item_proto, dict):
                continue
            
            item_name = item_proto.get('name', f'item_prototype({ip_idx + 1})')
            item_key = item_proto.get('key', '')
            ip_path = f"{path}/item_prototypes/item_prototype({ip_idx + 1})"
            
            # Check if key contains at least one LLD macro
            if item_key and not LLD_MACRO_PATTERN.search(item_key):
                line_num = find_line_for_item_key(item_key)
                # Check if it incorrectly uses user macro instead
                if USER_MACRO_PATTERN.search(item_key):
                    user_macros = USER_MACRO_PATTERN.findall(item_key)
                    errors.append((
                        line_num,
                        f"Item prototype '{item_name}' at {ip_path} uses user macro(s) {user_macros} "
                        f"instead of LLD macro(s). Item prototype keys must contain at least one "
                        f"LLD macro (e.g., {{#PORT}}) from the discovery rule, not user macros ({{$...}})."
                    ))
                else:
                    errors.append((
                        line_num,
                        f"Item prototype '{item_name}' at {ip_path} key '{item_key}' does not contain "
                        f"any LLD macro. Item prototype keys must contain at least one LLD macro "
                        f"(e.g., {{#IFNAME}}, {{#PORT}}) from the discovery rule."
                    ))
    
    # Process templates -> discovery_rules -> item_prototypes
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            discovery_rules = template.get('discovery_rules', [])
            if not isinstance(discovery_rules, list):
                continue
            
            for dr_idx, dr in enumerate(discovery_rules):
                if not isinstance(dr, dict):
                    continue
                
                dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                dr_path = f"/zabbix_export/templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})"
                
                item_prototypes = dr.get('item_prototypes', [])
                check_item_prototypes(item_prototypes, dr_path, dr_name)
    
    return errors


def validate_numeric_constants(yaml_data, file_content):
    """
    Validate that fields requiring string constants in Zabbix 7.0 don't use numeric values.
    Zabbix 7.0 requires string constants like 'ZABBIX_PASSIVE', 'FLOAT', 'ENABLED' etc.
    instead of numeric values like 0, 3, 1.
    Returns a list of (line_num, error_message) tuples for invalid numeric constants.
    """
    errors = []
    lines = file_content.splitlines()
    
    # Fields that require string constants in Zabbix 7.0, mapped to their valid values
    # Item type constants
    ITEM_TYPE_VALUES = {
        '0': 'ZABBIX_PASSIVE', '1': 'SNMPv1', '2': 'TRAP', '3': 'SIMPLE', '4': 'SNMPv2',
        '5': 'INTERNAL', '6': 'SNMPv3', '7': 'ZABBIX_ACTIVE', '8': 'AGGREGATE',
        '9': 'HTTP_AGENT', '10': 'EXTERNAL', '11': 'ODBC', '12': 'IPMI', '13': 'SSH',
        '14': 'TELNET', '15': 'CALCULATED', '16': 'JMX', '17': 'SNMP_TRAP',
        '18': 'DEPENDENT', '19': 'SCRIPT', '20': 'BROWSER'
    }
    
    # Value type constants
    VALUE_TYPE_VALUES = {
        '0': 'FLOAT', '1': 'CHAR', '2': 'LOG', '3': 'UNSIGNED', '4': 'TEXT', '5': 'BINARY'
    }
    
    # Preprocessing type constants
    PREPROCESSING_TYPE_VALUES = {
        '1': 'MULTIPLIER', '2': 'RTRIM', '3': 'LTRIM', '4': 'TRIM', '5': 'REGEX',
        '6': 'BOOL_TO_DECIMAL', '7': 'OCTAL_TO_DECIMAL', '8': 'HEX_TO_DECIMAL',
        '9': 'SIMPLE_CHANGE', '10': 'CHANGE_PER_SECOND', '11': 'XMLPATH',
        '12': 'JSONPATH', '13': 'IN_RANGE', '14': 'MATCHES_REGEX', '15': 'NOT_MATCHES_REGEX',
        '16': 'CHECK_JSON_ERROR', '17': 'CHECK_XML_ERROR', '18': 'CHECK_REGEX_ERROR',
        '19': 'DISCARD_UNCHANGED', '20': 'DISCARD_UNCHANGED_HEARTBEAT',
        '21': 'JAVASCRIPT', '22': 'PROMETHEUS_PATTERN', '23': 'PROMETHEUS_TO_JSON',
        '24': 'CSV_TO_JSON', '25': 'STR_REPLACE', '26': 'CHECK_NOT_SUPPORTED',
        '27': 'XML_TO_JSON', '28': 'SNMP_WALK_VALUE', '29': 'SNMP_WALK_TO_JSON'
    }
    
    def find_line_number(search_pattern, start_line=0):
        """Find line number containing the pattern."""
        for i, line in enumerate(lines[start_line:], start_line + 1):
            if search_pattern in line:
                return i
        return 0
    
    # Valid status values
    STATUS_VALUES = {'0': 'ENABLED', '1': 'DISABLED'}
    
    # Valid inventory_link values (0 = NONE, other numbers map to inventory fields)
    # Common values: 0=NONE, 1=TYPE, 2=TYPE_FULL, 3=NAME, 4=ALIAS, 5=OS, 6=OS_FULL, etc.
    # See https://www.zabbix.com/documentation/7.0/en/manual/api/reference/item/object
    INVENTORY_LINK_VALUES = {
        '0': 'NONE', '1': 'TYPE', '2': 'TYPE_FULL', '3': 'NAME', '4': 'ALIAS',
        '5': 'OS', '6': 'OS_FULL', '7': 'OS_SHORT', '8': 'SERIALNO_A', '9': 'SERIALNO_B',
        '10': 'TAG', '11': 'ASSET_TAG', '12': 'MACADDRESS_A', '13': 'MACADDRESS_B',
        '14': 'HARDWARE', '15': 'HARDWARE_FULL', '16': 'SOFTWARE', '17': 'SOFTWARE_FULL',
        '18': 'SOFTWARE_APP_A', '19': 'SOFTWARE_APP_B', '20': 'SOFTWARE_APP_C',
        '21': 'SOFTWARE_APP_D', '22': 'SOFTWARE_APP_E', '23': 'CONTACT', '24': 'LOCATION',
        '25': 'LOCATION_LAT', '26': 'LOCATION_LON', '27': 'NOTES', '28': 'CHASSIS',
        '29': 'MODEL', '30': 'HW_ARCH', '31': 'VENDOR', '32': 'CONTRACT_NUMBER',
        '33': 'INSTALLER_NAME', '34': 'DEPLOYMENT_STATUS', '35': 'URL_A', '36': 'URL_B',
        '37': 'URL_C', '38': 'HOST_NETWORKS', '39': 'HOST_NETMASK', '40': 'HOST_ROUTER',
        '41': 'OOB_IP', '42': 'OOB_NETMASK', '43': 'OOB_ROUTER', '44': 'DATE_HW_PURCHASE',
        '45': 'DATE_HW_INSTALL', '46': 'DATE_HW_EXPIRY', '47': 'DATE_HW_DECOMM',
        '48': 'SITE_ADDRESS_A', '49': 'SITE_ADDRESS_B', '50': 'SITE_ADDRESS_C',
        '51': 'SITE_CITY', '52': 'SITE_STATE', '53': 'SITE_COUNTRY', '54': 'SITE_ZIP',
        '55': 'SITE_RACK', '56': 'SITE_NOTES', '57': 'POC_1_NAME', '58': 'POC_1_EMAIL',
        '59': 'POC_1_PHONE_A', '60': 'POC_1_PHONE_B', '61': 'POC_1_CELL', '62': 'POC_1_SCREEN',
        '63': 'POC_1_NOTES', '64': 'POC_2_NAME', '65': 'POC_2_EMAIL', '66': 'POC_2_PHONE_A',
        '67': 'POC_2_PHONE_B', '68': 'POC_2_CELL', '69': 'POC_2_SCREEN', '70': 'POC_2_NOTES'
    }
    
    def check_item_for_numeric_constants(item, path, item_name):
        """Check an item for numeric constants that should be strings."""
        # Check status
        status = item.get('status')
        if status is not None:
            status_str = str(status).strip('"\'')
            if status_str in STATUS_VALUES:
                line_num = find_line_number(f"status: {status}")
                errors.append((
                    line_num,
                    f"Invalid numeric constant '{status}' for 'status' in item '{item_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{STATUS_VALUES[status_str]}' instead."
                ))
        
        # Check item type
        item_type = item.get('type')
        if item_type is not None:
            type_str = str(item_type).strip('"\'')
            if type_str in ITEM_TYPE_VALUES:
                line_num = find_line_number(f"type: {item_type}") or find_line_number(f'type: "{item_type}"')
                errors.append((
                    line_num,
                    f"Invalid numeric constant '{item_type}' for 'type' in item '{item_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{ITEM_TYPE_VALUES[type_str]}' instead."
                ))
        
        # Check value_type
        value_type = item.get('value_type')
        if value_type is not None:
            vt_str = str(value_type).strip('"\'')
            if vt_str in VALUE_TYPE_VALUES:
                line_num = find_line_number(f"value_type: {value_type}")
                errors.append((
                    line_num,
                    f"Invalid numeric constant '{value_type}' for 'value_type' in item '{item_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{VALUE_TYPE_VALUES[vt_str]}' instead."
                ))
        
        # Check inventory_link
        inventory_link = item.get('inventory_link')
        if inventory_link is not None:
            il_str = str(inventory_link).strip('"\'')
            if il_str in INVENTORY_LINK_VALUES:
                line_num = find_line_number(f"inventory_link: {inventory_link}")
                errors.append((
                    line_num,
                    f"Invalid numeric constant '{inventory_link}' for 'inventory_link' in item '{item_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{INVENTORY_LINK_VALUES[il_str]}' instead."
                ))
        
        # Check preprocessing steps
        preprocessing = item.get('preprocessing', [])
        if isinstance(preprocessing, dict):
            # Handle old format: preprocessing: {step: [...]}
            preprocessing = preprocessing.get('step', [])
        if isinstance(preprocessing, list):
            for pp_idx, pp in enumerate(preprocessing):
                if isinstance(pp, dict):
                    pp_type = pp.get('type')
                    if pp_type is not None:
                        pt_str = str(pp_type).strip('"\'')
                        if pt_str in PREPROCESSING_TYPE_VALUES:
                            errors.append((
                                0,
                                f"Invalid numeric constant '{pp_type}' for preprocessing 'type' in item '{item_name}' at {path}. "
                                f"Zabbix 7.0 requires string constant '{PREPROCESSING_TYPE_VALUES[pt_str]}' instead."
                            ))
    
    def check_discovery_rule_for_numeric_constants(dr, path, dr_name):
        """Check a discovery rule for numeric constants."""
        # Check status
        status = dr.get('status')
        if status is not None:
            status_str = str(status).strip('"\'')
            if status_str in STATUS_VALUES:
                errors.append((
                    0,
                    f"Invalid numeric constant '{status}' for 'status' in discovery rule '{dr_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{STATUS_VALUES[status_str]}' instead."
                ))
        
        # Check discovery rule type
        dr_type = dr.get('type')
        if dr_type is not None:
            type_str = str(dr_type).strip('"\'')
            if type_str in ITEM_TYPE_VALUES:
                errors.append((
                    0,
                    f"Invalid numeric constant '{dr_type}' for 'type' in discovery rule '{dr_name}' at {path}. "
                    f"Zabbix 7.0 requires string constant '{ITEM_TYPE_VALUES[type_str]}' instead."
                ))
        
        # Check item prototypes
        item_prototypes = dr.get('item_prototypes', [])
        if isinstance(item_prototypes, list):
            for ip_idx, ip in enumerate(item_prototypes):
                if isinstance(ip, dict):
                    ip_name = ip.get('name', f'item_prototype({ip_idx + 1})')
                    ip_path = f"{path}/item_prototypes/item_prototype({ip_idx + 1})"
                    check_item_for_numeric_constants(ip, ip_path, ip_name)
    
    # Process templates
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            
            # Check regular items
            items = template.get('items', [])
            if isinstance(items, list):
                for i_idx, item in enumerate(items):
                    if isinstance(item, dict):
                        item_name = item.get('name', f'item({i_idx + 1})')
                        item_path = f"/zabbix_export/templates/{template_name}/items/item({i_idx + 1})"
                        check_item_for_numeric_constants(item, item_path, item_name)
            
            # Check discovery rules
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if isinstance(dr, dict):
                        dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                        dr_path = f"/zabbix_export/templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})"
                        check_discovery_rule_for_numeric_constants(dr, dr_path, dr_name)
    
    return errors


# Invalid/deprecated trigger functions in Zabbix 7.0
# These functions don't exist or have been replaced
INVALID_TRIGGER_FUNCTIONS = {
    'regexp': 'Use find(item,#num,,"regexp","pattern") instead',
    'iregexp': 'Use find(item,#num,,"iregexp","pattern") instead',
    'str': 'Use find(item,#num,,"like","string") instead',
    'strlen': 'Use length(last(item)) instead',
    'regexp_substring': 'Use function with preprocessing instead',
    'logeventid': 'Use find() with appropriate operator instead',
    'logsource': 'Use find() with appropriate operator instead',
    'logseverity': 'Function deprecated in Zabbix 7.0',
}

# Valid Zabbix 7.0 trigger functions (partial list of commonly used ones)
VALID_TRIGGER_FUNCTIONS = {
    'abs', 'avg', 'band', 'between', 'bitand', 'bitlshift', 'bitnot', 'bitor',
    'bitrshift', 'bitxor', 'cbrt', 'ceil', 'change', 'changecount', 'count',
    'countunique', 'date', 'dayofmonth', 'dayofweek', 'diff', 'exp', 'expm1',
    'find', 'first', 'floor', 'forecast', 'fuzzytime', 'in', 'insert', 'jsonpath',
    'kurtosis', 'last', 'left', 'length', 'log', 'log10', 'ltrim', 'mad', 'max',
    'mid', 'min', 'mod', 'monodec', 'monoinc', 'nodata', 'now', 'percentile',
    'power', 'rate', 'repeat', 'replace', 'right', 'round', 'rtrim', 'signum',
    'skewness', 'sqrt', 'stddevpop', 'stddevsamp', 'sum', 'time', 'timeleft',
    'trendavg', 'trendcount', 'trendmax', 'trendmin', 'trendstl', 'trendsum',
    'trim', 'truncate', 'varpop', 'varsamp', 'xmlxpath',
}


def validate_duplicate_keys_in_same_object(file_content):
    """
    Check for duplicate keys within the same YAML object by parsing line by line.
    This detects real duplicate keys like having two 'description:' in the same object.
    
    Returns: list of (line_number, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    # Use a simple approach: detect when we have the same key at the same indentation level
    # within what appears to be the same object context
    
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            i += 1
            continue
            
        current_indent = len(line) - len(line.lstrip())
        
        # Look for key: value pairs that are not list items
        if ':' in stripped and not stripped.startswith('- '):
            key_match = re.match(r'^([^:]+):\s*', stripped)
            if key_match:
                key = key_match.group(1).strip()
                
                # Skip complex keys
                if ' ' in key or '[' in key or '{' in key:
                    i += 1
                    continue
                
                # Look ahead for duplicate keys at same indentation level within same object
                j = i + 1
                keys_seen = {key: i + 1}  # key -> line number
                
                while j < len(lines):
                    next_line = lines[j]
                    next_stripped = next_line.strip()
                    
                    # Skip empty lines and comments
                    if not next_stripped or next_stripped.startswith('#'):
                        j += 1
                        continue
                    
                    next_indent = len(next_line) - len(next_line.lstrip())
                    
                    # If indentation is less than current, we've exited this object
                    if next_indent < current_indent:
                        break
                    
                    # If indentation is same and it's a key:value pair (not list item)
                    if next_indent == current_indent and ':' in next_stripped and not next_stripped.startswith('- '):
                        next_key_match = re.match(r'^([^:]+):\s*', next_stripped)
                        if next_key_match:
                            next_key = next_key_match.group(1).strip()
                            
                            # Skip complex keys
                            if ' ' in next_key or '[' in next_key or '{' in next_key:
                                j += 1
                                continue
                            
                            # Check for duplicate
                            if next_key in keys_seen:
                                original_line = keys_seen[next_key]
                                errors.append((
                                    j + 1,
                                    f"Duplicate key '{next_key}' detected. First occurrence at line {original_line}, duplicate at line {j + 1}."
                                ))
                            else:
                                keys_seen[next_key] = j + 1
                    
                    # If we hit a list item at same level, we might be in a new object context
                    elif next_indent == current_indent and next_stripped.startswith('- '):
                        break
                    
                    j += 1
        
        i += 1
    
    return errors


def validate_duplicate_attributes(file_content):
    """
    Check for duplicate attribute names within YAML structures.
    This detects issues like having two 'name:' attributes in the same object,
    which would cause "Duplicate key 'name' detected" errors in Zabbix GUI.
    
    Returns: list of (line_number, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    # Stack to track current indentation context
    # Each element: (indent_level, attributes_seen, start_line)
    context_stack = []
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Skip empty lines and comments
        if not stripped or stripped.startswith('#'):
            continue
        
        # Calculate current indentation level
        current_indent = len(line) - len(line.lstrip())
        
        # Pop contexts with higher or equal indentation (we've left those scopes)
        while context_stack and current_indent <= context_stack[-1][0]:
            context_stack.pop()
        
        # Check if this line defines an attribute (key: value)
        if ':' in stripped and not stripped.startswith('- '):
            # Extract the attribute name
            attr_match = re.match(r'^([^:]+):\s*', stripped)
            if attr_match:
                attr_name = attr_match.group(1).strip()
                
                # Skip if it's a complex key (contains spaces, brackets, etc.) as these are usually values
                if ' ' not in attr_name and '[' not in attr_name and '{' not in attr_name:
                    # Check if we have a current context
                    if context_stack:
                        # Check for duplicate in current context
                        if attr_name in context_stack[-1][1]:
                            original_line = context_stack[-1][1][attr_name]
                            errors.append((
                                line_num,
                                f"Duplicate attribute '{attr_name}' detected. First occurrence at line {original_line}, duplicate at line {line_num}."
                            ))
                        else:
                            # Add to current context
                            context_stack[-1][1][attr_name] = line_num
                    else:
                        # Start new context
                        context_stack.append((current_indent, {attr_name: line_num}, line_num))
        
        # Check for list items that might start a new object context
        elif stripped.startswith('- '):
            # List item - this might contain nested attributes
            # Start a new context for this list item
            context_stack.append((current_indent + 2, {}, line_num))  # +2 for typical list item indentation
        
        # Check if line has only a key (no value), indicating start of nested object
        elif stripped.endswith(':') and not stripped.startswith('- '):
            # This is a nested object key, start new context
            context_stack.append((current_indent + 2, {}, line_num))  # +2 for typical nested indentation
    
    return errors


def validate_trigger_expressions(yaml_data, file_content):
    """
    Validate trigger expressions for invalid or deprecated functions.
    Returns a list of (line_num, error_message) tuples for invalid expressions.
    """
    errors = []
    lines = file_content.splitlines()
    
    # Pattern to match function calls in expressions
    func_pattern = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')
    
    def find_line_for_expression(expr_snippet, start_line=0):
        """Find the line number where an expression appears."""
        for i, line in enumerate(lines[start_line:], start_line + 1):
            if 'expression:' in line and expr_snippet[:30] in line:
                return i
        # Try to find just the expression content
        for i, line in enumerate(lines[start_line:], start_line + 1):
            if expr_snippet[:40] in line:
                return i
        return None
    
    def check_expression(expression, trigger_name, path):
        """Check a single expression for invalid functions."""
        if not expression:
            return
        
        # Find all function calls in the expression
        matches = func_pattern.findall(expression)
        for func_name in matches:
            func_lower = func_name.lower()
            if func_lower in INVALID_TRIGGER_FUNCTIONS:
                suggestion = INVALID_TRIGGER_FUNCTIONS[func_lower]
                line_num = find_line_for_expression(expression)
                errors.append((
                    line_num or 0,
                    f"Invalid/deprecated function '{func_name}()' in trigger '{trigger_name}' at {path}. {suggestion}"
                ))
        
        # Check for common syntax errors
        # Empty parameter in find() - like find(item,,"pattern")
        if ',,' in expression and 'find(' in expression:
            # This might be valid if it's intentional empty time_shift
            # But find(item,,"fail") is definitely wrong
            if re.search(r'find\([^)]+,,\s*"[^"]+"\s*\)', expression):
                line_num = find_line_for_expression(expression)
                errors.append((
                    line_num or 0,
                    f"Invalid find() syntax in trigger '{trigger_name}' at {path}. "
                    f"Syntax: find(item,#num,time_shift,\"operator\",\"pattern\")"
                ))
    
    def check_triggers(triggers, path):
        """Check a list of triggers for invalid expressions."""
        if not isinstance(triggers, list):
            return
        
        for t_idx, trigger in enumerate(triggers):
            if not isinstance(trigger, dict):
                continue
            
            trigger_name = trigger.get('name', f'trigger({t_idx + 1})')
            trigger_path = f"{path}/trigger({t_idx + 1})"
            
            # Check for missing expression
            expression = trigger.get('expression', '')
            if not expression:
                line_num = find_line_for_expression(trigger_name)
                errors.append((
                    line_num or 0,
                    f"Missing required 'expression' tag in trigger '{trigger_name}' at {trigger_path}"
                ))
            else:
                check_expression(expression, trigger_name, trigger_path)
            
            # Also check recovery_expression if present
            recovery_expr = trigger.get('recovery_expression', '')
            if recovery_expr:
                check_expression(recovery_expr, f"{trigger_name} (recovery)", trigger_path)
            
            # Check dependencies for missing expressions
            dependencies = trigger.get('dependencies', [])
            if isinstance(dependencies, list):
                for dep_idx, dep in enumerate(dependencies):
                    if isinstance(dep, dict):
                        dep_name = dep.get('name', f'dependency({dep_idx + 1})')
                        dep_path = f"{trigger_path}/dependencies/dependency({dep_idx + 1})"
                        
                        if 'expression' not in dep:
                            line_num = None
                            # Try to find the line with the dependency name
                            for i, line in enumerate(lines, 1):
                                if f"name: '{dep_name}'" in line or f'name: "{dep_name}"' in line or f"name: {dep_name}" in line:
                                    line_num = i
                                    break
                            errors.append((
                                line_num or 0,
                                f"Missing required 'expression' tag in dependency '{dep_name}' at {dep_path}. "
                                f"Zabbix 7.0 requires both 'name' and 'expression' for trigger dependencies."
                            ))
    
    export_data = yaml_data.get('zabbix_export', {})
    
    # Check standalone triggers
    triggers = export_data.get('triggers', [])
    check_triggers(triggers, '/zabbix_export/triggers')
    
    # Check template triggers and trigger_prototypes
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            template_path = f"/zabbix_export/templates/{template_name}"
            
            # Check template-level triggers
            check_triggers(template.get('triggers', []), f"{template_path}/triggers")
            
            # Check item-level triggers
            items = template.get('items', [])
            if isinstance(items, list):
                for item_idx, item in enumerate(items):
                    if isinstance(item, dict) and 'triggers' in item:
                        item_name = item.get('name', f'item({item_idx + 1})')
                        item_path = f"{template_path}/items/item({item_idx + 1})"
                        check_triggers(item.get('triggers', []), f"{item_path}/triggers")
            
            # Check discovery rule trigger_prototypes
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, rule in enumerate(discovery_rules):
                    if isinstance(rule, dict):
                        rule_name = rule.get('name', f'discovery_rule({dr_idx + 1})')
                        rule_path = f"{template_path}/discovery_rules/{rule_name}"
                        
                        trigger_prototypes = rule.get('trigger_prototypes', [])
                        check_triggers(trigger_prototypes, f"{rule_path}/trigger_prototypes")
                        
                        # Check item_prototype triggers as well
                        item_prototypes = rule.get('item_prototypes', [])
                        if isinstance(item_prototypes, list):
                            for ip_idx, ip in enumerate(item_prototypes):
                                if isinstance(ip, dict):
                                    ip_name = ip.get('name', f'item_prototype({ip_idx + 1})')
                                    ip_path = f"{rule_path}/item_prototypes/item_prototype({ip_idx + 1})"
                                    # Check both 'triggers' and 'trigger_prototypes'
                                    if 'triggers' in ip:
                                        check_triggers(ip.get('triggers', []), f"{ip_path}/triggers")
                                    if 'trigger_prototypes' in ip:
                                        check_triggers(ip.get('trigger_prototypes', []), f"{ip_path}/trigger_prototypes")
    
    return errors


def validate_trigger_dependency_exists(yaml_data, file_content):
    """
    Validate that trigger dependencies reference triggers that actually exist.
    Dependencies must reference triggers in the same scope (same template for regular triggers,
    same discovery rule for trigger_prototypes).
    Returns a list of (line_num, error_message) tuples for missing dependencies.
    """
    errors = []
    lines = file_content.split('\n')
    
    def find_line_number(search_text):
        """Find line number containing the search text."""
        for i, line in enumerate(lines, 1):
            if search_text in line:
                return i
        return 0
    
    def collect_trigger_names(triggers_list):
        """Collect all trigger names from a list of triggers."""
        names = set()
        if isinstance(triggers_list, list):
            for trigger in triggers_list:
                if isinstance(trigger, dict):
                    name = trigger.get('name')
                    if name:
                        names.add(name)
        return names
    
    def check_dependencies(triggers_list, available_trigger_names, scope_path, scope_description):
        """Check that all dependencies reference existing triggers."""
        if not isinstance(triggers_list, list):
            return
        
        for t_idx, trigger in enumerate(triggers_list):
            if not isinstance(trigger, dict):
                continue
            
            trigger_name = trigger.get('name', f'trigger({t_idx + 1})')
            dependencies = trigger.get('dependencies', [])
            
            if isinstance(dependencies, list):
                for dep_idx, dep in enumerate(dependencies):
                    if isinstance(dep, dict):
                        dep_name = dep.get('name')
                        if dep_name and dep_name not in available_trigger_names:
                            # Find line number for the dependency
                            line_num = find_line_number(f"- name: '{dep_name}'") or \
                                       find_line_number(f'- name: "{dep_name}"') or \
                                       find_line_number(f"name: '{dep_name}'") or \
                                       find_line_number(f'name: "{dep_name}"') or 0
                            errors.append((
                                line_num,
                                f"Trigger '{trigger_name}' at {scope_path} depends on trigger '{dep_name}', "
                                f"which does not exist in {scope_description}. "
                                f"Add the missing trigger or remove the dependency."
                            ))
    
    # Process templates
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            template_path = f"/zabbix_export/templates/{template_name}"
            
            # Collect all regular triggers at template level
            template_triggers = template.get('triggers', [])
            template_trigger_names = collect_trigger_names(template_triggers)
            
            # Check dependencies in regular triggers
            check_dependencies(
                template_triggers, 
                template_trigger_names, 
                f"{template_path}/triggers",
                f"template '{template_name}'"
            )
            
            # Process discovery rules
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if not isinstance(dr, dict):
                        continue
                    
                    dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                    dr_path = f"{template_path}/discovery_rules/{dr_name}"
                    
                    # Collect trigger_prototypes at DISCOVERY RULE level ONLY
                    dr_trigger_prototypes = dr.get('trigger_prototypes', [])
                    dr_level_trigger_names = collect_trigger_names(dr_trigger_prototypes)
                    
                    # Collect trigger_prototypes from item_prototypes (IP-level)
                    item_prototypes = dr.get('item_prototypes', [])
                    ip_level_trigger_names = set()
                    if isinstance(item_prototypes, list):
                        for ip in item_prototypes:
                            if isinstance(ip, dict):
                                ip_trigger_prototypes = ip.get('trigger_prototypes', [])
                                ip_level_trigger_names.update(collect_trigger_names(ip_trigger_prototypes))
                    
                    # ALL trigger names in the discovery rule (for IP-level triggers to reference)
                    all_dr_trigger_names = dr_level_trigger_names | ip_level_trigger_names
                    
                    # Check dependencies in discovery rule trigger_prototypes
                    # DR-level triggers can ONLY depend on other DR-level triggers (not IP-level)
                    check_dependencies(
                        dr_trigger_prototypes,
                        dr_level_trigger_names,  # Only DR-level triggers are valid dependencies
                        f"{dr_path}/trigger_prototypes",
                        f"discovery rule '{dr_name}' (trigger_prototypes at discovery rule level)"
                    )
                    
                    # Check dependencies in item_prototype trigger_prototypes
                    # IP-level triggers can depend on any trigger in the discovery rule
                    if isinstance(item_prototypes, list):
                        for ip_idx, ip in enumerate(item_prototypes):
                            if isinstance(ip, dict):
                                ip_name = ip.get('name', f'item_prototype({ip_idx + 1})')
                                ip_path = f"{dr_path}/item_prototypes/{ip_name}"
                                ip_trigger_prototypes = ip.get('trigger_prototypes', [])
                                
                                check_dependencies(
                                    ip_trigger_prototypes,
                                    all_dr_trigger_names,  # IP-level can depend on both DR and IP level
                                    f"{ip_path}/trigger_prototypes",
                                    f"discovery rule '{dr_name}'"
                                )
    
    return errors


def validate_required_uuids(yaml_data, file_content):
    """
    Validate that required elements have UUID tags.
    In Zabbix 7.0, certain elements require UUIDs: templates, items, triggers, 
    discovery_rules, valuemaps, template_groups, dashboards, graphs, etc.
    Returns a list of (line_num, error_message) tuples for missing UUIDs.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_name(name_value, context_key=None):
        """Find the line number where a name appears."""
        for i, line in enumerate(lines, 1):
            if f"name: '{name_value}'" in line or f'name: "{name_value}"' in line or f"name: {name_value}" in line:
                return i
        return None
    
    def check_list_for_uuids(items, path, item_type):
        """Check a list of items for missing UUIDs."""
        if not isinstance(items, list):
            return
        
        for idx, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            
            item_name = item.get('name', item.get('template', f'{item_type}({idx + 1})'))
            item_path = f"{path}/{item_type}({idx + 1})"
            
            if 'uuid' not in item:
                line_num = find_line_for_name(item_name)
                errors.append((
                    line_num or 0,
                    f"Missing required 'uuid' tag in {item_type} '{item_name}' at {item_path}"
                ))
    
    export_data = yaml_data.get('zabbix_export', {})
    
    # Check template_groups
    template_groups = export_data.get('template_groups', [])
    check_list_for_uuids(template_groups, '/zabbix_export/template_groups', 'template_group')
    
    # Check templates
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            template_path = f"/zabbix_export/templates/template({t_idx + 1})"
            
            # Check template itself has uuid
            if 'uuid' not in template:
                line_num = find_line_for_name(template_name)
                errors.append((
                    line_num or 0,
                    f"Missing required 'uuid' tag in template '{template_name}' at {template_path}"
                ))
            
            # Check items
            check_list_for_uuids(template.get('items', []), f"{template_path}/items", 'item')
            
            # Check discovery_rules
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, rule in enumerate(discovery_rules):
                    if isinstance(rule, dict):
                        rule_name = rule.get('name', f'discovery_rule({dr_idx + 1})')
                        rule_path = f"{template_path}/discovery_rules/discovery_rule({dr_idx + 1})"
                        
                        if 'uuid' not in rule:
                            line_num = find_line_for_name(rule_name)
                            errors.append((
                                line_num or 0,
                                f"Missing required 'uuid' tag in discovery_rule '{rule_name}' at {rule_path}"
                            ))
                        
                        # Check item_prototypes
                        check_list_for_uuids(rule.get('item_prototypes', []), f"{rule_path}/item_prototypes", 'item_prototype')
                        
                        # Check trigger_prototypes
                        check_list_for_uuids(rule.get('trigger_prototypes', []), f"{rule_path}/trigger_prototypes", 'trigger_prototype')
                        
                        # Check graph_prototypes
                        check_list_for_uuids(rule.get('graph_prototypes', []), f"{rule_path}/graph_prototypes", 'graph_prototype')
            
            # Check valuemaps
            check_list_for_uuids(template.get('valuemaps', []), f"{template_path}/valuemaps", 'valuemap')
            
            # Check dashboards
            dashboards = template.get('dashboards', [])
            if isinstance(dashboards, list):
                for d_idx, dashboard in enumerate(dashboards):
                    if isinstance(dashboard, dict):
                        dashboard_name = dashboard.get('name', f'dashboard({d_idx + 1})')
                        dashboard_path = f"{template_path}/dashboards/dashboard({d_idx + 1})"
                        
                        if 'uuid' not in dashboard:
                            line_num = find_line_for_name(dashboard_name)
                            errors.append((
                                line_num or 0,
                                f"Missing required 'uuid' tag in dashboard '{dashboard_name}' at {dashboard_path}"
                            ))
    
    # Check standalone triggers
    triggers = export_data.get('triggers', [])
    check_list_for_uuids(triggers, '/zabbix_export/triggers', 'trigger')
    
    return errors


def find_duplicate_uuids(yaml_data, file_content):
    """
    Find all UUIDs in the YAML data and check for duplicates.
    Returns a list of (line_num, error_message) tuples for any duplicates found.
    """
    errors = []
    lines = file_content.splitlines()
    uuid_locations = {}  # uuid -> list of (path, line_num)
    
    def find_line_for_uuid(uuid_value):
        """Find the line number where a specific UUID appears."""
        for i, line in enumerate(lines, 1):
            if uuid_value in line and 'uuid:' in line:
                return i
        return None
    
    def collect_uuids(obj, path="", in_application_prototypes=False):
        """Recursively collect all UUIDs from the YAML structure.
        
        Note: application_prototypes can legitimately share UUIDs when multiple
        items should be grouped into the same application, so we skip those.
        """
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                # Skip application_prototypes - they legitimately share UUIDs
                if key == 'application_prototypes':
                    continue
                if key == 'uuid' and isinstance(value, str):
                    if value not in uuid_locations:
                        uuid_locations[value] = []
                    line_num = find_line_for_uuid(value)
                    uuid_locations[value].append((current_path, line_num))
                else:
                    collect_uuids(value, current_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                collect_uuids(item, f"{path}[{i}]")
    
    # Collect all UUIDs
    collect_uuids(yaml_data)
    
    # Check for duplicates
    for uuid_value, locations in uuid_locations.items():
        if len(locations) > 1:
            # Format the locations for error message
            location_strs = []
            for path, line_num in locations:
                if line_num:
                    location_strs.append(f"{path} (line {line_num})")
                else:
                    location_strs.append(path)
            
            # Use the first line number for the error
            first_line = locations[0][1] or 0
            errors.append((first_line, 
                f"Duplicate UUID '{uuid_value}' found at: {'; '.join(location_strs)}. "
                f"Each UUID must be unique within the template."))
    
    return errors


def find_duplicate_item_keys(yaml_data, file_content):
    """
    Find all item keys in the YAML data and check for duplicates within the same scope.
    Returns a list of (line_num, error_message) tuples for any duplicates found.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_key(key_value):
        """Find the line number where a specific key appears."""
        for i, line in enumerate(lines, 1):
            # Match 'key: value' pattern
            if f"key: {key_value}" in line or f"key: '{key_value}'" in line:
                return i
        return None
    
    def collect_item_keys(items, path, key_locations):
        """Collect all item keys from an items list."""
        if not isinstance(items, list):
            return
        for i, item in enumerate(items):
            if isinstance(item, dict) and 'key' in item:
                key_value = item['key']
                if key_value not in key_locations:
                    key_locations[key_value] = []
                line_num = find_line_for_key(key_value)
                key_locations[key_value].append((f"{path}[{i}]", line_num))
    
    def process_template(template, template_path):
        """Process a template and check for duplicate keys in items and item_prototypes."""
        key_locations = {}
        
        # Check regular items
        if 'items' in template:
            collect_item_keys(template['items'], f"{template_path}.items", key_locations)
        
        # Check discovery rules and their item_prototypes
        if 'discovery_rules' in template:
            rules = template['discovery_rules']
            if isinstance(rules, list):
                for r_idx, rule in enumerate(rules):
                    if isinstance(rule, dict) and 'item_prototypes' in rule:
                        collect_item_keys(rule['item_prototypes'], 
                            f"{template_path}.discovery_rules[{r_idx}].item_prototypes", 
                            key_locations)
        
        # Report duplicates
        for key_value, locations in key_locations.items():
            if len(locations) > 1:
                location_strs = []
                for path, line_num in locations:
                    if line_num:
                        location_strs.append(f"{path} (line {line_num})")
                    else:
                        location_strs.append(path)
                
                first_line = locations[0][1] or 0
                errors.append((first_line,
                    f"Duplicate item key '{key_value}' found at: {'; '.join(location_strs)}. "
                    f"Each item key must be unique within a template."))
    
    # Process each template
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if isinstance(template, dict):
                process_template(template, f"templates[{t_idx}]")
    
    return errors


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

    # Check for fields that require string values but have bare integers
    string_field_errors = validate_string_required_fields(file_content)
    for line_num, msg in string_field_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid enum values (drawtype, yaxisside, calc_fnc, etc.)
    enum_errors = validate_enum_fields(file_content)
    for line_num, msg in enum_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for unexpected tags in specific contexts (e.g., uuid in dashboard pages)
    unexpected_tag_errors = validate_unexpected_tags(file_content)
    for line_num, msg in unexpected_tag_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for common misspellings of Zabbix tags (e.g., value_maps instead of valuemaps)
    spelling_errors = validate_tag_spelling(file_content)
    for line_num, msg in spelling_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid LLD filter condition operators
    lld_operator_errors = validate_lld_filter_operators(yaml_data, file_content)
    for line_num, msg in lld_operator_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid 'filter' tag inside dashboard widgets
    dashboard_filter_errors = validate_dashboard_widget_filter(yaml_data, file_content)
    for line_num, msg in dashboard_filter_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid 'filter' tag inside item_prototypes
    item_prototype_filter_errors = validate_item_prototype_filter(yaml_data, file_content)
    for line_num, msg in item_prototype_filter_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for non-numeric items in graph prototypes
    graph_item_type_errors = validate_graph_item_types(yaml_data, file_content)
    for line_num, msg in graph_item_type_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid export tags like 'date'
    invalid_export_tag_errors = validate_invalid_export_tags(yaml_data, file_content)
    for line_num, msg in invalid_export_tag_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for LLD macros in item prototypes
    lld_macro_errors = validate_lld_macro_in_prototypes(yaml_data, file_content)
    for line_num, msg in lld_macro_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for numeric constants that should be string constants in Zabbix 7.0
    numeric_constant_errors = validate_numeric_constants(yaml_data, file_content)
    for line_num, msg in numeric_constant_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for invalid/deprecated trigger expression functions
    expression_errors = validate_trigger_expressions(yaml_data, file_content)
    for line_num, msg in expression_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for missing required UUIDs (valuemaps, items, triggers, etc.)
    missing_uuid_errors = validate_required_uuids(yaml_data, file_content)
    for line_num, msg in missing_uuid_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check that trigger dependencies reference existing triggers
    dependency_errors = validate_trigger_dependency_exists(yaml_data, file_content)
    for line_num, msg in dependency_errors:
        errors.append(f"Line {line_num}: {msg}")

    # === ENHANCED VALIDATION CHECKS ===
    
    # Check for deprecated external script formats (JSON-style with quotes)
    external_script_errors = validate_external_script_format(yaml_data, file_content)
    for msg in external_script_errors:
        errors.append(msg)

    # Enhanced trigger expression validation (includes deprecated format detection)
    enhanced_trigger_errors = validate_trigger_references(yaml_data, file_content)
    for msg in enhanced_trigger_errors:
        errors.append(msg)

    # Check for duplicate UUIDs
    duplicate_uuid_errors = find_duplicate_uuids(yaml_data, file_content)
    for line_num, msg in duplicate_uuid_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for duplicate item keys
    duplicate_key_errors = find_duplicate_item_keys(yaml_data, file_content)
    for line_num, msg in duplicate_key_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check for duplicate attribute names within same YAML objects
    duplicate_attribute_errors = validate_duplicate_keys_in_same_object(file_content)
    for line_num, msg in duplicate_attribute_errors:
        errors.append(f"Line {line_num}: {msg}")

    # Check required top-level structure
    if 'zabbix_export' not in yaml_data:
        # Only error if the file looks like YAML (not Python or other source)
        if not file_content.lstrip().startswith('import') and not file_content.lstrip().startswith('#!'):
            errors.append("Missing required top-level 'zabbix_export' key")
        return errors, warnings, None
    
    export_data = yaml_data['zabbix_export']
    
    # Check version - initialize first to avoid NameError later
    version = None
    if 'version' not in export_data:
        errors.append("Missing required 'version' field in zabbix_export")
    else:
        version = str(export_data['version'])
        if version not in SUPPORTED_VERSIONS:
            expected = ", ".join([f"'{v}' ({desc})" for v, desc in SUPPORTED_VERSIONS.items()])
            errors.append(f"Unsupported version: '{version}'. Expected one of: {expected}")
    
    # Check for sections INSIDE templates that should be at zabbix_export level
    # In Zabbix 7.0, 'graphs' must be at zabbix_export level, NOT inside templates
    # Error: "Invalid tag '/zabbix_export/templates/template(1)': unexpected tag 'graphs'"
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if isinstance(template, dict):
                template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
                # Check if graphs is incorrectly placed inside a template
                if 'graphs' in template:
                    # Find the line number
                    line_num = None
                    for i, line in enumerate(lines, 1):
                        # Match 'graphs:' at 6 spaces (inside template)
                        if re.match(r'^      graphs:\s*$', line):
                            line_num = i
                            break
                    if line_num:
                        line_prefix = f"Line {line_num}: "
                        errors.append(f"{line_prefix}Misplaced 'graphs' section inside template '{template_name}'. "
                                     f"In Zabbix 7.0, 'graphs' must be at the zabbix_export level (2 spaces indentation), "
                                     f"not inside templates (6 spaces). Move it outside the template block.")

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

        # Check for required 'name' field
        if 'name' not in item:
            line = find_line_number(lines, item) or template_line
            errors.append(f"Line ~{line}: {item_prefix}: the tag 'name' is missing.")
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
            
        # Comprehensive Zabbix schema validation with all checks
        schema_errors, schema_warnings, version = validate_comprehensive_zabbix_schema(yaml_data, file_content)
        
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

def validate_required_fields(yaml_data, file_content):
    """
    Validate that required fields are present in the template structure.
    Returns a list of (line_num, error_message) tuples for missing required fields.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_value(search_value):
        """Find line number for a value."""
        for i, line in enumerate(lines, 1):
            if search_value in line:
                return i
        return 0
    
    export_data = yaml_data.get('zabbix_export', {})
    
    # Check required zabbix_export fields
    required_export_fields = ['version', 'templates']
    for field in required_export_fields:
        if field not in export_data:
            errors.append((
                0,
                f"Missing required field '{field}' in zabbix_export section"
            ))
    
    # Check templates
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', f'template({t_idx + 1})')
            
            # Required template fields
            required_template_fields = ['template', 'name']
            for field in required_template_fields:
                if field not in template:
                    line_num = find_line_for_value(template_name)
                    errors.append((
                        line_num,
                        f"Missing required field '{field}' in template '{template_name}'"
                    ))
            
            # Check vendor fields (required for proper template organization)
            vendor = template.get('vendor', {})
            if not isinstance(vendor, dict) or not vendor.get('name'):
                line_num = find_line_for_value(template_name)
                errors.append((
                    line_num,
                    f"Missing required vendor information in template '{template_name}'. "
                    f"Add: vendor: {{name: 'Vendor Name', version: 'Version'}}"
                ))
    
    return errors


def validate_snmp_configuration(yaml_data, file_content):
    """
    Validate SNMP configuration for items and discovery rules.
    Returns a list of (line_num, error_message) tuples for SNMP configuration issues.
    """
    errors = []
    lines = file_content.splitlines()
    
    # SNMP item types that require specific configuration
    SNMP_TYPES = {'SNMPV1', 'SNMPV2', 'SNMPV3', '1', '4', '6'}
    
    def find_line_for_item(item_name):
        """Find line number for an item by name."""
        for i, line in enumerate(lines, 1):
            if f"name: {item_name}" in line or f"name: '{item_name}'" in line:
                return i
        return 0
    
    def check_snmp_item(item, path, item_name):
        """Check SNMP configuration for a single item."""
        item_type = str(item.get('type', '')).upper()
        
        if item_type in SNMP_TYPES:
            # SNMP items must have snmp_oid
            if 'snmp_oid' not in item:
                line_num = find_line_for_item(item_name)
                errors.append((
                    line_num,
                    f"SNMP item '{item_name}' at {path} is missing required 'snmp_oid' field"
                ))
            
            # Validate SNMP OID format
            snmp_oid = item.get('snmp_oid', '')
            if snmp_oid:
                is_valid, error_msg = validate_snmp_oid(snmp_oid)
                if not is_valid:
                    line_num = find_line_for_item(item_name)
                    errors.append((
                        line_num,
                        f"Invalid SNMP OID in item '{item_name}' at {path}: {error_msg}"
                    ))
    
    # Check templates
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', f'template({t_idx + 1})')
            
            # Check regular items
            items = template.get('items', [])
            if isinstance(items, list):
                for i_idx, item in enumerate(items):
                    if isinstance(item, dict):
                        item_name = item.get('name', f'item({i_idx + 1})')
                        check_snmp_item(item, f"templates/{template_name}/items/item({i_idx + 1})", item_name)
            
            # Check discovery rules and their item prototypes
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if isinstance(dr, dict):
                        dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                        
                        # Check discovery rule itself
                        check_snmp_item(dr, f"templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})", dr_name)
                        
                        # Check item prototypes
                        item_prototypes = dr.get('item_prototypes', [])
                        if isinstance(item_prototypes, list):
                            for ip_idx, ip in enumerate(item_prototypes):
                                if isinstance(ip, dict):
                                    ip_name = ip.get('name', f'item_prototype({ip_idx + 1})')
                                    check_snmp_item(ip, f"templates/{template_name}/discovery_rules/discovery_rule({dr_idx + 1})/item_prototypes/item_prototype({ip_idx + 1})", ip_name)
    
    return errors


def validate_key_format(yaml_data, file_content):
    """
    Enhanced validation for Zabbix item key formats.
    Returns a list of (line_num, error_message) tuples for invalid key formats.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_key(key_value):
        """Find line number for a specific key."""
        for i, line in enumerate(lines, 1):
            if f"key: {key_value}" in line or f"key: '{key_value}'" in line:
                return i
        return 0
    
    def validate_item_key_enhanced(key, item_name, path):
        """Enhanced item key validation with specific error messages."""
        is_valid, error_msg = validate_item_key(key)
        if not is_valid:
            line_num = find_line_for_key(key)
            errors.append((
                line_num,
                f"Invalid item key '{key}' in '{item_name}' at {path}: {error_msg}"
            ))
        
        # Additional validations
        # Check for common mistakes
        if key.startswith('.'):
            line_num = find_line_for_key(key)
            errors.append((
                line_num,
                f"Item key '{key}' in '{item_name}' at {path} starts with '.' - keys cannot start with a dot"
            ))
        
        if '..' in key:
            line_num = find_line_for_key(key)
            errors.append((
                line_num,
                f"Item key '{key}' in '{item_name}' at {path} contains consecutive dots '..' - invalid syntax"
            ))
        
        # Check for spaces (only flag if outside of bracket parameters)
        if ' ' in key:
            # Allow spaces within bracket parameters for custom scripts
            # Pattern: key_name[parameters with spaces allowed]
            bracket_match = re.match(r'^([^[]+)(\[.*\])$', key)
            if bracket_match:
                key_name, params = bracket_match.groups()
                # Only check the key name part before brackets for spaces
                if ' ' in key_name:
                    line_num = find_line_for_key(key)
                    errors.append((
                        line_num,
                        f"Item key '{key}' in '{item_name}' at {path} has spaces in key name part (before brackets) - only parameters within brackets can contain spaces"
                    ))
            else:
                # No brackets, so spaces are not allowed at all
                if not (key.count('"') >= 2 or key.count("'") >= 2):
                    line_num = find_line_for_key(key)
                    errors.append((
                        line_num,
                        f"Item key '{key}' in '{item_name}' at {path} contains unquoted spaces - parameters with spaces must be quoted or use bracket notation"
                    ))
    
    def check_items_keys(items, path_prefix):
        """Check keys in a list of items."""
        if not isinstance(items, list):
            return
        
        for i_idx, item in enumerate(items):
            if isinstance(item, dict) and 'key' in item:
                item_name = item.get('name', f'item({i_idx + 1})')
                key = item['key']
                validate_item_key_enhanced(key, item_name, f"{path_prefix}/item({i_idx + 1})")
    
    # Check templates
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', f'template({t_idx + 1})')
            template_path = f"templates/{template_name}"
            
            # Check regular items
            check_items_keys(template.get('items', []), f"{template_path}/items")
            
            # Check discovery rules and their item prototypes
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if isinstance(dr, dict):
                        dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                        dr_path = f"{template_path}/discovery_rules/discovery_rule({dr_idx + 1})"
                        
                        # Check discovery rule key
                        if 'key' in dr:
                            validate_item_key_enhanced(dr['key'], dr_name, dr_path)
                        
                        # Check item prototypes
                        check_items_keys(dr.get('item_prototypes', []), f"{dr_path}/item_prototypes")
    
    return errors


def validate_duplicate_macros(yaml_data, file_content):
    """
    Validate that there are no duplicate macro definitions within templates.
    Returns a list of (line_num, error_message) tuples for duplicate macros.
    """
    errors = []
    lines = file_content.splitlines()
    
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', template.get('name', f'template({t_idx + 1})'))
            macros = template.get('macros', [])
            
            if isinstance(macros, list):
                macro_names = {}
                for m_idx, macro in enumerate(macros):
                    if isinstance(macro, dict) and 'macro' in macro:
                        macro_name = macro['macro']
                        if macro_name in macro_names:
                            # Find line numbers for both occurrences
                            first_line = find_line_number(lines, macro_names[macro_name]) or 0
                            second_line = find_line_number(lines, macro) or 0
                            errors.append((second_line, 
                                f"Duplicate macro '{macro_name}' found in template '{template_name}'. "
                                f"First occurrence at line ~{first_line}, duplicate at line ~{second_line}. "
                                f"Each macro must be unique within a template."))
                        else:
                            macro_names[macro_name] = macro
    
    return errors


def validate_widget_field_types(yaml_data, file_content):
    """
    Validate all dashboard widget field types against Zabbix schema.
    Returns list of (line_num, error_message) tuples for invalid widget field types.
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_widget_field(widget_name, field_name, field_type):
        """Find line number for a specific widget field type."""
        in_widget = False
        widget_found = False
        field_found = False
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Look for widget by name
            if f"name: '{widget_name}'" in line or f'name: "{widget_name}"' in line or f"name: {widget_name}" in line:
                widget_found = True
                in_widget = True
                continue
            
            # If we're in the right widget and find the field
            if in_widget and widget_found:
                # Check for field name match
                if f"name: {field_name}" in line or f"name: '{field_name}'" in line or f'name: "{field_name}"' in line:
                    field_found = True
                    continue
                
                # If we found the field and now see the type, return this line
                if field_found and f"type: {field_type}" in line:
                    return i
                
                # Reset if we hit another widget
                if line_stripped.startswith('- type:') and 'widget' not in line.lower():
                    in_widget = False
                    widget_found = False
                    field_found = False
        
        # Fallback: search for type occurrence
        for i, line in enumerate(lines, 1):
            if f"type: {field_type}" in line:
                return i
        
        return 0
    
    def suggest_widget_field_fix(widget_type, invalid_type, field_name):
        """Suggest fixes for common widget field type errors."""
        if invalid_type == 'PROTOTYPE_NAME':
            return "Remove PROTOTYPE_NAME field - not valid for any widget type"
        elif invalid_type == 'TAG_FILTER':
            return "Replace with STRING fields: 'tags.tag.0' and 'tags.value.0'"
        elif invalid_type == 'ITEM_TAG':
            return "Replace with STRING fields: 'tags.tag.0' and 'tags.value.0'"
        elif invalid_type == 'SHOW_TAGS':
            return "Remove SHOW_TAGS field - not a valid field type"
        elif 'tag' in field_name.lower() and widget_type in ['PROBLEMS', 'PROBLEMS_BY_SEVERITY']:
            return "Use STRING type with name 'tags.tag.0' or 'tags.value.0'"
        elif widget_type in ['GRAPH_PROTOTYPE'] and invalid_type not in ['STRING', 'BOOLEAN']:
            return f"Replace {invalid_type} with STRING or BOOLEAN for GRAPH_PROTOTYPE widgets"
        else:
            return f"Replace {invalid_type} with valid field type for {widget_type} widget"
    
    # Navigate to templates -> dashboards
    templates = yaml_data.get('zabbix_export', {}).get('templates', [])
    
    for template_idx, template in enumerate(templates):
        if not isinstance(template, dict):
            continue
            
        dashboards = template.get('dashboards', [])
        
        for dash_idx, dashboard in enumerate(dashboards):
            if not isinstance(dashboard, dict):
                continue
                
            pages = dashboard.get('pages', [])
            
            for page_idx, page in enumerate(pages):
                if not isinstance(page, dict):
                    continue
                    
                widgets = page.get('widgets', [])
                
                for widget_idx, widget in enumerate(widgets):
                    if not isinstance(widget, dict):
                        continue
                        
                    widget_type = widget.get('type', 'UNKNOWN')
                    widget_name = widget.get('name', f'widget({widget_idx + 1})')
                    fields = widget.get('fields', [])
                    
                    for field_idx, field in enumerate(fields):
                        if not isinstance(field, dict):
                            continue
                            
                        field_type = field.get('type', '')
                        field_name = field.get('name', f'field({field_idx + 1})')
                        
                        # Check if field type is valid
                        if field_type not in VALID_WIDGET_FIELD_TYPES:
                            xpath = f"/zabbix_export/templates/template({template_idx + 1})/dashboards/dashboard({dash_idx + 1})/pages/page({page_idx + 1})/widgets/widget({widget_idx + 1})/fields/field({field_idx + 1})/type"
                            line_num = find_line_for_widget_field(widget_name, field_name, field_type)
                            suggestion = suggest_widget_field_fix(widget_type, field_type, field_name)
                            
                            errors.append((
                                line_num,
                                f"Invalid widget field type '{field_type}' in {widget_type} widget '{widget_name}' field '{field_name}' at {xpath}. {suggestion}"
                            ))
                        
                        # Check widget-specific field compatibility
                        elif widget_type in WIDGET_FIELD_COMPATIBILITY:
                            valid_types = WIDGET_FIELD_COMPATIBILITY[widget_type]
                            if field_type not in valid_types:
                                xpath = f"/zabbix_export/templates/template({template_idx + 1})/dashboards/dashboard({dash_idx + 1})/pages/page({page_idx + 1})/widgets/widget({widget_idx + 1})/fields/field({field_idx + 1})/type"
                                line_num = find_line_for_widget_field(widget_name, field_name, field_type)
                                
                                errors.append((
                                    line_num,
                                    f"Incompatible widget field type '{field_type}' in {widget_type} widget '{widget_name}' field '{field_name}' at {xpath}. Valid types: {', '.join(sorted(valid_types))}"
                                ))
    
    return errors


def validate_trigger_indentation(yaml_data, file_content):
    """
    Validate proper indentation for trigger sections in items and discovery rules.
    Returns a list of (line_num, error_message) tuples for indentation errors.
    """
    errors = []
    lines = file_content.splitlines()
    
    def get_indentation(line):
        """Get the indentation level (number of spaces) for a line."""
        return len(line) - len(line.lstrip(' '))
    
    def find_triggers_section_indent(start_line, context):
        """Find proper indentation for triggers section based on context."""
        # Look backward to find the parent item indentation
        for i in range(start_line - 1, -1, -1):
            line = lines[i].strip()
            if line.startswith('- uuid:') or line.startswith('uuid:'):
                parent_indent = get_indentation(lines[i])
                # triggers: should be indented same as other item fields (uuid, name, type, etc.)
                return parent_indent + 2  # Standard YAML 2-space indentation
        return None
    
    # Check items section
    in_items_section = False
    in_triggers_section = False
    expected_trigger_indent = None
    current_item_indent = None
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        current_indent = get_indentation(line)
        
        # Track section changes
        if stripped == 'items:':
            in_items_section = True
            continue
        elif stripped in ['discovery_rules:', 'tags:', 'macros:', 'dashboards:', 'valuemaps:']:
            in_items_section = False
            in_triggers_section = False
            continue
        
        if not in_items_section:
            continue
            
        # Detect item boundaries
        if stripped.startswith('- uuid:'):
            current_item_indent = current_indent
            in_triggers_section = False
            
        # Detect triggers section
        if stripped == 'triggers:':
            in_triggers_section = True
            expected_trigger_indent = find_triggers_section_indent(line_num, 'items')
            
            if expected_trigger_indent is not None and current_indent != expected_trigger_indent:
                errors.append((
                    line_num,
                    f"Incorrect indentation for 'triggers:' section. "
                    f"Expected {expected_trigger_indent} spaces, found {current_indent} spaces. "
                    f"Triggers should align with other item fields (uuid, name, type, etc.)"
                ))
                
        # Check trigger list items
        elif in_triggers_section and stripped.startswith('- uuid:'):
            if expected_trigger_indent is not None:
                expected_trigger_item_indent = expected_trigger_indent + 2
                if current_indent != expected_trigger_item_indent:
                    errors.append((
                        line_num,
                        f"Incorrect indentation for trigger item. "
                        f"Expected {expected_trigger_item_indent} spaces, found {current_indent} spaces. "
                        f"Trigger list items should be indented 2 spaces from 'triggers:'"
                    ))
    
    # Check discovery_rules section for trigger_prototypes
    in_discovery_section = False
    in_trigger_prototypes_section = False
    
    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        current_indent = get_indentation(line)
        
        # Track section changes
        if stripped == 'discovery_rules:':
            in_discovery_section = True
            continue
        elif stripped in ['tags:', 'macros:', 'dashboards:', 'valuemaps:']:
            in_discovery_section = False
            in_trigger_prototypes_section = False
            continue
            
        if not in_discovery_section:
            continue
            
        # Detect discovery rule boundaries
        if stripped.startswith('- uuid:'):
            in_trigger_prototypes_section = False
            
        # Detect trigger_prototypes section
        if stripped == 'trigger_prototypes:':
            in_trigger_prototypes_section = True
            expected_proto_indent = find_triggers_section_indent(line_num, 'discovery_rules')
            
            if expected_proto_indent is not None and current_indent != expected_proto_indent:
                errors.append((
                    line_num,
                    f"Incorrect indentation for 'trigger_prototypes:' section. "
                    f"Expected {expected_proto_indent} spaces, found {current_indent} spaces. "
                    f"Trigger prototypes should align with other discovery rule fields"
                ))
                
        # Check trigger prototype list items
        elif in_trigger_prototypes_section and stripped.startswith('- uuid:'):
            if expected_proto_indent is not None:
                expected_proto_item_indent = expected_proto_indent + 2
                if current_indent != expected_proto_item_indent:
                    errors.append((
                        line_num,
                        f"Incorrect indentation for trigger prototype item. "
                        f"Expected {expected_proto_item_indent} spaces, found {current_indent} spaces. "
                        f"Trigger prototype list items should be indented 2 spaces from 'trigger_prototypes:'"
                    ))
    
    return errors


def validate_master_item_references(yaml_data, file_content):
    """
    Validate that DEPENDENT items reference master items that:
    1. Exist in the correct scope
    2. Are defined BEFORE the dependent item
    3. Are not themselves DEPENDENT (no chains allowed)
    
    Returns: list of (line_num, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_for_item(item_name, item_key):
        """Find line number for an item by name or key."""
        for i, line in enumerate(lines, 1):
            if item_name and (f"name: '{item_name}'" in line or f"name: \"{item_name}\"" in line or f"name: {item_name}" in line):
                return i
            if item_key and (f"key: '{item_key}'" in line or f"key: \"{item_key}\"" in line):
                return i
        return 0
    
    def find_line_for_master_item_key(master_key):
        """Find line number for a master_item key reference."""
        for i, line in enumerate(lines, 1):
            if f"key: '{master_key}'" in line or f"key: \"{master_key}\"" in line:
                # Check if this is in a master_item context
                if i > 1 and ('master_item:' in lines[i-2] or 'master_item:' in lines[i-1]):
                    continue
                return i
        return 0
    
    # Process each template
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', f'template({t_idx + 1})')
            
            # === VALIDATE REGULAR ITEMS ===
            items = template.get('items', [])
            if isinstance(items, list):
                # Track defined items in order - build complete list first
                defined_keys = {}  # key -> (line_num, item_type, item_name)
                dependent_items = []  # Store dependent items for later validation
                
                # First pass: collect all item definitions
                for i_idx, item in enumerate(items):
                    if not isinstance(item, dict):
                        continue
                    
                    item_name = item.get('name', f'item({i_idx + 1})')
                    item_key = item.get('key', '')
                    item_type = item.get('type', '')
                    line_num = find_line_for_item(item_name, item_key)
                    
                    # Track this item as defined
                    if item_key:
                        defined_keys[item_key] = (line_num, item_type, item_name)
                    
                    # If this is a DEPENDENT item, store for validation
                    if item_type == 'DEPENDENT' or item_type == '18':
                        dependent_items.append((i_idx, item, item_name, item_key, item_type, line_num))
                
                # Second pass: validate all dependent items
                for i_idx, item, item_name, item_key, item_type, line_num in dependent_items:
                    master_item = item.get('master_item', {})
                    if isinstance(master_item, dict):
                        master_key = master_item.get('key', '')
                        
                        if not master_key:
                            errors.append((
                                line_num,
                                f"DEPENDENT item '{item_name}' at templates/{template_name}/items/item({i_idx + 1}) "
                                f"is missing required 'master_item.key' field"
                            ))
                        elif master_key not in defined_keys:
                            errors.append((
                                line_num,
                                f"DEPENDENT item '{item_name}' (key: {item_key}) references master item "
                                f"key '{master_key}' which does not exist in this template. "
                                f"Add the master item or check for typos in the key name."
                            ))
                        else:
                            master_line, master_type, master_name = defined_keys[master_key]
                            # Check if master is also DEPENDENT (circular)
                            if master_type == 'DEPENDENT' or master_type == '18':
                                errors.append((
                                    line_num,
                                    f"DEPENDENT item '{item_name}' (key: {item_key}) references master item "
                                    f"'{master_name}' (key: {master_key}) which is also DEPENDENT. "
                                    f"Circular or chained dependencies are not supported. "
                                    f"The master item must be EXTERNAL, TRAP, or another collector type."
                                ))
            
            # === VALIDATE DISCOVERY RULES AND ITEM PROTOTYPES ===
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if not isinstance(dr, dict):
                        continue
                    
                    dr_name = dr.get('name', f'discovery_rule({dr_idx + 1})')
                    dr_key = dr.get('key', '')
                    dr_type = dr.get('type', '')
                    
                    # Track defined items in this discovery rule scope
                    proto_defined_keys = {}
                    
                    # Add discovery rule itself as a potential master
                    if dr_key:
                        dr_line = find_line_for_item(dr_name, dr_key)
                        proto_defined_keys[dr_key] = (dr_line, dr_type, dr_name)
                    
                    # Process item prototypes
                    item_prototypes = dr.get('item_prototypes', [])
                    if isinstance(item_prototypes, list):
                        # Track defined items in this discovery rule scope
                        dependent_prototypes = []  # Store for later validation
                        
                        # First pass: collect all item prototype definitions
                        for ip_idx, ip in enumerate(item_prototypes):
                            if not isinstance(ip, dict):
                                continue
                            
                            ip_name = ip.get('name', f'item_prototype({ip_idx + 1})')
                            ip_key = ip.get('key', '')
                            ip_type = ip.get('type', '')
                            ip_line = find_line_for_item(ip_name, ip_key)
                            
                            # Track this item prototype as defined
                            if ip_key:
                                proto_defined_keys[ip_key] = (ip_line, ip_type, ip_name)
                            
                            # If this is a DEPENDENT item prototype, store for validation
                            if ip_type == 'DEPENDENT' or ip_type == '18':
                                dependent_prototypes.append((ip_idx, ip, ip_name, ip_key, ip_type, ip_line))
                        
                        # Second pass: validate all dependent item prototypes
                        for ip_idx, ip, ip_name, ip_key, ip_type, ip_line in dependent_prototypes:
                            master_item = ip.get('master_item', {})
                            if isinstance(master_item, dict):
                                master_key = master_item.get('key', '')
                                
                                if not master_key:
                                    errors.append((
                                        ip_line,
                                        f"DEPENDENT item prototype '{ip_name}' in discovery rule '{dr_name}' "
                                        f"is missing required 'master_item.key' field"
                                    ))
                                elif master_key not in proto_defined_keys:
                                    # Only flag as error if the master key doesn't exist anywhere in the template
                                    if master_key not in defined_keys:
                                        errors.append((
                                            ip_line,
                                            f"DEPENDENT item prototype '{ip_name}' (key: {ip_key}) references master "
                                            f"key '{master_key}' which does not exist in template. "
                                            f"Add the missing master item or correct the key reference."
                                        ))
                                elif master_key in proto_defined_keys:
                                    master_line, master_type, master_name = proto_defined_keys[master_key]
                                    # Check circular dependency
                                    if master_type == 'DEPENDENT' or master_type == '18':
                                        errors.append((
                                            ip_line,
                                            f"DEPENDENT item prototype '{ip_name}' (key: {ip_key}) references master "
                                            f"'{master_name}' (key: {master_key}) which is also DEPENDENT. "
                                            f"Circular or chained dependencies are not supported."
                                        ))
    
    return errors


def validate_all_template_references(yaml_data, file_content):
    """
    Comprehensive validation of ALL template references that could cause
    "No permissions to referred object or it does not exist!" errors during import.
    
    Checks:
    1. Graph item references
    2. Trigger item references  
    3. Dashboard widget item references
    4. Item prototype references in discovery rules
    5. Host template name consistency
    
    Returns: list of (line_num, error_message) tuples
    """
    errors = []
    lines = file_content.splitlines()
    
    def find_line_containing(text, context_lines=3):
        """Find line number containing specific text with some context."""
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 0
    
    # Process each template
    export_data = yaml_data.get('zabbix_export', {})
    templates = export_data.get('templates', [])
    
    if isinstance(templates, list):
        for t_idx, template in enumerate(templates):
            if not isinstance(template, dict):
                continue
            
            template_name = template.get('template', f'template({t_idx + 1})')
            
            # Collect all available item keys in this template
            all_item_keys = set()
            
            # Regular items
            items = template.get('items', [])
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get('key'):
                        all_item_keys.add(item['key'])
            
            # Item prototypes from discovery rules
            discovery_rules = template.get('discovery_rules', [])
            if isinstance(discovery_rules, list):
                for dr in discovery_rules:
                    if isinstance(dr, dict):
                        # Add discovery rule key
                        if dr.get('key'):
                            all_item_keys.add(dr['key'])
                        
                        # Add item prototype keys
                        item_prototypes = dr.get('item_prototypes', [])
                        if isinstance(item_prototypes, list):
                            for ip in item_prototypes:
                                if isinstance(ip, dict) and ip.get('key'):
                                    all_item_keys.add(ip['key'])
            
            # === CHECK GRAPH REFERENCES ===
            # Check graph_prototypes in discovery rules
            if isinstance(discovery_rules, list):
                for dr_idx, dr in enumerate(discovery_rules):
                    if isinstance(dr, dict):
                        dr_name = dr.get('name', f'discovery_rule({dr_idx})')
                        graph_prototypes = dr.get('graph_prototypes', [])
                        if isinstance(graph_prototypes, list):
                            for gp_idx, gp in enumerate(graph_prototypes):
                                if isinstance(gp, dict):
                                    graph_items = gp.get('graph_items', [])
                                    if isinstance(graph_items, list):
                                        for gi_idx, gi in enumerate(graph_items):
                                            if isinstance(gi, dict):
                                                item_ref = gi.get('item', {})
                                                if isinstance(item_ref, dict):
                                                    ref_host = item_ref.get('host', '')
                                                    ref_key = item_ref.get('key', '')
                                                    
                                                    # Check if host matches template name
                                                    if ref_host and ref_host != template_name and ref_host != '{HOST.NAME}':
                                                        line_num = find_line_containing(f"host: '{ref_host}'" if "'" in str(ref_host) else f"host: {ref_host}")
                                                        errors.append((
                                                            line_num,
                                                            f"Graph prototype in discovery rule '{dr_name}' references "
                                                            f"host '{ref_host}' but template name is '{template_name}'. "
                                                            f"Update host reference to match template name or use '{{HOST.NAME}}'."
                                                        ))
                                                    
                                                    # Check if referenced item key exists
                                                    if ref_key and ref_key not in all_item_keys:
                                                        line_num = find_line_containing(f"key: '{ref_key}'" if "'" in ref_key else f"key: {ref_key}")
                                                        errors.append((
                                                            line_num,
                                                            f"Graph prototype in discovery rule '{dr_name}' references "
                                                            f"item key '{ref_key}' which does not exist in this template. "
                                                            f"Add the missing item or correct the key reference."
                                                        ))
            
            # === CHECK TRIGGER REFERENCES ===
            # Check trigger expressions for item references
            if isinstance(items, list):
                for item_idx, item in enumerate(items):
                    if isinstance(item, dict):
                        triggers = item.get('triggers', [])
                        if isinstance(triggers, list):
                            for trigger_idx, trigger in enumerate(triggers):
                                if isinstance(trigger, dict):
                                    expression = trigger.get('expression', '')
                                    if expression:
                                        # Extract item references from trigger expression
                                        # Pattern: last(/Template Name/item.key[params])
                                        import re
                                        pattern = r'last\(/([^/]+)/([^\)]+)\)'
                                        matches = re.findall(pattern, expression)
                                        for host_ref, key_ref in matches:
                                            # Check if host matches template name
                                            if host_ref != template_name and host_ref != '{HOST.NAME}':
                                                line_num = find_line_containing(expression)
                                                errors.append((
                                                    line_num,
                                                    f"Trigger expression references host '{host_ref}' "
                                                    f"but template name is '{template_name}'. "
                                                    f"Update trigger expression to use correct template name."
                                                ))
                                            
                                            # Check if referenced item key exists
                                            # Strip historical value references like ,#1, ,#2, etc.
                                            base_key = re.sub(r',#\d+$', '', key_ref)
                                            if base_key not in all_item_keys:
                                                line_num = find_line_containing(expression)
                                                errors.append((
                                                    line_num,
                                                    f"Trigger expression references item key '{key_ref}' "
                                                    f"which does not exist in template '{template_name}'. "
                                                    f"Add the missing item or correct the key reference."
                                                ))
            
            # === CHECK DASHBOARD WIDGET REFERENCES ===
            dashboards = template.get('dashboards', [])
            if isinstance(dashboards, list):
                for dash_idx, dashboard in enumerate(dashboards):
                    if isinstance(dashboard, dict):
                        pages = dashboard.get('pages', [])
                        if isinstance(pages, list):
                            for page in pages:
                                if isinstance(page, dict):
                                    widgets = page.get('widgets', [])
                                    if isinstance(widgets, list):
                                        for widget in widgets:
                                            if isinstance(widget, dict):
                                                fields = widget.get('fields', [])
                                                if isinstance(fields, list):
                                                    for field in fields:
                                                        if isinstance(field, dict) and field.get('type') == 'ITEM':
                                                            value = field.get('value', {})
                                                            if isinstance(value, dict):
                                                                ref_host = value.get('host', '')
                                                                ref_key = value.get('key', '')
                                                                
                                                                # Check if host reference is valid
                                                                if ref_host and ref_host != template_name and ref_host != '{HOST.NAME}':
                                                                    line_num = find_line_containing(f"host: '{ref_host}'" if "'" in str(ref_host) else f"host: {ref_host}")
                                                                    errors.append((
                                                                        line_num,
                                                                        f"Dashboard widget references host '{ref_host}' "
                                                                        f"but template name is '{template_name}'. "
                                                                        f"Update host reference to match template name or use '{{HOST.NAME}}'."
                                                                    ))
                                                                
                                                                # Check if referenced item key exists
                                                                if ref_key and ref_key not in all_item_keys:
                                                                    line_num = find_line_containing(f"key: '{ref_key}'" if "'" in ref_key else f"key: {ref_key}")
                                                                    errors.append((
                                                                        line_num,
                                                                        f"Dashboard widget references item key '{ref_key}' "
                                                                        f"which does not exist in template '{template_name}'. "
                                                                        f"Add the missing item or correct the key reference."
                                                                    ))
    
    return errors


def validate_comprehensive_zabbix_schema(yaml_data, file_content):
    """
    Comprehensive Zabbix template validation combining all checks.
    Returns (errors, warnings, version) tuple.
    """
    all_errors = []
    all_warnings = []
    
    # Get basic schema validation first
    errors, warnings, version = validate_zabbix_schema(yaml_data, file_content)
    all_errors.extend(errors)
    all_warnings.extend(warnings)
    
    # Add missing validation checks
    required_field_errors = validate_required_fields(yaml_data, file_content)
    for line_num, msg in required_field_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    snmp_config_errors = validate_snmp_configuration(yaml_data, file_content)
    for line_num, msg in snmp_config_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    key_format_errors = validate_key_format(yaml_data, file_content)
    for line_num, msg in key_format_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    # Check for duplicate macros
    duplicate_macro_errors = validate_duplicate_macros(yaml_data, file_content)
    for line_num, msg in duplicate_macro_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    # Check widget field types in dashboards
    widget_field_errors = validate_widget_field_types(yaml_data, file_content)
    for line_num, msg in widget_field_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    # Check trigger indentation
    trigger_indent_errors = validate_trigger_indentation(yaml_data, file_content)
    for line_num, msg in trigger_indent_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    # Check master item references (DEPENDENT items)
    master_item_errors = validate_master_item_references(yaml_data, file_content)
    for line_num, msg in master_item_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    # Check all template references (graphs, triggers, dashboards)
    reference_errors = validate_all_template_references(yaml_data, file_content)
    for line_num, msg in reference_errors:
        prefix = f"Line {line_num}: " if line_num else ""
        all_errors.append(f"{prefix}{msg}")
    
    return all_errors, all_warnings, version


def validate_external_script_format(yaml_data, file_content):
    """
    Validate external script key formats to detect deprecated JSON-style format.
    Reports EXTERNAL items using deprecated ["param1","param2"] syntax.
    """
    errors = []
    
    def find_line_for_item_key(item_key):
        lines = file_content.split('\n')
        for line_no, line in enumerate(lines, 1):
            if item_key in line and 'key:' in line:
                return line_no
        return None
    
    def check_items_for_script_format(items_list, location_name, template_name):
        if not isinstance(items_list, list):
            return
            
        for i_idx, item in enumerate(items_list):
            if not isinstance(item, dict):
                continue
                
            item_type = item.get('type', '')
            item_key = item.get('key', '')
            item_name = item.get('name', f'{location_name}({i_idx + 1})')
            
            if item_type == 'EXTERNAL' or item_type == '10':
                # Check for deprecated JSON-style format with quoted parameters
                if re.search(r'\.py\["[^"]*"', item_key):
                    line_num = find_line_for_item_key(item_key)
                    line_ref = f"line {line_num}" if line_num else f"templates/{template_name}/{location_name}/item({i_idx + 1})"
                    errors.append((
                        f"EXTERNAL item '{item_name}' at {line_ref} "
                        f"uses deprecated JSON-style external script format: {item_key}. "
                        f"Use unquoted parameters: script.py[param1,param2,param3]"
                    ))
                
                # Check for general external script format validity
                elif '.py' in item_key and not re.match(r'^[^.]+\.py\[[^\]]*\]$', item_key):
                    line_num = find_line_for_item_key(item_key)
                    line_ref = f"line {line_num}" if line_num else f"templates/{template_name}/{location_name}/item({i_idx + 1})"
                    errors.append((
                        f"EXTERNAL item '{item_name}' at {line_ref} "
                        f"may have invalid external script format: {item_key}"
                    ))
    
    if 'zabbix_export' not in yaml_data or 'templates' not in yaml_data['zabbix_export']:
        return errors
    
    for template in yaml_data['zabbix_export']['templates']:
        if not isinstance(template, dict):
            continue
            
        template_name = template.get('template', 'UNKNOWN')
        
        # Check regular items
        items = template.get('items', [])
        if isinstance(items, list):
            check_items_for_script_format(items, 'items', template_name)
        
        # Check discovery rule item prototypes
        discovery_rules = template.get('discovery_rules', [])
        if isinstance(discovery_rules, list):
            for dr_idx, dr in enumerate(discovery_rules):
                if not isinstance(dr, dict):
                    continue
                    
                item_prototypes = dr.get('item_prototypes', [])
                if isinstance(item_prototypes, list):
                    check_items_for_script_format(item_prototypes, f'discovery_rules/discovery_rule({dr_idx + 1})/item_prototypes', template_name)
    
    return errors


def validate_trigger_references(yaml_data, file_content):
    """
    Enhanced trigger expression validation including deprecated external script format detection.
    Validates that trigger expressions reference existing items and don't use deprecated JSON-style formats.
    """
    errors = []
    
    def extract_item_refs(expression):
        """Extract all possible item references from trigger expression"""
        refs = []
        patterns = [
            r'last\(/[^/]+/([^)]+)\)',
            r'min\(/[^/]+/([^),]+)',
            r'max\(/[^/]+/([^),]+)',
            r'avg\(/[^/]+/([^),]+)',
            r'sum\(/[^/]+/([^),]+)',
            r'count\(/[^/]+/([^),]+)',
            r'nodata\(/[^/]+/([^),]+)',
            r'change\(/[^/]+/([^)]+)\)',
            r'diff\(/[^/]+/([^)]+)\)',
            r'find\(/[^/]+/([^),]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, expression)
            refs.extend(matches)
        
        return list(set(refs))
    
    def find_line_for_trigger_name(trigger_name):
        lines = file_content.split('\n')
        for line_no, line in enumerate(lines, 1):
            if trigger_name in line and 'name:' in line:
                return line_no
        return None
    
    def check_triggers_for_refs(triggers_list, location_name, template_name, rule_name=None):
        if not isinstance(triggers_list, list):
            return
            
        for t_idx, trigger in enumerate(triggers_list):
            if not isinstance(trigger, dict):
                continue
                
            trigger_name = trigger.get('name', f'{location_name}({t_idx + 1})')
            expression = trigger.get('expression', '')
            
            # Check for deprecated JSON-style external script format in trigger expressions
            if re.search(r'\.py\["[^"]*"', expression):
                line_num = find_line_for_trigger_name(trigger_name)
                location = f"{location_name} in {rule_name}" if rule_name else location_name
                line_ref = f"line {line_num}" if line_num else f"templates/{template_name}/{location}/trigger({t_idx + 1})"
                errors.append((
                    f"Trigger '{trigger_name}' at {line_ref} "
                    f"uses deprecated JSON-style external script format in expression: {expression}. "
                    f"Update to use unquoted parameters."
                ))
            
            # Extract and validate item references
            item_refs = extract_item_refs(expression)
            for item_ref in item_refs:
                # Check if the extracted item reference uses JSON style
                if re.search(r'\.py\["[^"]*"', item_ref):
                    line_num = find_line_for_trigger_name(trigger_name)
                    location = f"{location_name} in {rule_name}" if rule_name else location_name
                    line_ref = f"line {line_num}" if line_num else f"templates/{template_name}/{location}/trigger({t_idx + 1})"
                    errors.append((
                        f"Trigger '{trigger_name}' at {line_ref} "
                        f"references item with deprecated JSON-style external script format: {item_ref}. "
                        f"Update to use unquoted parameters."
                    ))
    
    if 'zabbix_export' not in yaml_data or 'templates' not in yaml_data['zabbix_export']:
        return errors
    
    for template in yaml_data['zabbix_export']['templates']:
        if not isinstance(template, dict):
            continue
            
        template_name = template.get('template', 'UNKNOWN')
        
        # Template-level triggers
        triggers = template.get('triggers', [])
        if isinstance(triggers, list):
            check_triggers_for_refs(triggers, 'triggers', template_name)
        
        # Item triggers
        items = template.get('items', [])
        if isinstance(items, list):
            for i_idx, item in enumerate(items):
                if isinstance(item, dict) and 'triggers' in item:
                    check_triggers_for_refs(item['triggers'], f'items/item({i_idx + 1})/triggers', template_name)
        
        # Discovery rule trigger prototypes
        discovery_rules = template.get('discovery_rules', [])
        if isinstance(discovery_rules, list):
            for dr_idx, rule in enumerate(discovery_rules):
                if not isinstance(rule, dict):
                    continue
                    
                rule_name = rule.get('name', f'discovery_rule({dr_idx + 1})')
                
                # Direct trigger prototypes under discovery rule
                if 'trigger_prototypes' in rule:
                    check_triggers_for_refs(
                        rule['trigger_prototypes'], 
                        f'discovery_rules/discovery_rule({dr_idx + 1})/trigger_prototypes', 
                        template_name, 
                        rule_name
                    )
                
                # Trigger prototypes inside item prototypes
                item_prototypes = rule.get('item_prototypes', [])
                if isinstance(item_prototypes, list):
                    for ip_idx, item_proto in enumerate(item_prototypes):
                        if isinstance(item_proto, dict) and 'trigger_prototypes' in item_proto:
                            item_name = item_proto.get('name', f'item_prototype({ip_idx + 1})')
                            check_triggers_for_refs(
                                item_proto['trigger_prototypes'],
                                f'discovery_rules/discovery_rule({dr_idx + 1})/item_prototypes/item_prototype({ip_idx + 1})/trigger_prototypes',
                                template_name,
                                f"{rule_name}/{item_name}"
                            )
    
    return errors


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
        print("  ✓ Dashboard widget field type validation")
        print("  ✓ Widget-specific field compatibility checking")
        print("  ✓ Trigger section indentation validation")
        print("  ✓ Master item reference validation (DEPENDENT items)")
        print("  ✓ Circular dependency detection")
        print("  ✓ Cross-scope reference validation")
        sys.exit(1)
    
    file_path = sys.argv[1]
    print(f"Validating {file_path}...")
    print("=" * 80)
    success = validate_yaml_file(file_path)
    print("=" * 80)
    
    sys.exit(0 if success else 1)
