# Zabbix 7.4 Import Validation vs validate_zabbix_template.py Comparison

## Overview

This document compares the validation checks performed by Zabbix 7.4's built-in import process against our custom `validate_zabbix_template.py` script.

**Purpose**: Identify gaps in our validation to ensure templates pass Zabbix import on the first attempt.

---

## Zabbix 7.4 Import Validation Capabilities

Based on Zabbix documentation and source code analysis, the following validators are implemented:

### 1. **Core Schema Validators** (`ui/include/classes/validators/`)

| Validator Class | Purpose | Our Script Status |
|----------------|---------|-------------------|
| `CApiInputValidator.php` | Master API input validation (120KB+) | ⚠️ **PARTIAL** - Basic structure only |
| `CFormValidator.php` | Form/import validation (58KB+) | ⚠️ **PARTIAL** - Basic structure only |
| `CExpressionValidator.php` | Trigger expression validation | ❌ **MISSING** - Simple regex only |
| `CHistFunctionValidator.php` | History function validation | ❌ **MISSING** |
| `CItemKeyValidator.php` | Item key format validation | ❌ **MISSING** |
| `CHostNameValidator.php` | Host/template name validation | ❌ **MISSING** |
| `CHostGroupNameValidator.php` | Group name validation | ❌ **MISSING** |
| `CColorValidator.php` | Color code validation | ❌ **MISSING** |
| `CJsonValidator.php` | JSON format validation | ❌ **MISSING** |
| `CXmlValidator.php` | XML format validation | ❌ **MISSING** |
| `CEmailValidator.php` | Email format validation | ❌ **MISSING** |
| `CHtmlUrlValidator.php` | URL validation | ❌ **MISSING** |
| `CUrlValidator.php` | Basic URL validation | ❌ **MISSING** |
| `CRegexValidator.php` | Regex pattern validation | ❌ **MISSING** |
| `CTimeUnitValidator.php` | Time unit format validation | ❌ **MISSING** |
| `CIdValidator.php` | ID format validation | ❌ **MISSING** |
| `CStringValidator.php` | String constraints validation | ❌ **MISSING** |
| `CMathFunctionValidator.php` | Math function validation | ❌ **MISSING** |
| `CCalcFormulaValidator.php` | Calculated item formula validation | ❌ **MISSING** |
| `CEventNameValidator.php` | Event name validation | ❌ **MISSING** |
| `CActionCondValidator.php` | Action condition validation | ❌ **MISSING** |
| `CEventCorrCondValidator.php` | Event correlation validation | ❌ **MISSING** |

### 2. **Import-Specific Validations**

| Validation Category | Zabbix Checks | Our Script Status |
|--------------------|---------------|-------------------|
| **Version Compatibility** | Validates version field against supported versions | ✅ **IMPLEMENTED** |
| **UUID Format** | Validates UUIDv4 format (32 hex chars) | ✅ **IMPLEMENTED** |
| **UUID Uniqueness** | Checks UUIDs don't conflict with existing objects | ❌ **CANNOT CHECK** (requires DB) |
| **Required Fields** | Validates all required fields per object type | ⚠️ **PARTIAL** - Basic fields only |
| **Field Types** | Validates field value types (string, int, bool, etc.) | ❌ **MISSING** |
| **Enum Values** | Validates enumerated values (status, type, etc.) | ❌ **MISSING** |
| **Value Ranges** | Validates numeric ranges (0-100, 1-10, etc.) | ❌ **MISSING** |
| **String Length** | Validates max string lengths per field | ❌ **MISSING** |
| **Regex Patterns** | Validates format patterns (time units, IPs, etc.) | ❌ **MISSING** |

### 3. **Structural Validations**

| Structure | Zabbix Checks | Our Script Status |
|-----------|---------------|-------------------|
| **Template Structure** | Valid template groups, name, etc. | ✅ **IMPLEMENTED** |
| **Item Structure** | Type, key, delay, value_type, etc. | ⚠️ **PARTIAL** - Key structure only |
| **Trigger Structure** | Expression syntax, dependencies | ⚠️ **PARTIAL** - Simple regex only |
| **Discovery Rule Structure** | Filter conditions, prototypes | ⚠️ **PARTIAL** - Prototype placement only |
| **Graph Structure** | Graph items, axes, thresholds | ❌ **MISSING** |
| **Dashboard Structure** | Widgets, pages, fields | ❌ **MISSING** |
| **Value Map Structure** | Mappings, types | ❌ **MISSING** |
| **Web Scenario Structure** | Steps, headers, authentication | ❌ **MISSING** |

### 4. **Reference Integrity Validations**

| Reference Type | Zabbix Checks | Our Script Status |
|----------------|---------------|-------------------|
| **Item Keys in Graphs** | Graph items reference existing items | ✅ **IMPLEMENTED** |
| **Item Keys in Triggers** | Trigger expressions reference existing items | ✅ **IMPLEMENTED** |
| **Host Names in Graphs** | Host matches template name | ✅ **IMPLEMENTED** |
| **Host Names in Triggers** | Host matches template name | ✅ **IMPLEMENTED** |
| **Master Items** | Dependent items reference valid master | ❌ **MISSING** |
| **Value Maps** | Item references valid value map | ❌ **MISSING** |
| **Macros** | Macro references are valid | ❌ **MISSING** |
| **Trigger Dependencies** | Dependencies reference existing triggers | ⚠️ **PARTIAL** - Basic check only |
| **Template Linkage** | Linked templates exist | ❌ **MISSING** |
| **Discovery Rule Filters** | Macros exist in discovery | ❌ **MISSING** |
| **LLD Macro Paths** | JSONPath/XPath are valid | ❌ **MISSING** |

### 5. **Item-Specific Validations**

| Item Field | Zabbix Checks | Our Script Status |
|------------|---------------|-------------------|
| **key** | Valid syntax, parameters | ❌ **MISSING** |
| **type** | Valid item type enum (0-22) | ❌ **MISSING** |
| **value_type** | Valid value type (0-5) | ❌ **MISSING** |
| **delay** | Valid time unit format | ❌ **MISSING** |
| **history** | Valid time unit format | ❌ **MISSING** |
| **trends** | Valid time unit format | ❌ **MISSING** |
| **snmp_oid** | Valid OID format (for SNMP items) | ❌ **MISSING** |
| **units** | Valid units string | ❌ **MISSING** |
| **params** | Valid script/formula (by type) | ❌ **MISSING** |
| **username/password** | Required for certain types | ❌ **MISSING** |
| **authtype** | Valid auth type enum | ❌ **MISSING** |
| **url** | Valid URL (for HTTP agent) | ❌ **MISSING** |
| **preprocessing** | Valid preprocessing steps | ❌ **MISSING** |
| **tags** | Valid tag structure | ❌ **MISSING** |

### 6. **Trigger-Specific Validations**

| Trigger Field | Zabbix Checks | Our Script Status |
|---------------|---------------|-------------------|
| **expression** | Full expression parser validation | ⚠️ **PARTIAL** - Simple regex only |
| **recovery_expression** | Valid recovery expression | ❌ **MISSING** |
| **priority** | Valid severity enum (0-5) | ❌ **MISSING** |
| **status** | Valid status enum (0-1) | ❌ **MISSING** |
| **type** | Valid type enum (0-1) | ❌ **MISSING** |
| **manual_close** | Valid bool enum | ❌ **MISSING** |
| **opdata** | Valid operational data | ❌ **MISSING** |
| **url** | Valid URL format | ❌ **MISSING** |
| **correlation_mode** | Valid correlation enum | ❌ **MISSING** |
| **dependencies** | Valid trigger references | ⚠️ **BASIC** - Found errors but limited |

### 7. **Complex Expression Validation**

Zabbix uses `CExpressionValidator.php` which performs:

| Check | Description | Our Script Status |
|-------|-------------|-------------------|
| **Function Syntax** | Validates `last()`, `avg()`, `max()`, etc. | ❌ **MISSING** |
| **Function Parameters** | Validates parameter count and types | ❌ **MISSING** |
| **Time Parameters** | Validates time suffixes (s, m, h, d, w) | ❌ **MISSING** |
| **Math Operators** | Validates +, -, *, /, (), etc. | ❌ **MISSING** |
| **Logical Operators** | Validates and, or, not, =, <>, <, >, etc. | ❌ **MISSING** |
| **Item References** | Validates `/template/item.key` format | ⚠️ **PARTIAL** - Basic regex |
| **Macro References** | Validates `{$MACRO}` usage | ❌ **MISSING** |
| **Nested Expressions** | Validates complex nested logic | ❌ **MISSING** |
| **Context Functions** | Validates context-specific functions | ❌ **MISSING** |

**Example expressions our script cannot fully validate:**
```
avg(/Linux/system.cpu.load,3m)>2 and last(/Linux/system.uptime)<10m
(100-avg(/Linux/vm.memory.size[pavailable],5m))<{$MEMORY.AVAILABLE.MIN}
min(/Linux/net.if.in[{#IFNAME}],5m)*100/last(/Linux/net.if.speed[{#IFNAME}])>90
```

---

## Current Script Capabilities Summary

### ✅ What We Validate Well

1. **Basic YAML Syntax** - Python yaml parser handles this
2. **Top-Level Structure** - `zabbix_export`, `version`, `templates`
3. **Version Compatibility** - Checks against supported versions
4. **UUID Format** - Full UUIDv4 validation (position 12='4', position 16='8'/'9'/'a'/'b')
5. **Template Required Fields** - `name`, `groups`
6. **Prototype Placement** - Ensures `*_prototypes` only in `discovery_rules`
7. **Item Reference Integrity** - Graphs and triggers reference existing items
8. **Host Name Consistency** - Host names match template name

### ⚠️ What We Partially Validate

1. **Trigger Expressions** - Simple regex pattern matching, misses complex expressions
2. **Item Keys** - Basic presence check, no format validation
3. **Required Fields** - Only checks critical fields, not all required fields
4. **Trigger Dependencies** - Basic check, caught errors but limited parsing

### ❌ What We Don't Validate

1. **Field Data Types** - No type checking (string vs int vs bool)
2. **Enum Values** - No validation of status codes, types, priorities
3. **Value Ranges** - No numeric range validation
4. **String Lengths** - No max length enforcement
5. **Time Unit Formats** - No validation of `1m`, `5h`, `30s`, etc.
6. **Item Key Syntax** - No parsing of `item.key[param1,param2]`
7. **SNMP OID Format** - No validation of OID syntax
8. **URL Formats** - No URL validation for HTTP items
9. **Regex Patterns** - No validation of user regex patterns
10. **Preprocessing Steps** - No validation of preprocessing types/params
11. **Master Item References** - No validation of dependent items
12. **Value Map References** - No checking if value maps exist
13. **Macro Definitions** - No macro validation
14. **LLD Macros** - No discovery macro validation
15. **Graph Configuration** - No graph structure validation
16. **Dashboard Widgets** - No dashboard validation
17. **Web Scenarios** - No web scenario validation
18. **Complex Math** - No validation of mathematical expressions
19. **Function Calls** - No validation of Zabbix functions
20. **Database Uniqueness** - Cannot check if UUIDs/names already exist

---

## Identified Gaps in Our Validator

### **HIGH PRIORITY** (Causes import failures)

1. **Item Key Format Validation**
   - Issue found: `aruba.ap.clientcount[{#SSIDNAME}` missing closing `]`
   - Need: Parse item key syntax, validate brackets, parameters
   - Impact: **HIGH** - Causes import failure

2. **Complex Trigger Expression Parsing**
   - Issue found: Regex catches math operators as template names
   - Example: `(100-avg(...))` → regex catches `100)*last(` as template name
   - Need: Full expression parser, not simple regex
   - Impact: **HIGH** - False positives make validation unreliable

3. **Time Unit Format Validation**
   - Examples: `1m`, `5h`, `30s`, `1d`, `1w`
   - Fields: `delay`, `history`, `trends`, `timeout`
   - Impact: **MEDIUM** - Causes import failure

4. **Enum Value Validation**
   - Fields: `type`, `value_type`, `status`, `priority`, etc.
   - Need: Validate against allowed enum values per Zabbix version
   - Impact: **MEDIUM** - Causes import failure

5. **SNMP OID Format**
   - Example: `1.3.6.1.4.1.14823.2.2.1.5.2.1.8.1`
   - Required for: SNMP agent items
   - Impact: **MEDIUM** - Causes import failure for SNMP templates

### **MEDIUM PRIORITY** (Improves reliability)

6. **Master Item References**
   - Dependent items must reference existing master items
   - Impact: **MEDIUM** - Causes import failure

7. **Value Map References**
   - Items referencing value maps that don't exist
   - Impact: **LOW** - Visual issue, not fatal

8. **Preprocessing Step Validation**
   - Step types, parameter counts, parameter formats
   - Impact: **MEDIUM** - Can cause runtime errors

9. **Field Type Validation**
   - Ensure integers are integers, booleans are valid, etc.
   - Impact: **LOW** - YAML parser catches most

10. **String Length Limits**
    - Zabbix has max lengths per field
    - Impact: **LOW** - Database constraints catch this

### **LOW PRIORITY** (Nice to have)

11. **Graph Structure Validation**
12. **Dashboard Widget Validation**
13. **Web Scenario Validation**
14. **Discovery Filter Validation**
15. **LLD Macro Path Validation** (JSONPath/XPath)

---

## Recommendations

### Immediate Actions

1. **Fix Item Key Validator**
   ```python
   def validate_item_key(key):
       # Parse item.key[param1,param2] format
       # Validate brackets are balanced
       # Validate parameters are properly quoted if needed
   ```

2. **Implement Time Unit Validator**
   ```python
   def validate_time_unit(value):
       # Match pattern: \d+[smhdw] or user macros
       # Examples: 1m, 5h, 30s, 1d, 1w, {$MACRO}
   ```

3. **Replace Trigger Expression Regex with Parser**
   - Consider using a proper expression parser
   - Option 1: Implement recursive descent parser
   - Option 2: Use existing parser library
   - Option 3: Skip complex expressions, document limitation

4. **Add Enum Validators**
   ```python
   ITEM_TYPES = {
       '0': 'ZABBIX_PASSIVE',
       '2': 'TRAP',
       # ... etc
   }
   def validate_item_type(type_value):
       return type_value in ITEM_TYPES
   ```

### Long-term Improvements

1. **Consider using Zabbix API for validation**
   - Could call `configuration.import` with `dryRun: true` (if available)
   - Would catch all validation errors Zabbix would catch

2. **Build comprehensive test suite**
   - Create test templates with known errors
   - Ensure validator catches all known error patterns

3. **Document limitations**
   - Be clear about what the validator can and cannot check
   - Provide guidance for complex expressions

---

## Conclusion

Our `validate_zabbix_template.py` script provides **good coverage for basic structure and reference integrity**, but has **significant gaps in detailed field validation**.

**Coverage Estimate:**
- ✅ **Structural validation**: ~80% coverage
- ⚠️ **Field validation**: ~20% coverage
- ⚠️ **Expression validation**: ~10% coverage
- ❌ **Advanced validation**: ~5% coverage

**Overall**: We catch ~30-40% of issues that would cause Zabbix import failures.

The validator is **useful for catching common mistakes early**, but **cannot replace testing actual imports** into Zabbix.

### Success Criteria Met

✅ Prevents YAML syntax errors
✅ Prevents UUID format errors
✅ Prevents prototype misplacement
✅ Catches broken item references
✅ Catches host name mismatches

### Still Requires Manual Testing

⚠️ Item key syntax errors
⚠️ Complex trigger expressions
⚠️ Time unit formats
⚠️ Enum value errors
⚠️ SNMP OID formats
⚠️ Field type mismatches

---

**Generated**: 2025-11-12
**Zabbix Version**: 7.4
**Script Version**: validate_zabbix_template.py (with item reference validation)
