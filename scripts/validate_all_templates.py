#!/usr/bin/env python3
"""
Zabbix Template Validation Suite

Validates all Zabbix YAML templates in the templates directory by running
validate_zabbix_template.py against each template file.

Usage:
    python validate_all_templates.py
    python validate_all_templates.py --templates-path /path/to/templates
    python validate_all_templates.py --show-details
"""

import os
import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple


class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    DARK_RED = '\033[31m'
    DARK_GRAY = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


def colorize(text: str, color: str) -> str:
    """Wrap text in ANSI color codes"""
    return f"{color}{text}{Colors.RESET}"


def print_header():
    """Print validation suite header"""
    print()
    print(colorize("=" * 40, Colors.CYAN))
    print(colorize("Zabbix Template Validation Suite", Colors.CYAN))
    print(colorize("=" * 40, Colors.CYAN))


def print_separator():
    """Print separator line"""
    print(colorize("=" * 40, Colors.CYAN))


def find_templates(templates_path: Path) -> List[Path]:
    """Find all YAML template files in the templates directory"""
    yaml_files = list(templates_path.glob("*.yaml"))
    yml_files = list(templates_path.glob("*.yml"))
    all_templates = sorted(yaml_files + yml_files, key=lambda p: p.name)
    return all_templates


def validate_template(python_exe: str, validator_script: Path, template_path: Path) -> Tuple[bool, str]:
    """
    Run validation on a single template
    
    Returns:
        Tuple of (success: bool, output: str)
    """
    try:
        result = subprocess.run(
            [python_exe, str(validator_script), str(template_path)],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=30
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output.strip()
    except subprocess.TimeoutExpired:
        return False, "Validation timed out after 30 seconds"
    except Exception as e:
        return False, f"Error running validation: {str(e)}"


def main():
    """Main validation routine"""
    parser = argparse.ArgumentParser(
        description="Validate all Zabbix YAML templates in the templates directory"
    )
    parser.add_argument(
        '--templates-path',
        type=str,
        default='',
        help='Path to templates directory (defaults to ../templates relative to script)'
    )
    parser.add_argument(
        '--show-details',
        action='store_true',
        help='Show detailed output for each template validation'
    )
    
    args = parser.parse_args()
    
    # Determine paths
    script_dir = Path(__file__).parent.resolve()
    repo_root = script_dir.parent
    
    if args.templates_path:
        templates_path = Path(args.templates_path).resolve()
    else:
        templates_path = repo_root / "templates"
    
    validator_script = script_dir / "validate_zabbix_template.py"
    
    # Try to find Python executable - prefer venv, fallback to system Python
    python_exe = None
    venv_python_win = repo_root / ".venv" / "Scripts" / "python.exe"
    venv_python_unix = repo_root / ".venv" / "bin" / "python"
    
    if venv_python_win.exists():
        python_exe = str(venv_python_win)
    elif venv_python_unix.exists():
        python_exe = str(venv_python_unix)
    else:
        # Fallback to system Python (the one running this script)
        python_exe = sys.executable
    
    # Verify paths exist
    if not templates_path.exists():
        print(colorize(f"Error: Templates directory not found: {templates_path}", Colors.RED), file=sys.stderr)
        sys.exit(1)
    
    if not validator_script.exists():
        print(colorize(f"Error: Validator script not found: {validator_script}", Colors.RED), file=sys.stderr)
        sys.exit(1)
    
    # Find all templates
    all_templates = find_templates(templates_path)
    
    if not all_templates:
        print(colorize(f"Warning: No YAML template files found in: {templates_path}", Colors.YELLOW))
        sys.exit(0)
    
    # Print header
    print_header()
    print(colorize(f"Templates Path: {templates_path}", Colors.DARK_GRAY))
    print(colorize(f"Found Templates: {len(all_templates)}", Colors.DARK_GRAY))
    print_separator()
    print()
    
    # Track results
    passed_count = 0
    failed_count = 0
    results = []
    
    # Validate each template
    for template in all_templates:
        template_name = template.name
        
        print("Validating: ", end="")
        print(colorize(template_name, Colors.YELLOW), end="")
        print(" ... ", end="", flush=True)
        
        # Execute validation
        success, output = validate_template(python_exe, validator_script, template)
        
        if success:
            print(colorize("[PASS]", Colors.GREEN))
            passed_count += 1
            results.append({
                'template': template_name,
                'status': 'PASS',
                'message': output
            })
            
            if args.show_details:
                print(colorize(f"  Output: {output}", Colors.DARK_GRAY))
        else:
            print(colorize("[FAIL]", Colors.RED))
            failed_count += 1
            results.append({
                'template': template_name,
                'status': 'FAIL',
                'message': output
            })
            
            # Always show errors
            print(colorize("  Errors:", Colors.RED))
            for line in output.split('\n'):
                if line.strip():
                    print(colorize(f"    {line}", Colors.DARK_RED))
    
    # Print summary
    print()
    print_separator()
    print(colorize("Validation Summary", Colors.CYAN))
    print_separator()
    
    print("Total Templates: ", end="")
    print(colorize(str(len(all_templates)), Colors.WHITE))
    
    print("Passed:          ", end="")
    print(colorize(str(passed_count), Colors.GREEN))
    
    print("Failed:          ", end="")
    print(colorize(str(failed_count), Colors.RED))
    
    print("Success Rate:    ", end="")
    if len(all_templates) > 0:
        success_rate = round((passed_count / len(all_templates)) * 100, 2)
        if success_rate == 100:
            color = Colors.GREEN
        elif success_rate >= 75:
            color = Colors.YELLOW
        else:
            color = Colors.RED
        print(colorize(f"{success_rate}%", color))
    
    print_separator()
    print()
    
    # List failed templates if any
    if failed_count > 0:
        print(colorize("Failed Templates:", Colors.RED))
        for result in results:
            if result['status'] == 'FAIL':
                print(colorize(f"  - {result['template']}", Colors.RED))
        print()
    
    # Exit with appropriate code
    if failed_count == 0:
        print(colorize("[SUCCESS] All templates validated successfully!", Colors.GREEN))
        sys.exit(0)
    else:
        print(colorize(f"[FAILED] {failed_count} template(s) failed validation.", Colors.RED))
        sys.exit(1)


if __name__ == "__main__":
    main()
