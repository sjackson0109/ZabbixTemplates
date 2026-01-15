#!/usr/bin/env python3
"""
Zabbix Template Database Performance Optimisation Analyser

This script analyses all Zabbix template YAML files to identify database 
performance optimisation opportunities using UK English terminology.

Author: GitHub Copilot Analysis Tool
Date: January 4, 2026
"""

import os
import yaml
import glob
import re
import sys
import argparse
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass
from pathlib import Path

@dataclass
class OptimisationOpportunity:
    template_name: str
    category: str
    current_issue: str
    recommendation: str
    expected_benefit: str
    risk_level: str
    severity: str

class ZabbixTemplateAnalyser:
    def __init__(self, templates_dir: str):
        self.templates_dir = Path(templates_dir)
        self.opportunities: List[OptimisationOpportunity] = []
        
    def analyse_all_templates(self) -> List[OptimisationOpportunity]:
        """Analyse all YAML templates in the directory."""
        template_files = list(self.templates_dir.glob("*.yaml"))
        
        for template_file in template_files:
            print(f"Analysing: {template_file.name}")
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    template_data = yaml.safe_load(f)
                self._analyse_template(template_file.name, template_data)
            except Exception as e:
                print(f"Error analysing {template_file.name}: {e}")
                
        return self.opportunities
    
    def _analyse_template(self, filename: str, template_data: Dict[str, Any]):
        """Analyze a single template for optimization opportunities."""
        if 'zabbix_export' not in template_data:
            return
            
        templates = template_data.get('zabbix_export', {}).get('templates', [])
        
        for template in templates:
            template_name = template.get('name', filename.replace('.yaml', ''))
            
            # Analyze different aspects
            self._analyze_history_retention(template_name, template)
            self._analyze_trends_retention(template_name, template)
            self._analyze_data_collection_intervals(template_name, template)
            self._analyze_value_types(template_name, template)
            self._analyze_preprocessing(template_name, template)
            self._analyze_item_counts(template_name, template)
            self._analyze_text_items_without_trends(template_name, template)
    
    def _analyze_history_retention(self, template_name: str, template: Dict[str, Any]):
        """Analyze history retention settings."""
        items = self._get_all_items(template)
        
        for item in items:
            history = item.get('history', '90d')  # Default Zabbix history
            
            # Check for unnecessarily long history
            if self._parse_time_to_days(history) > 30:
                value_type = item.get('value_type', 'FLOAT')
                item_name = item.get('name', 'Unknown Item')
                
                # Only flag if it's not a critical monitoring item
                if not self._is_critical_item(item_name):
                    self.opportunities.append(OptimisationOpportunity(
                        template_name=template_name,
                        category="History Retention",
                        current_issue=f"Item '{item_name}' has {history} history retention",
                        recommendation=f"Reduce history to 7d or 14d for {value_type} items",
                        expected_benefit="50-80% storage reduction for this item",
                        risk_level="Low",
                        severity="Medium"
                    ))
    
    def _analyze_trends_retention(self, template_name: str, template: Dict[str, Any]):
        """Analyze trends retention settings."""
        items = self._get_all_items(template)
        
        for item in items:
            trends = item.get('trends', '365d')
            value_type = item.get('value_type', 'FLOAT')
            item_name = item.get('name', 'Unknown Item')
            
            # Check for TEXT/CHAR items with trends enabled
            if value_type in ['TEXT', 'CHAR', 'LOG'] and trends != '0':
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Trends Configuration",
                    current_issue=f"Item '{item_name}' ({value_type}) has trends enabled: {trends}",
                    recommendation="Disable trends for TEXT/CHAR/LOG items (set trends: '0')",
                    expected_benefit="Eliminate unnecessary trend calculations and storage",
                    risk_level="Low",
                    severity="High"
                ))
            
            # Check for excessively long trends retention
            elif self._parse_time_to_days(trends) > 365 and value_type in ['FLOAT', 'UINT64']:
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Trends Retention",
                    current_issue=f"Item '{item_name}' has {trends} trends retention",
                    recommendation="Reduce trends to 365d for most numeric items",
                    expected_benefit="30-50% trends storage reduction",
                    risk_level="Medium",
                    severity="Low"
                ))
    
    def _analyze_data_collection_intervals(self, template_name: str, template: Dict[str, Any]):
        """Analyze data collection intervals (delay settings)."""
        items = self._get_all_items(template)
        
        for item in items:
            delay = item.get('delay', '1m')
            item_name = item.get('name', 'Unknown Item')
            item_type = item.get('type', 'SNMP_AGENT')
            
            delay_seconds = self._parse_delay_to_seconds(delay)
            
            # Flag very frequent collection for slow-changing metrics
            if delay_seconds <= 30 and self._is_slow_changing_metric(item_name):
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Collection Frequency",
                    current_issue=f"Item '{item_name}' collected every {delay} (appears to be slow-changing)",
                    recommendation="Increase collection interval to 5m or 10m for slow-changing metrics",
                    expected_benefit="Reduce database writes by 90%, lower CPU usage",
                    risk_level="Low",
                    severity="Medium"
                ))
            
            # Flag external script items with high frequency
            elif item_type == 'EXTERNAL' and delay_seconds < 300:  # Less than 5 minutes
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="External Script Frequency",
                    current_issue=f"External script '{item_name}' runs every {delay}",
                    recommendation="Increase interval to 10m or 15m for external scripts",
                    expected_benefit="Reduce external script execution overhead",
                    risk_level="Medium",
                    severity="Medium"
                ))
    
    def _analyze_value_types(self, template_name: str, template: Dict[str, Any]):
        """Analyze value types for optimization opportunities."""
        items = self._get_all_items(template)
        
        for item in items:
            value_type = item.get('value_type', 'FLOAT')
            item_name = item.get('name', 'Unknown Item')
            
            # Check for TEXT items that could be numeric
            if value_type == 'TEXT' and self._could_be_numeric(item_name):
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Value Type Optimization",
                    current_issue=f"Item '{item_name}' uses TEXT but appears to be numeric",
                    recommendation="Change to FLOAT or UINT64 with appropriate units",
                    expected_benefit="Enable trends, reduce storage by 60-80%",
                    risk_level="Medium",
                    severity="Medium"
                ))
            
            # Check for CHAR items that could be smaller
            elif value_type == 'CHAR':
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Value Type Optimization",
                    current_issue=f"Item '{item_name}' uses CHAR type",
                    recommendation="Consider if this could be TEXT with trends=0 or numeric",
                    expected_benefit="Potentially reduce storage and enable better processing",
                    risk_level="Low",
                    severity="Low"
                ))
    
    def _analyze_preprocessing(self, template_name: str, template: Dict[str, Any]):
        """Analyze preprocessing steps for optimization opportunities."""
        items = self._get_all_items(template)
        
        for item in items:
            preprocessing = item.get('preprocessing', [])
            item_name = item.get('name', 'Unknown Item')
            
            # Count preprocessing steps
            if len(preprocessing) > 5:
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Preprocessing Complexity",
                    current_issue=f"Item '{item_name}' has {len(preprocessing)} preprocessing steps",
                    recommendation="Consider simplifying preprocessing or moving logic to external script",
                    expected_benefit="Reduce Zabbix server CPU usage during data collection",
                    risk_level="Medium",
                    severity="Medium"
                ))
            
            # Check for complex regex operations
            for step in preprocessing:
                if step.get('type') == 'REGEX' or step.get('type') == 'JAVASCRIPT':
                    self.opportunities.append(OptimisationOpportunity(
                        template_name=template_name,
                        category="Preprocessing Optimization",
                        current_issue=f"Item '{item_name}' uses {step.get('type')} preprocessing",
                        recommendation="Consider simpler preprocessing methods or external script processing",
                        expected_benefit="Reduce CPU overhead during data processing",
                        risk_level="Medium",
                        severity="Low"
                    ))
                    break
    
    def _analyze_item_counts(self, template_name: str, template: Dict[str, Any]):
        """Analyze total item counts and suggest optimizations."""
        items = self._get_all_items(template)
        item_count = len(items)
        
        # Count discovery rule prototypes
        discovery_rules = template.get('discovery_rules', [])
        prototype_count = 0
        for rule in discovery_rules:
            prototype_count += len(rule.get('item_prototypes', []))
        
        total_potential_items = item_count + prototype_count
        
        if total_potential_items > 100:
            self.opportunities.append(OptimisationOpportunity(
                template_name=template_name,
                category="Template Complexity",
                current_issue=f"Template has {item_count} items + {prototype_count} prototypes = {total_potential_items} potential items",
                recommendation="Consider splitting template or disabling unnecessary items",
                expected_benefit="Reduce template processing overhead and database load",
                risk_level="Medium",
                severity="Medium"
            ))
    
    def _analyze_text_items_without_trends(self, template_name: str, template: Dict[str, Any]):
        """Check TEXT items have trends disabled."""
        items = self._get_all_items(template)
        
        for item in items:
            value_type = item.get('value_type', 'FLOAT')
            trends = item.get('trends', '365d')
            item_name = item.get('name', 'Unknown Item')
            
            if value_type in ['TEXT', 'CHAR', 'LOG'] and trends != '0':
                self.opportunities.append(OptimisationOpportunity(
                    template_name=template_name,
                    category="Trends Configuration",
                    current_issue=f"TEXT item '{item_name}' has trends={trends}",
                    recommendation="Set trends: '0' for all TEXT/CHAR/LOG items",
                    expected_benefit="Prevent unnecessary trend calculation attempts",
                    risk_level="Low",
                    severity="High"
                ))
    
    def _get_all_items(self, template: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get all items from template including prototypes."""
        items = template.get('items', [])
        
        # Add discovery rule item prototypes
        for discovery_rule in template.get('discovery_rules', []):
            items.extend(discovery_rule.get('item_prototypes', []))
        
        return items
    
    def _parse_time_to_days(self, time_str: str) -> int:
        """Parse time string to days."""
        if not time_str or time_str == '0':
            return 0
        
        time_str = str(time_str).lower()
        
        # Extract number and unit
        if time_str.endswith('d'):
            return int(time_str[:-1])
        elif time_str.endswith('h'):
            return int(time_str[:-1]) // 24
        elif time_str.endswith('m'):
            return max(1, int(time_str[:-1]) // (24 * 60))
        elif time_str.endswith('s'):
            return max(1, int(time_str[:-1]) // (24 * 60 * 60))
        else:
            try:
                # Assume it's in seconds if no unit
                return max(1, int(time_str) // (24 * 60 * 60))
            except ValueError:
                return 90  # Default
    
    def _parse_delay_to_seconds(self, delay_str: str) -> int:
        """Parse delay string to seconds."""
        if not delay_str or delay_str == '0':
            return 0
        
        delay_str = str(delay_str).lower()
        
        if delay_str.endswith('s'):
            return int(delay_str[:-1])
        elif delay_str.endswith('m'):
            return int(delay_str[:-1]) * 60
        elif delay_str.endswith('h'):
            return int(delay_str[:-1]) * 3600
        elif delay_str.endswith('d'):
            return int(delay_str[:-1]) * 86400
        else:
            try:
                return int(delay_str)
            except ValueError:
                return 60  # Default 1 minute
    
    def _is_critical_item(self, item_name: str) -> bool:
        """Determine if an item is critical and needs longer history."""
        critical_keywords = [
            'uptime', 'availability', 'status', 'error', 'failure',
            'critical', 'alert', 'down', 'reachability'
        ]
        return any(keyword in item_name.lower() for keyword in critical_keywords)
    
    def _is_slow_changing_metric(self, item_name: str) -> bool:
        """Determine if a metric changes slowly."""
        slow_keywords = [
            'model', 'version', 'serial', 'firmware', 'hostname',
            'location', 'contact', 'description', 'name', 'type',
            'vendor', 'license', 'capacity', 'total'
        ]
        return any(keyword in item_name.lower() for keyword in slow_keywords)
    
    def _could_be_numeric(self, item_name: str) -> bool:
        """Determine if a TEXT item could be numeric."""
        numeric_keywords = [
            'count', 'total', 'number', 'size', 'length', 'time',
            'latency', 'response', 'duration', 'bytes', 'rate',
            'percentage', 'percent', 'utilization', 'usage'
        ]
        return any(keyword in item_name.lower() for keyword in numeric_keywords)

def main():
    """Main analysis function."""
    parser = argparse.ArgumentParser(
        description='Analyse Zabbix templates for database performance optimisation opportunities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Analyse all templates in default directory
  python analyze_template_optimization.py
  
  # Analyse a specific template file
  python analyze_template_optimization.py templates/aruba_wireless.yaml
  
  # Analyse all templates in a specific directory
  python analyze_template_optimization.py /path/to/templates/
  
  # Analyse multiple specific files
  python analyze_template_optimization.py templates/sonicwall*.yaml
'''
    )
    
    parser.add_argument(
        'path', 
        nargs='?',
        default=None,
        help='Path to template file, directory, or glob pattern (default: templates/ directory)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Output file for detailed report (markdown format)'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['console', 'markdown', 'csv'],
        default='console',
        help='Output format (default: console)'
    )
    
    args = parser.parse_args()
    
    # Determine template path(s) to analyse
    if args.path:
        template_path = Path(args.path)
        
        if template_path.is_file() and template_path.suffix.lower() in ['.yaml', '.yml']:
            # Single file
            template_files = [template_path]
        elif template_path.is_dir():
            # Directory - find all YAML files
            template_files = list(template_path.glob('*.yaml')) + list(template_path.glob('*.yml'))
        elif '*' in str(template_path) or '?' in str(template_path):
            # Glob pattern
            template_files = [Path(f) for f in glob.glob(str(template_path))]
        else:
            print(f"Error: Path '{args.path}' is not a valid file, directory, or glob pattern")
            sys.exit(1)
    else:
        # Default to templates directory relative to script location
        script_dir = Path(__file__).parent
        templates_dir = script_dir.parent / 'templates'
        if not templates_dir.exists():
            print(f"Error: Default templates directory not found: {templates_dir}")
            print("Please specify a path to analyse")
            sys.exit(1)
        template_files = list(templates_dir.glob('*.yaml')) + list(templates_dir.glob('*.yml'))
    
    if not template_files:
        print("No template files found to analyse")
        sys.exit(1)
    
    print(f"Analysing {len(template_files)} template file(s)...")
    
    # Analyse templates
    all_opportunities = []
    analysed_templates = []
    
    for template_file in template_files:
        print(f"Analysing: {template_file.name}")
        try:
            analyser = ZabbixTemplateAnalyser(str(template_file.parent))
            # Temporarily set to analyse just this file
            analyser.templates_dir = template_file.parent
            
            with open(template_file, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            
            analyser._analyse_template(template_file.name, template_data)
            all_opportunities.extend(analyser.opportunities)
            analysed_templates.append(template_file.stem)
            
        except Exception as e:
            print(f"Error analysing {template_file.name}: {e}")
    
    opportunities = all_opportunities
    
    # Sort opportunities by severity and risk
    severity_order = {'High': 3, 'Medium': 2, 'Low': 1}
    opportunities.sort(key=lambda x: (severity_order.get(x.severity, 0), x.template_name))
    
    if not opportunities:
        print("No optimisation opportunities found.")
        return
    
    # Generate report based on format
    if args.format == 'console' or not args.output:
        generate_console_report(opportunities, analysed_templates)
    
    if args.output:
        if args.format == 'markdown':
            generate_markdown_report(opportunities, analysed_templates, args.output)
        elif args.format == 'csv':
            generate_csv_report(opportunities, args.output)
        print(f"\nDetailed report saved to: {args.output}")


def generate_console_report(opportunities, analysed_templates):
    """Generate console output report."""
    print("\n" + "="*120)
    print("ZABBIX TEMPLATE DATABASE PERFORMANCE OPTIMISATION ANALYSIS")
    print("="*120)
    print(f"Total optimisation opportunities found: {len(opportunities)}")
    print(f"Templates analysed: {', '.join(analysed_templates)}")
    print()
    
    # Group by category
    categories = {}
    for opp in opportunities:
        if opp.category not in categories:
            categories[opp.category] = []
        categories[opp.category].append(opp)
    
    for category, opps in categories.items():
        print(f"\n{category.upper()} ({len(opps)} issues)")
        print("-" * 80)
        
        for opp in opps:
            print(f"Template: {opp.template_name}")
            print(f"Issue: {opp.current_issue}")
            print(f"Recommendation: {opp.recommendation}")
            print(f"Expected Benefit: {opp.expected_benefit}")
            print(f"Risk Level: {opp.risk_level} | Severity: {opp.severity}")
            print()
    
    # Summary statistics
    print("\n" + "="*120)
    print("SUMMARY STATISTICS")
    print("="*120)
    
    for category, opps in categories.items():
        high_severity = len([o for o in opps if o.severity == 'High'])
        medium_severity = len([o for o in opps if o.severity == 'Medium'])
        low_severity = len([o for o in opps if o.severity == 'Low'])
        
        print(f"{category}: {len(opps)} total (High: {high_severity}, Medium: {medium_severity}, Low: {low_severity})")
    
    print(f"\nTotal templates analysed: {len(set(opp.template_name for opp in opportunities))}")
    print(f"Templates with optimisation opportunities: {len(set(opp.template_name for opp in opportunities))}")


def generate_markdown_report(opportunities, analysed_templates, output_file):
    """Generate detailed markdown report."""
    from datetime import datetime
    
    report_content = f"""# Zabbix Template Database Performance Optimisation Analysis

**Generated:** {datetime.now().strftime('%d %B %Y at %H:%M')}
**Templates Analysed:** {', '.join(analysed_templates)}
**Total Optimisation Opportunities:** {len(opportunities)}

## Executive Summary

This analysis identifies database performance optimisation opportunities across the specified Zabbix templates.

### Key Findings by Severity
"""
    
    # Count by severity
    severity_counts = {}
    for opp in opportunities:
        severity_counts[opp.severity] = severity_counts.get(opp.severity, 0) + 1
    
    for severity, count in severity_counts.items():
        report_content += f"- **{severity} Priority**: {count} optimisations identified\n"
    
    report_content += "\n## Detailed Recommendations\n\n"
    
    # Group by template
    templates = {}
    for opp in opportunities:
        if opp.template_name not in templates:
            templates[opp.template_name] = []
        templates[opp.template_name].append(opp)
    
    for template_name, template_opps in templates.items():
        report_content += f"### {template_name}\n\n"
        
        for i, opp in enumerate(template_opps, 1):
            report_content += f"#### {i}. {opp.category}\n"
            report_content += f"**Severity:** {opp.severity} | **Risk:** {opp.risk_level}\n\n"
            report_content += f"**Current Issue:** {opp.current_issue}\n\n"
            report_content += f"**Recommendation:** {opp.recommendation}\n\n"
            report_content += f"**Expected Benefit:** {opp.expected_benefit}\n\n"
            report_content += "---\n\n"
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(report_content)


def generate_csv_report(opportunities, output_file):
    """Generate CSV report."""
    import csv
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Template', 'Category', 'Severity', 'Risk Level', 'Current Issue', 'Recommendation', 'Expected Benefit'])
        
        for opp in opportunities:
            writer.writerow([
                opp.template_name,
                opp.category,
                opp.severity,
                opp.risk_level,
                opp.current_issue,
                opp.recommendation,
                opp.expected_benefit
            ])

if __name__ == "__main__":
    main()
