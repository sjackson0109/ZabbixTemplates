#!/usr/bin/env python3
"""
Convert American English spellings to British English throughout the codebase.

This script searches through various file types in the project and replaces
common American English spellings with their British English equivalents.
Creates backups before making changes.

Examples:
    python convert_to_uk_english.py --what-if          # Preview changes
    python convert_to_uk_english.py                    # Apply changes
    python convert_to_uk_english.py --verbose          # Apply with details
    python convert_to_uk_english.py --backup-folder ./my_backups
    python convert_to_uk_english.py --root-path ../my_project
    python convert_to_uk_english.py --include-extensions .py,.js,.ts
"""

import os
import re
import argparse
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Set
import fnmatch
import yaml


class SpellingConverter:
    """Handles conversion from American to British English spellings."""
    
    def __init__(self, file_extensions: Set[str] = None):
        """Initialise the converter with configurable file extensions."""
        # File extensions to process (can be overridden)
        if file_extensions:
            self.file_extensions = file_extensions
        else:
            self.file_extensions = {'.ps1', '.psm1', '.md', '.txt', '.json', '.yaml', '.yml'}
        
        # Define American -> British spelling mappings
        self.stem_replacements = [
            # -ize to -ise (stem replacements)
            ('Utiliz', 'Utilis'),
            ('utiliz', 'utilis'),
            ('Normaliz', 'Normalis'),
            ('normaliz', 'normalis'),
            ('Initializ', 'Initialis'),
            ('initializ', 'initialis'),
            ('Optimiz', 'Optimis'),
            ('optimiz', 'optimis'),
            ('Organiz', 'Organis'),
            ('organiz', 'organis'),
            ('Authoriz', 'Authoris'),
            ('authoriz', 'authoris'),
            ('Specializ', 'Specialis'),
            ('specializ', 'specialis'),
            ('Recogniz', 'Recognis'),
            ('recogniz', 'recognis'),
            ('Synchroniz', 'Synchronis'),
            ('synchroniz', 'synchronis'),
            ('Analyz', 'Analys'),
            ('analyz', 'analys'),
            ('Categoriz', 'Categoris'),
            ('categoriz', 'categoris'),
            ('Customiz', 'Customis'),
            ('customiz', 'customis'),
            ('Moderniz', 'Modernis'),
            ('moderniz', 'modernis'),
        ]
        
        self.word_replacements = [
            # -or to -our (full words)
            ('Color', 'Colour'),
            ('color', 'colour'),
            ('Behavior', 'Behaviour'),
            ('behavior', 'behaviour'),
            ('Favor', 'Favour'),
            ('favor', 'favour'),
            ('Favorite', 'Favourite'),
            ('favorite', 'favourite'),
            ('Honor', 'Honour'),
            ('honor', 'honour'),
            ('Labor', 'Labour'),
            ('labor', 'labour'),
            ('Neighbor', 'Neighbour'),
            ('neighbor', 'neighbour'),
            
            # -er to -re (full words)
            ('Center', 'Centre'),
            ('center', 'centre'),
            ('Centered', 'Centred'),
            ('centered', 'centred'),
            ('Meter', 'Metre'),
            ('meter', 'metre'),
            ('Theater', 'Theatre'),
            ('theater', 'theatre'),
            
            # -og to -ogue (full words)
            ('Catalog', 'Catalogue'),
            ('catalog', 'catalogue'),
            ('Dialog', 'Dialogue'),
            ('dialog', 'dialogue'),
            
            # -ense to -ence (full words)
            ('Defense', 'Defence'),
            ('defense', 'defence'),
            ('License', 'Licence'),
            ('license', 'licence'),
            
            # -ll words (full words)
            ('Canceled', 'Cancelled'),
            ('canceled', 'cancelled'),
            ('Canceling', 'Cancelling'),
            ('canceling', 'cancelling'),
            ('Traveled', 'Travelled'),
            ('traveled', 'travelled'),
            ('Traveling', 'Travelling'),
            ('traveling', 'travelling'),
            ('Labeled', 'Labelled'),
            ('labeled', 'labelled'),
            ('Labeling', 'Labelling'),
            ('labeling', 'labelling'),
        ]
        
        # Words that should NOT be replaced when in quotes (framework/API terms)
        self.quoted_exclusions = {
            'Center', 'center', 'Centered', 'centered', 
            'Color', 'color', 'Behavior', 'behavior'
        }
        
        # File extensions to process
        self.file_extensions = {'.ps1', '.psm1', '.md', '.txt', '.json', '.yaml', '.yml'}
    
    def is_in_quotes(self, text: str, position: int) -> bool:
        """Check if position is within quotes (single or double)."""
        before_text = text[:position]
        
        # Count quotes before position
        double_quotes = before_text.count('"') % 2 == 1
        single_quotes = before_text.count("'") % 2 == 1
        
        return double_quotes or single_quotes
    
    def is_in_filename(self, text: str, position: int) -> bool:
        """Check if position is within a filename pattern."""
        # Look for common filename patterns around the position
        start = max(0, position - 50)
        end = min(len(text), position + 50)
        context = text[start:end]
        
        # Find the word at position
        word_start = position - start
        while word_start > 0 and context[word_start - 1].isalnum():
            word_start -= 1
        word_end = word_start
        while word_end < len(context) and (context[word_end].isalnum() or context[word_end] in '_.-'):
            word_end += 1
        
        # Check if this looks like a filename
        word = context[word_start:word_end]
        
        # Patterns that suggest this is a filename
        filename_indicators = [
            r'\w+\.(yaml|yml|md|py|ps1|txt|json|html|css|js)$',  # Has file extension
            r'^[a-zA-Z0-9_.-]+\.(yaml|yml|md|py|ps1|txt|json|html|css|js)',  # Starts with filename
            r'`[^`]*$',  # Inside backticks (code)
            r'file.*\.yaml',  # Mentioned as a file
            r'script.*\.py',  # Mentioned as a script
        ]
        
        for pattern in filename_indicators:
            if re.search(pattern, word, re.IGNORECASE):
                return True
        
        return False
    
    def is_in_hyperlink(self, text: str, position: int) -> bool:
        """Check if position is within a markdown hyperlink."""
        # Look for markdown link patterns around the position
        start = max(0, position - 100)
        end = min(len(text), position + 100)
        context = text[start:end]
        relative_pos = position - start
        
        # Check for markdown link patterns: [text](url) or ![alt](url)
        link_patterns = [
            r'\[([^\]]*)\]\(([^)]*)\)',  # [text](url)
            r'!\[([^\]]*)\]\(([^)]*)\)', # ![alt](url)
            r'<([^>]+)>',               # <url>
            r'https?://[^\s\])\}]+',    # Raw URLs
        ]
        
        for pattern in link_patterns:
            for match in re.finditer(pattern, context):
                if match.start() <= relative_pos <= match.end():
                    return True
        
        return False
    
    def apply_stem_replacements(self, content: str) -> Tuple[str, List[str]]:
        """Apply stem-based replacements (e.g., 'utiliz*' -> 'utilis*')."""
        details = []
        
        for american_stem, british_stem in self.stem_replacements:
            # Pattern: word boundary + stem + word characters
            pattern = rf'\b{re.escape(american_stem)}(\w+)\b'
            
            def replace_match(match):
                full_word = match.group(0)
                suffix = match.group(1)
                british_word = british_stem + suffix
                
                # Only replace if not already British
                if full_word != british_word:
                    return british_word
                return full_word
            
            original_content = content
            content = re.sub(pattern, replace_match, content)
            
            # Count actual replacements
            if content != original_content:
                matches = len(re.findall(pattern, original_content))
                details.append(f"  {american_stem}* -> {british_stem}* ({matches} times)")
        
        return content, details
    
    def apply_word_replacements(self, content: str) -> Tuple[str, List[str]]:
        """Apply full word replacements."""
        details = []
        
        for american, british in self.word_replacements:
            pattern = rf'\b{re.escape(american)}\b'
            
            # Enhanced replacement function that checks multiple exclusion types
            def replace_with_exclusions(match):
                pos = match.start()
                
                # Check various exclusion conditions
                if self.is_in_quotes(content, pos):
                    return match.group(0)  # Skip quoted text
                if self.is_in_filename(content, pos):
                    return match.group(0)  # Skip filenames
                if self.is_in_hyperlink(content, pos):
                    return match.group(0)  # Skip hyperlinks
                
                return british
            
            original_content = content
            content = re.sub(pattern, replace_with_exclusions, content)
            
            if content != original_content:
                # Count actual replacements (excluding skipped ones)
                count = 0
                for match in re.finditer(pattern, original_content):
                    pos = match.start()
                    if (not self.is_in_quotes(original_content, pos) and 
                        not self.is_in_filename(original_content, pos) and
                        not self.is_in_hyperlink(original_content, pos)):
                        count += 1
                
                if count > 0:
                    exclusion_notes = []
                    if american in self.quoted_exclusions:
                        exclusion_notes.append("quoted")
                    exclusion_notes.extend(["filenames", "hyperlinks"])
                    exclusion_text = f", excluding {', '.join(exclusion_notes)}" if exclusion_notes else ""
                    details.append(f"  {american} -> {british} ({count} times{exclusion_text})")
        
        return content, details
    
    def convert_yaml_values(self, data, details_list):
        """Recursively convert American spellings in YAML values only."""
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    original_value = value
                    # Apply stem replacements
                    for american_stem, british_stem in self.stem_replacements:
                        pattern = rf'\b{re.escape(american_stem)}(\w+)\b'
                        def replace_match(match):
                            full_word = match.group(0)
                            suffix = match.group(1)
                            british_word = british_stem + suffix
                            if full_word != british_word:
                                return british_word
                            return full_word
                        new_value = re.sub(pattern, replace_match, value)
                        if new_value != value:
                            matches = len(re.findall(pattern, value))
                            details_list.append(f"  {american_stem}* -> {british_stem}* ({matches} times in values)")
                            value = new_value
                    
                    # Apply word replacements
                    for american, british in self.word_replacements:
                        pattern = rf'\b{re.escape(american)}\b'
                        if american in self.quoted_exclusions:
                            # Skip quoted exclusions in YAML values for now
                            continue
                        else:
                            matches = len(re.findall(pattern, value))
                            if matches > 0:
                                value = re.sub(pattern, british, value)
                                details_list.append(f"  {american} -> {british} ({matches} times in values)")
                    
                    # Update the value if it changed
                    if value != original_value:
                        data[key] = value
                else:
                    # Recurse into nested structures
                    self.convert_yaml_values(value, details_list)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, str):
                    original_item = item
                    # Apply same conversions as above
                    for american_stem, british_stem in self.stem_replacements:
                        pattern = rf'\b{re.escape(american_stem)}(\w+)\b'
                        def replace_match(match):
                            full_word = match.group(0)
                            suffix = match.group(1)
                            british_word = british_stem + suffix
                            if full_word != british_word:
                                return british_word
                            return full_word
                        new_item = re.sub(pattern, replace_match, item)
                        if new_item != item:
                            matches = len(re.findall(pattern, item))
                            details_list.append(f"  {american_stem}* -> {british_stem}* ({matches} times in values)")
                            item = new_item
                    
                    for american, british in self.word_replacements:
                        pattern = rf'\b{re.escape(american)}\b'
                        if american not in self.quoted_exclusions:
                            matches = len(re.findall(pattern, item))
                            if matches > 0:
                                item = re.sub(pattern, british, item)
                                details_list.append(f"  {american} -> {british} ({matches} times in values)")
                    
                    if item != original_item:
                        data[i] = item
                else:
                    self.convert_yaml_values(item, details_list)
    
    def convert_file(self, file_path: Path) -> Tuple[str, int, List[str]]:
        """Convert a single file and return new content, replacement count, and details."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            with open(file_path, 'r', encoding='latin-1') as f:
                original_content = f.read()
        
        all_details = []
        
        # Handle YAML files specially to preserve structure and only modify values
        if file_path.suffix.lower() in {'.yaml', '.yml'}:
            try:
                # Parse YAML
                yaml_data = yaml.safe_load(original_content)
                if yaml_data is not None:
                    # Convert only values, not keys
                    self.convert_yaml_values(yaml_data, all_details)
                    # Convert back to YAML string
                    content = yaml.dump(yaml_data, default_flow_style=False, allow_unicode=True, sort_keys=False)
                else:
                    content = original_content
            except yaml.YAMLError:
                # If YAML parsing fails, fall back to text replacement
                content = original_content
                content, stem_details = self.apply_stem_replacements(content)
                all_details.extend(stem_details)
                content, word_details = self.apply_word_replacements(content)
                all_details.extend(word_details)
        else:
            # For non-YAML files, use text-based replacement
            content = original_content
            content, stem_details = self.apply_stem_replacements(content)
            all_details.extend(stem_details)
            content, word_details = self.apply_word_replacements(content)
            all_details.extend(word_details)
        
        # Count total replacements
        replacement_count = len(all_details)
        
        return content, replacement_count, all_details


def find_files_to_process(root_path: Path, extensions: Set[str], exclude_patterns: List[str]) -> List[Path]:
    """Find all files to process, excluding specified patterns."""
    files_to_process = []
    
    for file_path in root_path.rglob('*'):
        if not file_path.is_file():
            continue
        
        # Check extension
        if file_path.suffix.lower() not in extensions:
            continue
        
        # Check exclusion patterns
        relative_path = str(file_path.relative_to(root_path))
        excluded = False
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(relative_path, pattern) or pattern in str(file_path):
                excluded = True
                break
        
        if not excluded:
            files_to_process.append(file_path)
    
    return files_to_process


def create_backup(file_path: Path, backup_root: Path, project_root: Path) -> Path:
    """Create a backup of the file."""
    # Calculate relative path from project root
    relative_path = file_path.relative_to(project_root)
    
    backup_path = backup_root / relative_path
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    
    shutil.copy2(file_path, backup_path)
    return backup_path


def main():
    parser = argparse.ArgumentParser(
        description='Convert American English spellings to British English',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--backup-folder',
        type=str,
        help='Optional folder to store backups (default: Backups/UKEnglish_[timestamp])'
    )
    parser.add_argument(
        '--what-if',
        action='store_true',
        help='Show what would be changed without making actual changes'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed replacement information'
    )
    parser.add_argument(
        '--root-path',
        type=str,
        help='Root directory to search for files (default: parent of script directory)'
    )
    parser.add_argument(
        '--include-extensions',
        type=str,
        help='Comma-separated list of file extensions to process (e.g., .py,.js,.md)'
    )
    parser.add_argument(
        '--exclude-patterns',
        type=str,
        help='Comma-separated list of exclude patterns (e.g., */.git/*,*/node_modules/*)'
    )
    
    args = parser.parse_args()
    
    # Set up paths
    script_dir = Path(__file__).parent
    if args.root_path:
        project_root = Path(args.root_path).resolve()
        if not project_root.exists():
            print(f"Error: Root path '{project_root}' does not exist")
            return 1
        if not project_root.is_dir():
            print(f"Error: Root path '{project_root}' is not a directory")
            return 1
    else:
        project_root = script_dir.parent
    
    # Create backup folder
    if args.backup_folder:
        backup_folder = Path(args.backup_folder).resolve()
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_folder = script_dir / f'Backups/UKEnglish_{timestamp}'
    
    if not args.what_if and not backup_folder.exists():
        backup_folder.mkdir(parents=True, exist_ok=True)
        print(f"Created backup folder: {backup_folder}")
    
    # Parse file extensions
    file_extensions = None
    if args.include_extensions:
        extensions = [ext.strip() for ext in args.include_extensions.split(',')]
        # Ensure extensions start with '.'
        file_extensions = {ext if ext.startswith('.') else f'.{ext}' for ext in extensions}
    
    # Initialize converter
    converter = SpellingConverter(file_extensions)
    
    # Parse exclude patterns
    exclude_patterns = [
        '*/Backups/*',
        '*/.git/*',
        '*/.venv/*',
        '*/node_modules/*',
        '*/__pycache__/*',
        '*.pyc',
        'convert_to_uk_english.py'  # Exclude this script
    ]
    
    if args.exclude_patterns:
        additional_excludes = [pattern.strip() for pattern in args.exclude_patterns.split(',')]
        exclude_patterns.extend(additional_excludes)
    
    files_to_process = find_files_to_process(project_root, converter.file_extensions, exclude_patterns)
    
    print(f"\nFound {len(files_to_process)} files to process")
    print("Searching for American English spellings...\n")
    
    total_replacements = 0
    files_modified = 0
    
    for i, file_path in enumerate(files_to_process, 1):
        content, replacement_count, details = converter.convert_file(file_path)
        
        if replacement_count > 0:
            files_modified += 1
            total_replacements += replacement_count
            
            relative_path = file_path.relative_to(project_root)
            
            if args.what_if:
                if args.verbose and details:
                    print(f"\n{relative_path}:")
                    for detail in details:
                        print(f"  Would replace: {detail}")
                print(f"[{files_modified}] {relative_path}")
                print(f"    Would make {replacement_count} replacement(s)")
            else:
                print(f"[{files_modified}] {relative_path}")
                print(f"    {replacement_count} replacement(s)")
                
                if args.verbose and details:
                    for detail in details:
                        print(f"    {detail}")
                
                # Create backup and write updated file
                try:
                    create_backup(file_path, backup_folder, project_root)
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception as e:
                    print(f"    Error: {e}")
    
    # Summary
    print("\n" + "=" * 50)
    print("SUMMARY")
    print("=" * 50)
    
    if args.what_if:
        print("WhatIf Mode: No files were modified")
        print(f"Would modify: {files_modified} files")
        print(f"Would make: {total_replacements} total replacements")
    else:
        print(f"Modified: {files_modified} files")
        print(f"Total replacements: {total_replacements}")
        if files_modified > 0:
            print(f"Backups saved to: {backup_folder}")
    
    print("\nDone!")


if __name__ == '__main__':
    main()