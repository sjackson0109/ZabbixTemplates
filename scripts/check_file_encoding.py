#!/usr/bin/env python3
"""
Check YAML file encoding and line endings for Zabbix templates
"""
import os
import sys
import glob

def check_file_encoding_and_lineendings(filepath):
    """Check if file has BOM and what line endings it uses"""
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Check for UTF-8 BOM
    has_bom = content.startswith(b'\xef\xbb\xbf')
    
    # Check line endings
    text_content = content.decode('utf-8-sig' if has_bom else 'utf-8')
    
    if '\r\n' in text_content:
        line_ending = 'CRLF (Windows)'
    elif '\n' in text_content:
        line_ending = 'LF (Unix)'
    else:
        line_ending = 'Unknown'
    
    return has_bom, line_ending

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_file_encoding.py <pattern>")
        print("Example: python check_file_encoding.py templates/*.yaml")
        sys.exit(1)
    
    pattern = sys.argv[1]
    files = glob.glob(pattern)
    
    print("File Encoding and Line Ending Report")
    print("=" * 60)
    
    files_with_bom = []
    files_with_crlf = []
    files_with_lf = []
    
    for filepath in sorted(files):
        filename = os.path.basename(filepath)
        has_bom, line_ending = check_file_encoding_and_lineendings(filepath)
        
        encoding_str = "UTF-8 with BOM" if has_bom else "UTF-8 without BOM"
        print(f"{filename:30} | {encoding_str:18} | {line_ending}")
        
        if has_bom:
            files_with_bom.append(filename)
        
        if 'CRLF' in line_ending:
            files_with_crlf.append(filename)
        elif 'LF' in line_ending:
            files_with_lf.append(filename)
    
    print("\n" + "=" * 60)
    print("SUMMARY:")
    print(f"Files with BOM: {len(files_with_bom)}")
    print(f"Files with CRLF: {len(files_with_crlf)}")
    print(f"Files with LF: {len(files_with_lf)}")
    
    print("\n" + "=" * 60)
    print("RECOMMENDATIONS:")
    print("1. ENCODING: Zabbix prefers UTF-8 WITHOUT BOM")
    print("   - BOM can cause parsing issues in some versions")
    print("   - Files with BOM:", ", ".join(files_with_bom) if files_with_bom else "None")
    
    print("\n2. LINE ENDINGS: LF (Unix) is recommended for consistency")
    print("   - Git can handle conversion automatically")
    print("   - Mixed line endings can cause diff/merge issues")
    print("   - Files with CRLF:", ", ".join(files_with_crlf[:5]) if files_with_crlf else "None", 
          f"... and {len(files_with_crlf)-5} more" if len(files_with_crlf) > 5 else "")

if __name__ == "__main__":
    main()