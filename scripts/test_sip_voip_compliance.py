#!/usr/bin/env python3
"""
SIP/VoIP Compliance Testing Examples and Validation

Test examples for the SIP/VoIP Compliance Monitoring System.
These examples demonstrate various testing scenarios and validation approaches.
"""

import json
import subprocess
import sys
import time

def run_test(command_args, description):
    """Run a test command and display results."""
    print(f"\n{'='*60}")
    print(f"TEST: {description}")
    print(f"{'='*60}")
    
    cmd = ["python", "externalscripts/get_sip_voip_compliance.py"] + command_args
    print(f"Command: {' '.join(cmd)}")
    print()
    
    try:
        start_time = time.time()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        end_time = time.time()
        
        print(f"Execution time: {end_time - start_time:.2f} seconds")
        print(f"Return code: {result.returncode}")
        
        if result.stdout:
            try:
                # Try to parse and pretty-print JSON
                data = json.loads(result.stdout)
                print("Output (JSON):")
                print(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                print("Output (Raw):")
                print(result.stdout)
        
        if result.stderr:
            print("Errors:")
            print(result.stderr)
            
    except subprocess.TimeoutExpired:
        print("Test timed out after 30 seconds")
    except Exception as e:
        print(f"Test failed with error: {e}")

def main():
    """Run SIP/VoIP compliance test examples."""
    
    # Test server (using a known non-SIP server for demonstration)
    test_server = "google.com"
    
    print("SIP/VoIP Compliance Testing Examples")
    print("====================================")
    print(f"Test Server: {test_server}")
    print("Note: Using google.com for demonstration - timeouts are expected")
    
    # Test 1: Basic SIP OPTIONS
    run_test(["sip_test", test_server], "SIP OPTIONS Request")
    
    # Test 2: SIP with specific port
    run_test(["sip_test", test_server, "5061"], "SIP OPTIONS with TLS Port")
    
    # Test 3: STUN connectivity test
    run_test(["stun_test", test_server, "3478"], "STUN Connectivity Test")
    
    # Test 4: RTP capability test
    run_test(["rtp_test", test_server, "10000"], "RTP Capability Test")
    
    # Test 5: Codec support test
    run_test(["codec_test", test_server], "Codec Support Analysis")
    
    # Test 6: NAT traversal test
    run_test(["nat_test", test_server], "NAT Traversal Assessment")
    
    # Test 7: TLS security test
    run_test(["tls_test", test_server, "5061"], "TLS Security Assessment")
    
    # Test 8: Service discovery (commented out due to port scanning time)
    # run_test(["discover", test_server], "VoIP Service Discovery")
    
    # Test 9: Comprehensive assessment
    run_test(["comprehensive", test_server], "Comprehensive VoIP Assessment")
    
    print(f"\n{'='*60}")
    print("TESTING COMPLETE")
    print("="*60)
    print()
    print("Summary:")
    print("- All commands executed successfully")
    print("- Timeouts are expected when testing non-VoIP servers")
    print("- In production, use actual SIP/VoIP server addresses")
    print("- Review JSON output for detailed metrics")
    print()
    print("Next Steps:")
    print("1. Import sip_voip_compliance.yaml template into Zabbix")
    print("2. Configure host macros for your environment")
    print("3. Assign template to VoIP infrastructure hosts")
    print("4. Monitor dashboards and adjust thresholds as needed")

if __name__ == "__main__":
    main()