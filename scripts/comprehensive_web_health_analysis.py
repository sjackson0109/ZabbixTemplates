#!/usr/bin/env python3
"""
Comprehensive Analysis and Summary Report
Analyzes the 50-test suite results and provides actionable insights
"""

import json
import sys
from datetime import datetime

def load_test_results():
    """Load the test results from JSON file"""
    try:
        with open('/root/test/test_results_20260106_125048.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print("❌ Test results file not found!")
        sys.exit(1)

def analyze_functionality_coverage(results):
    """Analyze what functionality was successfully tested"""
    print("📊 FUNCTIONALITY COVERAGE ANALYSIS")
    print("=" * 80)
    
    categories = {
        'Core Operations': ['Basic'],
        'Protocol Support': ['HTTP'],
        'Security Analysis': ['OWASP', 'Security'],
        'Infrastructure Analysis': ['CDN', 'SSL'],
        'Advanced Features': ['HTTP3', 'Compliance'],
        'Performance Monitoring': ['Performance'],
        'Error Handling': ['Error'],
        'CLI Integration': ['CLI']
    }
    
    for category, keywords in categories.items():
        total_tests = sum(1 for k in results.keys() if any(kw in k for kw in keywords))
        successful_tests = sum(1 for k, v in results.items() 
                             if any(kw in k for kw in keywords) and v['success'])
        
        if total_tests > 0:
            success_rate = (successful_tests / total_tests) * 100
            status = "✅" if success_rate >= 90 else "⚠️" if success_rate >= 70 else "❌"
            print(f"   {status} {category}: {successful_tests}/{total_tests} tests ({success_rate:.1f}%)")

def analyze_security_findings(results):
    """Deep dive into security analysis results"""
    print("\n🔒 SECURITY ANALYSIS DEEP DIVE")
    print("=" * 80)
    
    # OWASP Analysis
    owasp_tests = {k: v for k, v in results.items() if 'OWASP' in k and v['success']}
    print(f"\n🛡️  OWASP Top 10 Analysis ({len(owasp_tests)} sites tested):")
    
    for test_name, result in owasp_tests.items():
        site = test_name.split('_')[-1].upper()
        owasp_data = result['result']
        
        # Extract key security metrics
        overall_score = owasp_data.get('overall_score', 0)
        vulnerabilities = owasp_data.get('vulnerabilities_detected', 0)
        risk_level = owasp_data.get('risk_level', 'UNKNOWN')
        
        # Security status indicator
        if overall_score >= 90:
            status = "🟢"
        elif overall_score >= 70:
            status = "🟡"
        else:
            status = "🔴"
            
        print(f"   {status} {site}: Security Score {overall_score}/100 ({risk_level} risk)")
        
        # Show specific findings if available
        findings = owasp_data.get('detailed_findings', {})
        high_risk_found = False
        for vuln_type, details in findings.items():
            if details.get('risk_level') == 'HIGH':
                print(f"     ⚠️  HIGH RISK: {vuln_type} - {details.get('description', 'No details')[:60]}...")
                high_risk_found = True
        
        if not high_risk_found and findings:
            print(f"     ✅ No high-risk vulnerabilities detected")

def analyze_performance_insights(results):
    """Analyze performance characteristics"""
    print("\n⚡ PERFORMANCE ANALYSIS")
    print("=" * 80)
    
    perf_tests = {k: v for k, v in results.items() if 'Performance' in k and v['success']}
    
    if not perf_tests:
        print("   No performance data available")
        return
    
    response_times = []
    site_performance = {}
    
    for test_name, result in perf_tests.items():
        site = test_name.split('_')[-1].upper()
        perf_data = result['result']
        
        response_time = perf_data.get('response_time', 0)
        status_code = perf_data.get('status_code', 0)
        content_length = perf_data.get('content_length', 0)
        
        response_times.append(response_time)
        site_performance[site] = {
            'response_time': response_time,
            'status_code': status_code,
            'content_length': content_length
        }
    
    # Performance statistics
    if response_times:
        avg_time = sum(response_times) / len(response_times)
        min_time = min(response_times)
        max_time = max(response_times)
        
        print(f"📈 Overall Performance Statistics:")
        print(f"   Average Response Time: {avg_time:.3f}s")
        print(f"   Fastest Response: {min_time:.3f}s")
        print(f"   Slowest Response: {max_time:.3f}s")
        
        # Performance categories
        fast_sites = [site for site, data in site_performance.items() 
                     if data['response_time'] < 0.1]
        medium_sites = [site for site, data in site_performance.items() 
                       if 0.1 <= data['response_time'] < 0.3]
        slow_sites = [site for site, data in site_performance.items() 
                     if data['response_time'] >= 0.3]
        
        if fast_sites:
            print(f"   🚀 Fast Sites (<100ms): {', '.join(fast_sites)}")
        if medium_sites:
            print(f"   🟡 Medium Sites (100-300ms): {', '.join(medium_sites)}")
        if slow_sites:
            print(f"   🐌 Slower Sites (>300ms): {', '.join(slow_sites)}")

def analyze_infrastructure_detection(results):
    """Analyze CDN and infrastructure detection"""
    print("\n🌐 INFRASTRUCTURE ANALYSIS")
    print("=" * 80)
    
    cdn_tests = {k: v for k, v in results.items() if 'CDN' in k and v['success']}
    
    if not cdn_tests:
        print("   No CDN detection data available")
        return
    
    cdn_providers = {}
    proxy_detected = []
    
    for test_name, result in cdn_tests.items():
        site = test_name.split('_')[-1].upper()
        cdn_data = result['result']
        
        detected = cdn_data.get('cdn_detected', False)
        provider = cdn_data.get('cdn_provider', 'None')
        proxy = cdn_data.get('proxy_detected', False)
        
        if detected and provider != 'None':
            if provider not in cdn_providers:
                cdn_providers[provider] = []
            cdn_providers[provider].append(site)
        
        if proxy:
            proxy_detected.append(site)
    
    print(f"📡 CDN Provider Distribution:")
    if cdn_providers:
        for provider, sites in cdn_providers.items():
            print(f"   {provider}: {', '.join(sites)} ({len(sites)} sites)")
    else:
        print("   No CDN providers detected")
    
    if proxy_detected:
        print(f"🔄 Proxy Detection: {', '.join(proxy_detected)}")
    else:
        print("🔄 No proxy servers detected")

def analyze_protocol_support(results):
    """Analyze HTTP protocol version support"""
    print("\n📡 HTTP PROTOCOL ANALYSIS")
    print("=" * 80)
    
    http_tests = {k: v for k, v in results.items() if 'HTTP_Versions' in k and v['success']}
    
    if not http_tests:
        print("   No HTTP version data available")
        return
    
    protocol_support = {
        'HTTP/1.0': [],
        'HTTP/1.1': [],
        'HTTP/2.0': [],
        'HTTP/3.0': []
    }
    
    for test_name, result in http_tests.items():
        site = test_name.split('_')[-1].upper()
        version_data = result['result'].get('version_support', {})
        
        for protocol, details in version_data.items():
            # Convert protocol format: HTTP_1_0 -> HTTP/1.0
            if protocol == 'HTTP_1_0':
                protocol_name = 'HTTP/1.0'
            elif protocol == 'HTTP_1_1':
                protocol_name = 'HTTP/1.1'
            elif protocol == 'HTTP_2_0':
                protocol_name = 'HTTP/2.0'
            else:
                continue  # Skip unknown protocols
                
            if details.get('supported', False):
                protocol_support[protocol_name].append(site)
    
    print("📊 Protocol Version Support:")
    for protocol, sites in protocol_support.items():
        if sites:
            print(f"   {protocol}: {', '.join(sites)} ({len(sites)} sites)")
        else:
            print(f"   {protocol}: No sites detected")
    
    # HTTP/2 analysis
    http2_tests = {k: v for k, v in results.items() if 'HTTP3' in k and v['success']}
    if http2_tests:
        print(f"\n🚀 HTTP/3 Support Analysis:")
        for test_name, result in http2_tests.items():
            site = test_name.split('_')[-1].upper()
            http3_data = result['result']
            supported = http3_data.get('supported', False)
            method = http3_data.get('detection_method', 'Unknown')
            print(f"   {site}: {'✅ Supported' if supported else '❌ Not supported'} (via {method})")

def generate_recommendations(results):
    """Generate actionable recommendations based on test results"""
    print("\n💡 RECOMMENDATIONS & NEXT STEPS")
    print("=" * 80)
    
    recommendations = []
    
    # Check for failed tests
    failed_tests = [k for k, v in results.items() if not v['success']]
    if failed_tests:
        recommendations.append("🔧 URGENT: Address failed tests to ensure monitoring reliability")
        for test in failed_tests[:3]:  # Show first 3 failed tests
            recommendations.append(f"   → Fix: {test}")
    
    # Performance recommendations
    perf_tests = {k: v for k, v in results.items() if 'Performance' in k and v['success']}
    slow_sites = []
    for test_name, result in perf_tests.items():
        site = test_name.split('_')[-1]
        if result['result'].get('response_time', 0) > 0.3:
            slow_sites.append(site)
    
    if slow_sites:
        recommendations.append(f"⚡ PERFORMANCE: Optimize slow responding sites: {', '.join(slow_sites)}")
        recommendations.append("   → Consider CDN implementation or server optimization")
    
    # HTTP/2 recommendations
    http_tests = {k: v for k, v in results.items() if 'HTTP_Versions' in k and v['success']}
    no_http2_sites = []
    for test_name, result in http_tests.items():
        site = test_name.split('_')[-1]
        version_data = result['result'].get('version_support', {})
        if not version_data.get('HTTP_2_0', {}).get('supported', False):
            no_http2_sites.append(site)
    
    if no_http2_sites:
        recommendations.append(f"📡 PROTOCOL: Enable HTTP/2 support for: {', '.join(no_http2_sites)}")
        recommendations.append("   → HTTP/2 provides significant performance improvements")
    
    # Security recommendations
    owasp_tests = {k: v for k, v in results.items() if 'OWASP' in k and v['success']}
    low_security_sites = []
    for test_name, result in owasp_tests.items():
        site = test_name.split('_')[-1]
        score = result['result'].get('overall_score', 0)
        if score < 70:
            low_security_sites.append(site)
    
    if low_security_sites:
        recommendations.append(f"🔒 SECURITY: Improve security posture for: {', '.join(low_security_sites)}")
        recommendations.append("   → Implement security headers and OWASP guidelines")
    
    # Monitoring recommendations
    recommendations.append("📊 MONITORING: Deploy enhanced Zabbix template for continuous monitoring")
    recommendations.append("🔄 AUTOMATION: Schedule regular security and performance assessments")
    recommendations.append("📈 METRICS: Establish baseline performance and security metrics")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i:2d}. {rec}")

def main():
    """Main analysis execution"""
    print("🔍 COMPREHENSIVE TEST RESULTS ANALYSIS")
    print(f"📅 Analysis generated at: {datetime.now().isoformat()}")
    print("=" * 80)
    
    # Load results
    results = load_test_results()
    
    # Execute all analysis functions
    analyze_functionality_coverage(results)
    analyze_security_findings(results)
    analyze_performance_insights(results)
    analyze_infrastructure_detection(results)
    analyze_protocol_support(results)
    generate_recommendations(results)
    
    # Final summary
    total_tests = len(results)
    successful_tests = sum(1 for v in results.values() if v['success'])
    success_rate = (successful_tests / total_tests) * 100
    
    print(f"\n" + "=" * 80)
    print(f"📋 FINAL SUMMARY")
    print(f"   Total Functionality Tests: {total_tests}")
    print(f"   Successful Tests: {successful_tests} ({success_rate:.1f}%)")
    print(f"   Failed Tests: {total_tests - successful_tests}")
    
    if success_rate >= 95:
        print("   🏆 EXCELLENT: Web health monitoring system is highly functional")
    elif success_rate >= 90:
        print("   ✅ GOOD: Minor issues to address for optimal performance")
    elif success_rate >= 80:
        print("   ⚠️  WARNING: Several issues need attention")
    else:
        print("   ❌ CRITICAL: Significant functionality problems detected")
    
    print(f"=" * 80)

if __name__ == "__main__":
    main()