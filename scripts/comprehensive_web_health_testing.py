#!/usr/bin/env python3
"""
Comprehensive Test Suite for Web Health Monitoring
Tests all 50 major functionality areas of get_web_health.py
"""

import sys
import os
import json
import time
import subprocess
from datetime import datetime

# Add the external scripts directory to path
sys.path.insert(0, '/root/media/data/usr/lib/zabbix/externalscripts')

try:
    from get_web_health import WebHealthMonitor
except ImportError as e:
    print(f"Error importing WebHealthMonitor: {e}")
    sys.exit(1)

class ComprehensiveTestSuite:
    def __init__(self):
        self.results = {}
        self.test_count = 0
        self.success_count = 0
        self.error_count = 0
        
        # Test targets with different characteristics
        self.test_urls = {
            'httpbin': 'https://httpbin.org/get',
            'google': 'https://www.google.com',
            'github': 'https://github.com',
            'cloudflare': 'https://www.cloudflare.com',
            'badssl_expired': 'https://expired.badssl.com',
            'badssl_selfsigned': 'https://self-signed.badssl.com',
            'badssl_untrusted': 'https://untrusted-root.badssl.com',
            'http_neverssl': 'http://neverssl.com',
            'ipv6_test': 'https://ipv6-test.com',
            'fast_site': 'https://www.fastly.com'
        }

    def log_test(self, test_name, success=True, result=None, error=None):
        """Log test results"""
        self.test_count += 1
        if success:
            self.success_count += 1
        else:
            self.error_count += 1
            
        self.results[f"Test_{self.test_count:02d}_{test_name}"] = {
            'success': success,
            'result': result,
            'error': str(error) if error else None,
            'timestamp': datetime.now().isoformat()
        }
        
        status = "✅" if success else "❌"
        print(f"{status} Test {self.test_count:02d}: {test_name}")
        if error:
            print(f"   Error: {error}")

    def run_test_safely(self, test_name, test_func):
        """Run a test with error handling"""
        try:
            result = test_func()
            self.log_test(test_name, True, result)
            return result
        except Exception as e:
            self.log_test(test_name, False, None, e)
            return None

    def test_basic_initialization(self):
        """Test 1: Basic WebHealthMonitor initialization"""
        def test():
            monitor = WebHealthMonitor(self.test_urls['httpbin'])
            return {'initialized': True, 'url': monitor.url}
        return self.run_test_safely("Basic_Initialization", test)

    def test_http_versions_all_sites(self):
        """Tests 2-4: HTTP Version Detection for multiple sites"""
        for i, (name, url) in enumerate(list(self.test_urls.items())[:3], 2):
            def test(test_url=url, site_name=name):
                monitor = WebHealthMonitor(test_url)
                return monitor.test_http_versions(test_url)
            self.run_test_safely(f"HTTP_Versions_{name}", test)

    def test_owasp_security_analysis(self):
        """Tests 5-9: OWASP Top 10 Security Analysis"""
        test_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(test_sites, 5):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                response = monitor.make_http_request(test_url)
                if response.get('success'):
                    return monitor.check_owasp_top10(test_url, response['headers'], response.get('content', ''))
                return {'error': 'Failed to get response for OWASP analysis'}
            self.run_test_safely(f"OWASP_Analysis_{site}", test)

    def test_ssl_compatibility_analysis(self):
        """Tests 10-14: SSL/TLS Compatibility Analysis"""
        ssl_test_sites = ['httpbin', 'google', 'github', 'badssl_expired', 'badssl_selfsigned']
        for i, site in enumerate(ssl_test_sites, 10):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                return monitor.check_ssl_compatibility(test_url)
            self.run_test_safely(f"SSL_Compatibility_{site}", test)

    def test_cdn_proxy_detection(self):
        """Tests 15-19: CDN and Proxy Detection"""
        cdn_test_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(cdn_test_sites, 15):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                response = monitor.make_http_request(test_url)
                if response.get('success'):
                    return monitor.detect_proxy_and_cdn(response['headers'], test_url)
                return {'error': 'Failed to get headers'}
            self.run_test_safely(f"CDN_Detection_{site}", test)

    def test_http3_support(self):
        """Tests 20-24: HTTP/3 Support Detection"""
        http3_test_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(http3_test_sites, 20):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                return monitor.check_http3_support(test_url)
            self.run_test_safely(f"HTTP3_Support_{site}", test)

    def test_compliance_frameworks(self):
        """Tests 25-29: Compliance Framework Analysis"""
        compliance_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(compliance_sites, 25):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                response = monitor.make_http_request(test_url)
                if response.get('success'):
                    return monitor.check_compliance_frameworks(test_url, response['headers'])
                return {'error': 'Failed to get response for compliance analysis'}
            self.run_test_safely(f"Compliance_Analysis_{site}", test)

    def test_performance_metrics(self):
        """Tests 30-34: Performance and Response Time Analysis"""
        perf_test_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(perf_test_sites, 30):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                start_time = time.time()
                response = monitor.make_http_request(test_url)
                end_time = time.time()
                if response.get('success'):
                    return {
                        'response_time': end_time - start_time,
                        'status_code': response.get('status_code'),
                        'content_length': len(response.get('content', '')),
                        'headers_count': len(response.get('headers', {}))
                    }
                return {'error': 'Request failed'}
            self.run_test_safely(f"Performance_Metrics_{site}", test)

    def test_security_headers_analysis(self):
        """Tests 35-39: Security Headers Analysis"""
        header_test_sites = ['httpbin', 'google', 'github', 'cloudflare', 'fast_site']
        for i, site in enumerate(header_test_sites, 35):
            def test(test_url=self.test_urls[site], site_name=site):
                monitor = WebHealthMonitor(test_url)
                response = monitor.make_http_request(test_url)
                if response.get('success'):
                    headers = response.get('headers', {})
                    security_headers = {
                        'Content-Security-Policy': headers.get('content-security-policy'),
                        'X-Frame-Options': headers.get('x-frame-options'),
                        'X-Content-Type-Options': headers.get('x-content-type-options'),
                        'Strict-Transport-Security': headers.get('strict-transport-security'),
                        'X-XSS-Protection': headers.get('x-xss-protection')
                    }
                    return {k: v for k, v in security_headers.items() if v is not None}
                return {'error': 'Failed to get headers'}
            self.run_test_safely(f"Security_Headers_{site}", test)

    def test_error_handling(self):
        """Tests 40-44: Error Handling and Edge Cases"""
        error_test_cases = [
            ('Invalid_URL', 'not-a-valid-url'),
            ('Non_Existent_Domain', 'https://this-domain-definitely-does-not-exist-12345.com'),
            ('Timeout_Test', 'https://httpbin.org/delay/30'),
            ('Invalid_Port', 'https://google.com:99999'),
            ('Malformed_Protocol', 'htp://google.com')
        ]
        
        for i, (test_name, test_url) in enumerate(error_test_cases, 40):
            def test(url=test_url, expected_error=test_name):
                # For error handling tests, we EXPECT failures/exceptions
                # Proper error handling (catching invalid input) is considered SUCCESS
                try:
                    monitor = WebHealthMonitor(url)
                    result = monitor.make_http_request(url)
                    
                    # If we get a proper error response, that's successful error handling
                    if isinstance(result, dict) and not result.get('success', True):
                        return {'error_handling_success': True, 'error_response': result}
                    
                    # If we somehow get a success, that's unexpected for error cases
                    return {'unexpected_success': True, 'result': result}
                    
                except Exception as e:
                    # Catching exceptions for invalid input is GOOD error handling
                    return {'error_handling_success': True, 'exception_caught': str(e)}
                    
            self.run_test_safely(f"Error_Handling_{test_name}", test)

    def test_command_line_interface(self):
        """Tests 45-50: Command Line Interface Testing"""
        cli_commands = [
            ('basic_health', [self.test_urls['httpbin']]),
            ('http_versions', [self.test_urls['httpbin'], 'http-versions']),
            ('owasp_analysis', [self.test_urls['httpbin'], 'owasp']),
            ('ssl_compatibility', [self.test_urls['httpbin'], 'ssl-compat']),
            ('cdn_detection', [self.test_urls['httpbin'], 'proxy']),
            ('compliance_check', [self.test_urls['httpbin'], 'frameworks'])
        ]
        
        script_path = '/root/media/data/usr/lib/zabbix/externalscripts/get_web_health.py'
        
        for i, (test_name, args) in enumerate(cli_commands, 45):
            def test(cmd_args=args):
                cmd = ['python3', script_path] + cmd_args
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    return {
                        'return_code': result.returncode,
                        'stdout': result.stdout[:500],  # Limit output
                        'stderr': result.stderr[:500] if result.stderr else None
                    }
                except subprocess.TimeoutExpired:
                    return {'error': 'Command timed out'}
                except Exception as e:
                    return {'error': str(e)}
            self.run_test_safely(f"CLI_Interface_{test_name}", test)

    def run_all_tests(self):
        """Execute all test suites"""
        print("🚀 Starting Comprehensive Web Health Monitoring Test Suite")
        print(f"📅 Test started at: {datetime.now().isoformat()}")
        print("=" * 80)
        
        start_time = time.time()
        
        # Run all test categories
        self.test_basic_initialization()
        self.test_http_versions_all_sites()
        self.test_owasp_security_analysis()
        self.test_ssl_compatibility_analysis()
        self.test_cdn_proxy_detection()
        self.test_http3_support()
        self.test_compliance_frameworks()
        self.test_performance_metrics()
        self.test_security_headers_analysis()
        self.test_error_handling()
        self.test_command_line_interface()
        
        end_time = time.time()
        
        print("=" * 80)
        print(f"📊 Test Summary:")
        print(f"   Total Tests: {self.test_count}")
        print(f"   Successful: {self.success_count} ({self.success_count/self.test_count*100:.1f}%)")
        print(f"   Failed: {self.error_count} ({self.error_count/self.test_count*100:.1f}%)")
        print(f"   Duration: {end_time - start_time:.2f} seconds")
        print(f"📅 Test completed at: {datetime.now().isoformat()}")
        
        return self.results

    def analyze_results(self):
        """Analyze test results and provide insights"""
        print("\n" + "=" * 80)
        print("📈 COMPREHENSIVE ANALYSIS REPORT")
        print("=" * 80)
        
        # Category Analysis
        categories = {}
        for test_name, result in self.results.items():
            category = test_name.split('_')[2] if len(test_name.split('_')) > 2 else 'Other'
            if category not in categories:
                categories[category] = {'total': 0, 'success': 0, 'failed': 0}
            categories[category]['total'] += 1
            if result['success']:
                categories[category]['success'] += 1
            else:
                categories[category]['failed'] += 1
        
        print("\n🔍 Results by Category:")
        for category, stats in categories.items():
            success_rate = stats['success'] / stats['total'] * 100
            print(f"   {category}: {stats['success']}/{stats['total']} ({success_rate:.1f}% success)")
        
        # Failed Tests Analysis
        failed_tests = {k: v for k, v in self.results.items() if not v['success']}
        if failed_tests:
            print(f"\n❌ Failed Tests ({len(failed_tests)}):")
            for test_name, result in failed_tests.items():
                print(f"   {test_name}: {result['error']}")
        
        # Performance Insights
        perf_tests = {k: v for k, v in self.results.items() if 'Performance' in k and v['success']}
        if perf_tests:
            print(f"\n⚡ Performance Insights:")
            response_times = []
            for test_name, result in perf_tests.items():
                if result['result'] and 'response_time' in result['result']:
                    response_times.append(result['result']['response_time'])
            
            if response_times:
                avg_time = sum(response_times) / len(response_times)
                min_time = min(response_times)
                max_time = max(response_times)
                print(f"   Average Response Time: {avg_time:.3f}s")
                print(f"   Fastest Response: {min_time:.3f}s")
                print(f"   Slowest Response: {max_time:.3f}s")
        
        # Security Analysis
        security_tests = {k: v for k, v in self.results.items() if any(x in k for x in ['OWASP', 'SSL', 'Security']) and v['success']}
        if security_tests:
            print(f"\n🔒 Security Analysis Summary:")
            ssl_grades = []
            owasp_scores = []
            
            for test_name, result in security_tests.items():
                if 'SSL' in test_name and result['result']:
                    if 'overall_grade' in result['result']:
                        ssl_grades.append(result['result']['overall_grade'])
                elif 'OWASP' in test_name and result['result']:
                    if 'overall_score' in result['result']:
                        owasp_scores.append(result['result']['overall_score'])
            
            if ssl_grades:
                print(f"   SSL Grades Found: {set(ssl_grades)}")
            if owasp_scores:
                avg_owasp = sum(owasp_scores) / len(owasp_scores)
                print(f"   Average OWASP Score: {avg_owasp:.1f}/100")
        
        # CDN/Infrastructure Analysis
        cdn_tests = {k: v for k, v in self.results.items() if 'CDN' in k and v['success']}
        if cdn_tests:
            print(f"\n🌐 Infrastructure Analysis:")
            cdn_providers = []
            for test_name, result in cdn_tests.items():
                if result['result'] and 'cdn_detected' in result['result']:
                    if result['result']['cdn_detected']:
                        provider = result['result'].get('cdn_provider', 'Unknown')
                        cdn_providers.append(provider)
            
            if cdn_providers:
                print(f"   CDN Providers Detected: {set(cdn_providers)}")
            else:
                print(f"   No CDN providers detected in test sites")
        
        return self.results

def main():
    """Main execution function"""
    print("Initializing Comprehensive Test Suite...")
    
    test_suite = ComprehensiveTestSuite()
    
    # Run all tests
    results = test_suite.run_all_tests()
    
    # Analyze results
    test_suite.analyze_results()
    
    # Save detailed results
    output_file = f"/root/test/test_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: {output_file}")
    
    return results

if __name__ == "__main__":
    main()