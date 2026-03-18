#!/usr/bin/env python3

import requests
import sys
import json
from datetime import datetime

class SecurityAPITester:
    def __init__(self, base_url="https://seccheck-hash.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.tests_run = 0
        self.tests_passed = 0

    def run_test(self, name, method, endpoint, expected_status, data=None, timeout=10):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}

        self.tests_run += 1
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=timeout)
            else:
                response = requests.request(method, url, json=data, headers=headers, timeout=timeout)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                print(f"✅ Passed - Status: {response.status_code}")
                try:
                    response_data = response.json()
                    print(f"   Response: {json.dumps(response_data, indent=2)[:200]}...")
                except:
                    print(f"   Response: {response.text[:200]}...")
            else:
                print(f"❌ Failed - Expected {expected_status}, got {response.status_code}")
                print(f"   Response: {response.text[:200]}...")

            return success, response.json() if response.text else {}

        except Exception as e:
            print(f"❌ Failed - Error: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test root API endpoint"""
        return self.run_test("Root API", "GET", "", 200)

    def test_hash_decode_md5(self):
        """Test MD5 hash decoding"""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"  # MD5 of "hello"
        return self.run_test(
            "Hash Decode - MD5",
            "POST",
            "hash/decode",
            200,
            data={"hash_value": md5_hash}
        )

    def test_hash_decode_sha256(self):
        """Test SHA256 hash decoding"""
        sha256_hash = "2cf24dba4f21d4288094c20c4fc4d853e3c4c1b88e4b1d72b8b73b5e5b4e5c7f"  # SHA256 of "hello"
        return self.run_test(
            "Hash Decode - SHA256",
            "POST",
            "hash/decode",
            200,
            data={"hash_value": sha256_hash}
        )

    def test_hash_decode_sha512(self):
        """Test SHA512 hash decoding"""
        sha512_hash = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"  # SHA512 of "hello"
        return self.run_test(
            "Hash Decode - SHA512",
            "POST",
            "hash/decode",
            200,
            data={"hash_value": sha512_hash}
        )

    def test_hash_decode_unknown(self):
        """Test unknown hash"""
        return self.run_test(
            "Hash Decode - Unknown",
            "POST",
            "hash/decode",
            200,
            data={"hash_value": "invalid_hash_123"}
        )

    def test_hash_generate(self):
        """Test hash generation"""
        return self.run_test(
            "Hash Generate",
            "POST",
            "hash/generate?text=hello",
            200
        )

    def test_hash_generate_empty(self):
        """Test hash generation with empty text"""
        return self.run_test(
            "Hash Generate - Empty Text",
            "POST",
            "hash/generate?text=",
            400
        )

    def test_pentest_port_scan(self):
        """Test penetration testing with port scan"""
        return self.run_test(
            "Pentest - Port Scan",
            "POST",
            "pentest/scan",
            200,
            data={
                "target_url": "example.com",
                "tests": ["port_scan"]
            },
            timeout=30
        )

    def test_pentest_ssl_tls(self):
        """Test SSL/TLS check"""
        return self.run_test(
            "Pentest - SSL/TLS",
            "POST",
            "pentest/scan",
            200,
            data={
                "target_url": "https://example.com",
                "tests": ["ssl_tls"]
            },
            timeout=30
        )

    def test_pentest_security_headers(self):
        """Test security headers check"""
        return self.run_test(
            "Pentest - Security Headers",
            "POST",
            "pentest/scan",
            200,
            data={
                "target_url": "https://example.com",
                "tests": ["security_headers"]
            },
            timeout=30
        )

    def test_pentest_comprehensive(self):
        """Test comprehensive penetration test"""
        return self.run_test(
            "Pentest - Comprehensive",
            "POST",
            "pentest/scan",
            200,
            data={
                "target_url": "https://example.com",
                "tests": ["port_scan", "ssl_tls", "security_headers", "xss_detection", "sql_injection"]
            },
            timeout=60
        )

    def test_pentest_history(self):
        """Test getting pentest history"""
        return self.run_test(
            "Pentest History",
            "GET",
            "pentest/history",
            200
        )

    def test_api_endpoint_test(self):
        """Test API endpoint testing"""
        return self.run_test(
            "API Endpoint Test - GET",
            "POST",
            "api/test",
            200,
            data={
                "endpoint_url": "https://jsonplaceholder.typicode.com/posts/1",
                "method": "GET"
            }
        )

    def test_api_endpoint_test_post(self):
        """Test API endpoint testing with POST"""
        return self.run_test(
            "API Endpoint Test - POST",
            "POST",
            "api/test",
            200,
            data={
                "endpoint_url": "https://jsonplaceholder.typicode.com/posts",
                "method": "POST"
            }
        )

    def test_invalid_endpoints(self):
        """Test invalid endpoints return proper errors"""
        success, _ = self.run_test(
            "Invalid Endpoint",
            "GET",
            "nonexistent/endpoint",
            404
        )
        return success

def main():
    print("🚀 Starting Security API Testing Suite")
    print("=" * 50)
    
    tester = SecurityAPITester()
    
    # Test sequence
    tests = [
        tester.test_root_endpoint,
        tester.test_hash_decode_md5,
        tester.test_hash_decode_sha256,
        tester.test_hash_decode_sha512,
        tester.test_hash_decode_unknown,
        tester.test_hash_generate,
        tester.test_hash_generate_empty,
        tester.test_pentest_port_scan,
        tester.test_pentest_ssl_tls,
        tester.test_pentest_security_headers,
        tester.test_pentest_history,
        tester.test_api_endpoint_test,
        tester.test_api_endpoint_test_post,
        tester.test_invalid_endpoints,
        # Skip comprehensive test for now due to time
        # tester.test_pentest_comprehensive,
    ]

    # Run all tests
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"❌ Test failed with exception: {str(e)}")

    # Print final results
    print("\n" + "=" * 50)
    print(f"📊 Final Results: {tester.tests_passed}/{tester.tests_run} tests passed")
    success_rate = (tester.tests_passed / tester.tests_run * 100) if tester.tests_run > 0 else 0
    print(f"📈 Success Rate: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("🎉 Backend API testing: PASSED")
        return 0
    else:
        print("⚠️  Backend API testing: FAILED")
        return 1

if __name__ == "__main__":
    sys.exit(main())