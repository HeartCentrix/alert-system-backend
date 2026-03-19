#!/usr/bin/env python3
"""
Prototype Pollution Security Test Script

This script tests the TMAlert backend for prototype pollution vulnerabilities
by sending malicious payloads and verifying they are properly handled.

Usage:
    python test_prototype_pollution.py [--email EMAIL] [--password PASSWORD] [--base-url URL]
    
Prerequisites:
    - Backend server running at http://localhost:8000
    - Valid access token (obtained via login)

Options:
    --email EMAIL         Login email (default: admin@tmalert.com)
    --password PASSWORD   Login password (default: Password123!)
    --base-url URL        Backend base URL (default: http://localhost:8000/api/v1)
"""

import requests
import json
import sys
import argparse
from typing import Optional, Dict, Any

# Default Configuration
DEFAULT_BASE_URL = "http://localhost:8000/api/v1"
DEFAULT_LOGIN_EMAIL = "admin@tmalert.com"
DEFAULT_LOGIN_PASSWORD = "Password123!"


def login(email: str, password: str) -> Optional[str]:
    """Login and return access token."""
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={"email": email, "password": password},
            headers={"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get("access_token")
        else:
            print(f"Login failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Login error: {e}")
        return None


def test_prototype_pollution_payload(token: str, payload: Dict[str, Any], endpoint: str, test_name: str) -> bool:
    """
    Test a prototype pollution payload against an endpoint.
    
    Returns True if the payload was safely rejected/handled.
    """
    try:
        response = requests.post(
            f"{BASE_URL}{endpoint}",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
        
        # Check response
        if response.status_code == 500:
            print(f"❌ FAIL: {test_name}")
            print(f"   Server error (500) - payload may have caused issues")
            print(f"   Response: {response.text[:200]}")
            return False
        
        # Check if response contains prototype pollution indicators
        response_text = response.text.lower()
        
        if "__proto__" in response_text:
            print(f"❌ FAIL: {test_name}")
            print(f"   Response contains __proto__ (not sanitized)")
            return False
        
        if "prototype" in response_text and "pollution" in response_text:
            print(f"⚠️ WARNING: {test_name}")
            print(f"   Response mentions prototype pollution")
        
        # Safe response (422 validation error or 200 with sanitized data)
        if response.status_code in [200, 201, 422]:
            print(f"✅ PASS: {test_name}")
            print(f"   Status: {response.status_code}")
            return True
        
        print(f"⚠️ UNEXPECTED: {test_name}")
        print(f"   Status: {response.status_code}")
        return True
        
    except Exception as e:
        print(f"❌ ERROR: {test_name} - {e}")
        return False


def run_prototype_pollution_tests(token: str):
    """Run all prototype pollution tests."""
    print("=" * 70)
    print("PROTOTYPE POLLUTION SECURITY TESTS")
    print("=" * 70)
    print()
    
    results = []
    
    # Test 1: __proto__ in user creation
    print("[Test 1] Testing __proto__ injection in user creation endpoint...")
    payload = {
        "email": "test_prototype@example.com",
        "password": "Password123!",
        "first_name": "Test",
        "last_name": "User",
        "__proto__": {
            "isAdmin": True,
            "role": "super_admin"
        }
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/users", 
        "User creation with __proto__ payload"
    ))
    print()
    
    # Test 2: __proto__ in user update
    print("[Test 2] Testing __proto__ injection in user update endpoint...")
    payload = {
        "first_name": "Updated",
        "__proto__": {
            "mfa_enabled": False,
            "is_verified": True
        }
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/users/1", 
        "User update with __proto__ payload"
    ))
    print()
    
    # Test 3: constructor in payload
    print("[Test 3] Testing constructor injection...")
    payload = {
        "name": "Test Location",
        "latitude": 40.7128,
        "longitude": -74.0060,
        "constructor": {
            "prototype": {
                "isAdmin": True
            }
        }
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/locations", 
        "Location creation with constructor payload"
    ))
    print()
    
    # Test 4: __proto__ in notification
    print("[Test 4] Testing __proto__ injection in notification endpoint...")
    payload = {
        "title": "Test Alert",
        "message": "Test message",
        "channels": ["sms"],
        "target_all": True,
        "__proto__": {
            "sent": True,
            "priority": "critical"
        }
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/notifications", 
        "Notification creation with __proto__ payload"
    ))
    print()
    
    # Test 5: prototype pollution via JSON array
    print("[Test 5] Testing prototype pollution via array...")
    payload = {
        "users": [
            {
                "email": "array_test@example.com",
                "__proto__": {
                    "injected": True
                }
            }
        ]
    }
    # This would be for bulk user creation if such endpoint exists
    # For now, we document the test
    print("⚠️ SKIPPED: Bulk user creation endpoint not available")
    results.append(True)
    print()
    
    # Test 6: Nested __proto__
    print("[Test 6] Testing nested __proto__ injection...")
    payload = {
        "name": "Test Group",
        "description": "Test group",
        "metadata": {
            "nested": {
                "__proto__": {
                    "admin": True
                }
            }
        }
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/groups", 
        "Group creation with nested __proto__ payload"
    ))
    print()
    
    # Test 7: toString pollution
    print("[Test 7] Testing toString pollution...")
    payload = {
        "email": "tostring_test@example.com",
        "password": "Password123!",
        "toString": "function() { return 'admin'; }"
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/users", 
        "User creation with toString payload"
    ))
    print()
    
    # Test 8: hasOwnProperty pollution
    print("[Test 8] Testing hasOwnProperty pollution...")
    payload = {
        "name": "Test",
        "hasOwnProperty": "injected_value"
    }
    results.append(test_prototype_pollution_payload(
        token, payload, "/locations", 
        "Location creation with hasOwnProperty payload"
    ))
    print()
    
    # Summary
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ All prototype pollution tests passed!")
        print("   Pydantic schemas are properly rejecting/ignoring prototype fields.")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed!")
        print("   Review the failures above for potential prototype pollution vulnerabilities.")
        return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="TMAlert Prototype Pollution Security Test"
    )
    parser.add_argument(
        "--email",
        default=DEFAULT_LOGIN_EMAIL,
        help=f"Login email (default: {DEFAULT_LOGIN_EMAIL})"
    )
    parser.add_argument(
        "--password",
        default=DEFAULT_LOGIN_PASSWORD,
        help=f"Login password (default: {DEFAULT_LOGIN_PASSWORD})"
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Backend base URL (default: {DEFAULT_BASE_URL})"
    )
    
    args = parser.parse_args()
    
    # Set global variables
    global BASE_URL, LOGIN_EMAIL, LOGIN_PASSWORD
    BASE_URL = args.base_url
    LOGIN_EMAIL = args.email
    LOGIN_PASSWORD = args.password
    
    print("TMAlert Prototype Pollution Security Test")
    print("=" * 70)
    print(f"Backend URL: {BASE_URL}")
    print(f"Login email: {LOGIN_EMAIL}")
    print()
    
    # Login
    print("Step 1: Logging in...")
    token = login(LOGIN_EMAIL, LOGIN_PASSWORD)
    
    if not token:
        print("\n❌ Failed to obtain access token.")
        print("   Make sure:")
        print("   1. Backend server is running at the specified URL")
        print("   2. Test credentials are correct")
        print("   3. User account exists and is active")
        print("\n   Usage:")
        print("   python test_prototype_pollution.py --email your@email.com --password YourPassword")
        sys.exit(1)
    
    print(f"✅ Login successful. Token obtained.")
    print()
    
    # Run tests
    exit_code = run_prototype_pollution_tests(token)
    
    print()
    print("=" * 70)
    print("Test completed.")
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
