#!/usr/bin/env python3
"""
DDoS Testing Script
Simulates DDoS attacks on localhost:3000
WARNING: Only use on your own systems!
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost:3000"

# Default settings
DEFAULT_REQUESTS = 100
DEFAULT_THREADS = 10

def send_request(endpoint, method="GET", data=None):
    """Send a single HTTP request"""
    url = f"{BASE_URL}{endpoint}"
    
    try:
        start_time = time.time()
        
        if method == "GET":
            response = requests.get(url, timeout=5)
        elif method == "POST":
            response = requests.post(url, json=data, timeout=5)
        else:
            response = requests.request(method, url, json=data, timeout=5)
        
        elapsed_time = time.time() - start_time
        
        return {
            "status_code": response.status_code,
            "response_time": round(elapsed_time, 3),
            "success": response.status_code == 200,
            "endpoint": endpoint
        }
    except Exception as e:
        return {
            "status_code": 0,
            "error": str(e),
            "success": False,
            "endpoint": endpoint
        }

def ddos_attack(endpoint="/api/ddos/heavy-compute", 
                num_requests=100, 
                concurrent_threads=10,
                method="POST",
                payload=None):
    """Simulate DDoS attack with concurrent requests"""
    
    print("\n" + "="*70)
    print("DDoS SIMULATION")
    print("="*70)
    print(f"Target: {BASE_URL}{endpoint}")
    print(f"Requests: {num_requests}")
    print(f"Concurrent threads: {concurrent_threads}")
    print(f"Method: {method}")
    if payload:
        print(f"Payload: {payload}")
    print("="*70)
    
    start_time = time.time()
    success_count = 0
    error_count = 0
    total_response_time = 0
    results = []
    
    def worker():
        nonlocal success_count, error_count, total_response_time
        result = send_request(endpoint, method, payload)
        results.append(result)
        if result["success"]:
            success_count += 1
            total_response_time += result.get("response_time", 0)
        else:
            error_count += 1
        return result
    
    print(f"\nSending {num_requests} requests...\n")
    progress_interval = max(1, num_requests // 20)
    
    with ThreadPoolExecutor(max_workers=concurrent_threads) as executor:
        futures = [executor.submit(worker) for _ in range(num_requests)]
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            if completed % progress_interval == 0:
                percent = (completed * 100) // num_requests
                print(f"  Progress: {completed}/{num_requests} ({percent}%)")
    
    elapsed_time = time.time() - start_time
    
    summary = {
        "total_requests": num_requests,
        "successful_requests": success_count,
        "failed_requests": error_count,
        "total_time": round(elapsed_time, 2),
        "requests_per_second": round(num_requests / elapsed_time, 2) if elapsed_time > 0 else 0,
        "avg_response_time": round(total_response_time / success_count, 3) if success_count > 0 else 0,
        "endpoint": endpoint
    }
    
    print(f"\n{'='*70}")
    print("RESULTS")
    print("="*70)
    print(f"Total requests sent: {summary['total_requests']}")
    print(f"Successful responses: {summary['successful_requests']}")
    print(f"Failed requests: {summary['failed_requests']}")
    print(f"Total time: {summary['total_time']}s")
    print(f"Requests per second: {summary['requests_per_second']}")
    print(f"Average response time: {summary['avg_response_time']}s")
    print("="*70 + "\n")
    
    return summary

def main():
    import sys
    
    # Default attack settings
    endpoint = "/api/ddos/heavy-compute"
    num_requests = DEFAULT_REQUESTS
    concurrent_threads = DEFAULT_THREADS
    method = "POST"
    payload = None
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print("\nDDoS Testing Script")
            print("="*70)
            print("Usage:")
            print("  python test_ddos.py")
            print("  python test_ddos.py [endpoint] [requests] [threads]")
            print("\nExamples:")
            print("  python test_ddos.py")
            print("  python test_ddos.py /api/search 50 5")
            print("  python test_ddos.py /api/ddos/memory-spike 200 20")
            print("\nDefault: /api/ddos/heavy-compute, 100 requests, 10 threads")
            print("="*70 + "\n")
            return
        
        if len(sys.argv) >= 2:
            endpoint = sys.argv[1]
        if len(sys.argv) >= 3:
            num_requests = int(sys.argv[2])
        if len(sys.argv) >= 4:
            concurrent_threads = int(sys.argv[3])
    
    # Special endpoint configurations
    if "memory-spike" in endpoint:
        payload = {"size": 1000}
    elif "heavy-compute" in endpoint:
        payload = {"iterations": 1000000, "depth": 40}
    elif "expensive-query" in endpoint:
        method = "GET"
        endpoint = "/api/ddos/expensive-query?joins=10"
    elif "recursive-fetch" in endpoint:
        method = "GET"
        endpoint = "/api/ddos/recursive-fetch?depth=5&target=self"
    
    print(f"\nStarting DDoS attack on {BASE_URL}")
    print(f"Press Ctrl+C to stop early\n")
    
    try:
        ddos_attack(
            endpoint=endpoint,
            num_requests=num_requests,
            concurrent_threads=concurrent_threads,
            method=method,
            payload=payload
        )
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user.")
        print("="*70 + "\n")

if __name__ == "__main__":
    main()
