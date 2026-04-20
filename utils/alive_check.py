import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
from urllib.parse import urlparse


def check_url_alive(url, timeout=5):
    """Check if a URL is alive (responds with HTTP status)"""
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        return url, response.status_code, True
    except requests.RequestException:
        try:
            # If HEAD fails, try GET
            response = requests.get(url, timeout=timeout, allow_redirects=True)
            return url, response.status_code, True
        except requests.RequestException:
            return url, None, False


def check_urls_alive(urls, max_threads=10, timeout=5):
    """Check multiple URLs for aliveness in parallel"""
    alive_urls = []
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_url_alive, url, timeout): url for url in urls}
        
        for future in as_completed(futures):
            url, status_code, is_alive = future.result()
            results[url] = {'status_code': status_code, 'alive': is_alive}
            if is_alive:
                alive_urls.append(url)
    
    return alive_urls, results


def filter_domains_alive(domains_file, output_file, max_threads=10, timeout=5):
    """Read domains from file, check which are alive, save to output file"""
    try:
        with open(domains_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{domains_file}' not found.")
        return
    
    print(f"Checking {len(domains)} domains for aliveness...")
    
    # Convert domains to URLs
    urls = []
    for domain in domains:
        urls.append(f"https://{domain}")
        urls.append(f"http://{domain}")
    
    alive_urls, results = check_urls_alive(urls, max_threads, timeout)
    
    # Extract unique domains from alive URLs
    alive_domains = set()
    for url in alive_urls:
        parsed = urlparse(url)
        alive_domains.add(parsed.netloc)
    
    # Write alive domains to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        for domain in sorted(alive_domains):
            f.write(f"{domain}\n")
    
    print(f"Found {len(alive_domains)} alive domains out of {len(domains)}.")
    print(f"Saved to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python alive_check.py <input_file> <output_file> [max_threads] [timeout]")
        print("Example: python alive_check.py domains.txt alive_domains.txt 10 5")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    max_threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    timeout = int(sys.argv[4]) if len(sys.argv) > 4 else 5
    
    filter_domains_alive(input_file, output_file, max_threads, timeout)
