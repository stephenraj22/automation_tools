import dns.resolver
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
GENERATE_REPORTS = True
# List of known services that are often involved in subdomain takeovers
KNOWN_SERVICES = {
    "Amazon S3": ["s3.amazonaws.com"],
    "GitHub Pages": ["github.io"],
    "Heroku": ["herokuapp.com"],
    "Shopify": ["myshopify.com"],
    "Azure Blob Storage": ["blob.core.windows.net"],
    "Fastly": ["fastly.net"],
    "Netlify": ["netlify.app"],
    "Vercel": ["vercel.app"],
    "Tsuru": ["tsuru.app"],
}

# Function to resolve DNS records for a subdomain
def resolve_dns(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        return [str(answer.target).rstrip('.') for answer in answers]
    except Exception:
        return []

# Function to check if a subdomain is vulnerable to takeover
def check_subdomain_takeover(subdomain, cname):
    try:
        response = requests.get(f"http://{subdomain}", timeout=10)
        if response.status_code == 404:
            print(f"[+] Potential Subdomain Takeover: {subdomain} -> {cname}")
            return subdomain, cname, "Potential Takeover"
        elif response.status_code == 403 or response.status_code == 401:
            print(f"[!] Access Denied: {subdomain} -> {cname}")
            return None
        else:
            print(f"[-] Not Vulnerable: {subdomain} -> {cname}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[+] Potential Subdomain Takeover (No Response): {subdomain} -> {cname}")
        return subdomain, cname, "Potential Takeover"

# Function to identify vulnerable subdomains
def test_subdomain_takeover(subdomains):
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for subdomain in subdomains:
            futures.append(executor.submit(resolve_dns, subdomain))

        for future in as_completed(futures):
            cnames = future.result()
            if cnames:
                for cname in cnames:
                    for service, patterns in KNOWN_SERVICES.items():
                        if any(pattern in cname for pattern in patterns):
                            result = check_subdomain_takeover(subdomain, cname)
                            if result:
                                results.append(result)

    return results

# Main function
def main():
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Test subdomains for potential takeover vulnerabilities.")
    parser.add_argument("-f", "--file", required=True, help="Path to the file containing subdomains")
    parser.add_argument("-d", "--domain", required=True, help="Domain name for organizing output files")
    args = parser.parse_args()

    subdomains_file = args.file
    domain_name = args.domain

    # Create output directory - use OUTPUT_DIR env var if set
    output_dir = os.environ.get('OUTPUT_DIR', f"C:/Users/STEPHENRAJ/Downloads/shared1/{domain_name}")
    os.makedirs(output_dir, exist_ok=True)  # Create directory if it doesn't exist
    output_txt = f"{output_dir}/subdomain_takeover_output.txt"

    # Load subdomains from file
    try:
        with open(subdomains_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"❌ Error: File '{subdomains_file}' not found.")
        return

    print(f"\n[+] Testing {len(subdomains)} subdomains for takeover vulnerabilities...\n")

    # Perform subdomain takeover testing
    results = test_subdomain_takeover(subdomains)

    # Handle results
    if results or GENERATE_REPORTS:
        with open(output_txt, "w") as f:
            for subdomain, cname, status in results:
                f.write(f"Subdomain: {subdomain}\nCNAME: {cname}\nStatus: {status}\n\n")
        print(f"\n✅ Results saved to '{output_txt}'")
    else:
        print("\n⚠️ No subdomain takeover vulnerabilities found.")

if __name__ == "__main__":
    main()

#python script.py -f subdomains.txt -d example.com