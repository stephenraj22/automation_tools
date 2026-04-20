import os
import subprocess

# Path to the base domain file
BASE_DOMAIN_FILE = "base_domains.txt"

# Path to the subdomain takeover script
SUBDOMAIN_TAKEOVER_SCRIPT = "../subdomain_takeover_vuln/subdomain_takeover_vuln.py"

# Directory structure for subdomains files
SUBDOMAINS_DIR = "C:/Users/STEPHENRAJ/Downloads/shared1"

def run_subdomain_takeover(domain):
    """
    Runs the subdomain takeover script for a given domain.
    """
    # Construct the subdomains file path dynamically
    subdomains_file = os.path.join(SUBDOMAINS_DIR, f"{domain}/domains_{domain}.txt")

    # Check if the subdomains file exists
    if not os.path.exists(subdomains_file):
        print(f"[-] Subdomains file not found: {subdomains_file}")
        return

    # Command to execute the subdomain takeover script
    command = [
        "python", SUBDOMAIN_TAKEOVER_SCRIPT,
        "-f", subdomains_file,
        "-d", domain
    ]

    # Run the command
    try:
        print(f"[+] Running subdomain takeover for domain: {domain}")
        result = subprocess.run(command, check=True, text=True, capture_output=True)
        print(result.stdout)  # Print the output of the script
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running subdomain takeover for domain: {domain}")
        print(e.stderr)  # Print the error message

def main():
    """
    Main function to read domains from the base domain file and process them.
    """
    # Check if the base domain file exists
    if not os.path.exists(BASE_DOMAIN_FILE):
        print(f"[-] Base domain file not found: {BASE_DOMAIN_FILE}")
        return

    # Read the list of domains from the base domain file
    with open(BASE_DOMAIN_FILE, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    # Iterate through each domain and run the subdomain takeover script
    for domain in domains:
        run_subdomain_takeover(domain)

if __name__ == "__main__":
    main()