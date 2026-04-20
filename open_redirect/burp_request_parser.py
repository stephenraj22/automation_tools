import base64
from urllib.parse import urlparse

# Function to decode Base64 safely with fallback encodings
def decode_b64(data):
    try:
        decoded_bytes = base64.b64decode(data.strip(), validate=True)
        try:
            return decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return decoded_bytes.decode('latin-1')
    except Exception as e:
        print(f"Base64 decode error: {e}")
        return ""

# Parse raw HTTP request string into components
def parse_raw_request(raw_req):
    lines = raw_req.strip().splitlines()
    if not lines:
        raise ValueError("Empty decoded request")

    first_line = lines[0]
    try:
        method, path, version = first_line.split()
    except ValueError:
        raise ValueError(f"Invalid first line: {first_line}")

    headers = {}
    host = ""
    body_start = -1

    for i, h in enumerate(lines[1:], start=1):
        if h == '':
            body_start = i + 1
            break
        if ": " in h:
            key, value = h.split(": ", 1)
            headers[key] = value
            if key.lower() == "host":
                host = value

    # If no empty line found, assume body starts after headers
    if body_start == -1:
        body_start = len(lines) + 1

    # Build URL
    if not path.startswith("http"):
        scheme = "https" if host.endswith("mozilla.net") else "http"
        url = f"{scheme}://{host}{path}"
    else:
        url = path

    # Body extraction (optional)
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""

    return {
        "method": method,
        "url": url,
        "headers": headers,
        "body": body
    }

# Extract URL from a decoded request
def extract_url_from_request(decoded_req):
    parsed = parse_raw_request(decoded_req)
    return parsed["url"]