import base64
import csv
from urllib.parse import urlparse
import requests
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import chardet

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

# Detect encoding of input file
def detect_encoding(path):
    with open(path, "rb") as f:
        result = chardet.detect(f.read(100000))
    return result['encoding']

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

# Send request and log response
def send_request(row):
    req_b64 = row.get("Request", "").strip()
    if not req_b64:
        return {"Original_Request": req_b64, "Error_Message": "Empty Request field"}, None

    try:
        decoded_req = decode_b64(req_b64)
        if not decoded_req.strip():
            raise ValueError("Decoded request is empty")

        parsed = parse_raw_request(decoded_req)

        method = parsed["method"]
        url = parsed["url"]
        headers = parsed["headers"]
        body = parsed["body"]

        print(f"[+] Sending {method} to {url}")

        res = None
        if method.upper() == "GET":
            res = requests.get(url, headers=headers, timeout=10)
        elif method.upper() == "POST":
            res = requests.post(url, headers=headers, data=body, timeout=10)
        elif method.upper() in ["HEAD", "OPTIONS", "DELETE"]:
            res = getattr(requests, method.lower())(url, headers=headers, timeout=10)
        elif method.upper() in ["PUT", "PATCH"]:
            res = getattr(requests, method.lower())(url, headers=headers, data=body, timeout=10)
        elif method.upper() == "TRACE":
            s = requests.Session()
            req = requests.Request("TRACE", url, headers=headers).prepare()
            res = s.send(req, timeout=10)
            res.status_code = res.status_code or "TRACE failed"
            res.text = res.text[:32767] or ""
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        success_data = {
            "Original_Request": req_b64,
            "Decoded_Request": decoded_req,
            "URL": url,
            "Headers": json.dumps(headers),
            "Method": method,
            "Response_Status": res.status_code,
            "Response_Text": res.text[:32767]
        }
        return None, success_data

    except Exception as e:
        error_data = {
            "Original_Request": req_b64,
            "Error_Message": str(e)
        }
        return error_data, None

# Main function
def main():
    input_csv = "burp.csv"
    output_log = "request_response_log.csv"
    error_log_file = "error_request_log.csv"

    # Detect encoding
    detected_encoding = detect_encoding(input_csv) or 'utf-8-sig'
    print(f"Detected file encoding: {detected_encoding}")

    # Open files
    with open(input_csv, mode="r", encoding=detected_encoding, errors='ignore') as infile:
        reader = csv.DictReader(infile)

        success_rows = []
        error_rows = []

        # Run in parallel
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(send_request, row) for row in reader]

            for future in as_completed(futures):
                error_data, success_data = future.result()
                if error_data:
                    error_rows.append(error_data)
                if success_data:
                    success_rows.append(success_data)

        # Write successful responses
        with open(output_log, "w", newline="", encoding="utf-8") as outfile:
            fieldnames = ["Original_Request", "Decoded_Request", "URL", "Headers", "Method", "Response_Status", "Response_Text"]
            writer = csv.DictWriter(outfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\')
            writer.writeheader()
            writer.writerows(success_rows)

        # Write errors
        with open(error_log_file, "w", newline="", encoding="utf-8") as errfile:
            error_fieldnames = ["Original_Request", "Error_Message"]
            error_writer = csv.DictWriter(errfile, fieldnames=error_fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\')
            error_writer.writeheader()
            error_writer.writerows(error_rows)

        print(f"\n✅ Done! Results saved to '{output_log}' and errors to '{error_log_file}'")

if __name__ == "__main__":
    main()