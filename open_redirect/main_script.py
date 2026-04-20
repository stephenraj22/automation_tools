import csv
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

import chardet
from burp_request_parser import decode_b64, parse_raw_request, extract_url_from_request
from open_redirect_tester import test_open_redirect, is_url_like, PAYLOADS

# Configuration options
ENABLE_OPEN_REDIRECT_CHECKS = True  # Set to False to disable open redirect checks
CREATE_FILE_IF_NO_FINDINGS = True  # Set to True to create the output file even if no findings

# Detect encoding of input file
def detect_encoding(path):
    with open(path, "rb") as f:
        result = chardet.detect(f.read(100000))
    return result['encoding']

# Process a single row from the CSV file
def process_row(row):
    req_b64 = row.get("Request", "").strip()
    if not req_b64:
        return {"Error_Message": "Empty Request field"}, None

    try:
        # Decode and parse the request
        decoded_req = decode_b64(req_b64)
        if not decoded_req.strip():
            raise ValueError("Decoded request is empty")

        parsed = parse_raw_request(decoded_req)

        # Extract URL
        url = parsed["url"]

        # Perform open redirect checks if enabled
        open_redirect_findings = []
        if ENABLE_OPEN_REDIRECT_CHECKS:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            url_like_params = [param for param, values in query_params.items() if any(is_url_like(value) for value in values)]

            for param in url_like_params:
                findings = test_open_redirect(url, param, PAYLOADS)
                open_redirect_findings.extend(findings)

        # Build the actual request JSON
        request_json = {
            "method": parsed["method"],
            "url": url,
            "headers": parsed["headers"],
            "body": parsed["body"]
        }

        success_data = {
            "Request_JSON": json.dumps(request_json),
            "URL": url,
            "Open_Redirect_Findings": open_redirect_findings
        }
        return None, success_data

    except Exception as e:
        error_data = {
            "Error_Message": str(e),
            "Base64_Request": req_b64  # Include Base64 request for debugging errors
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
            futures = [executor.submit(process_row, row) for row in reader]

            for future in as_completed(futures):
                error_data, success_data = future.result()
                if error_data:
                    error_rows.append(error_data)
                if success_data:
                    success_rows.append(success_data)

        # Write successful responses
        total_findings = sum(len(row["Open_Redirect_Findings"]) for row in success_rows)
        if total_findings > 0 or CREATE_FILE_IF_NO_FINDINGS:
            with open(output_log, "w", newline="", encoding="utf-8") as outfile:
                fieldnames = ["Request_JSON", "URL", "Open_Redirect_Findings"]
                writer = csv.DictWriter(outfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\')
                writer.writeheader()
                writer.writerows(success_rows)
            print(f"\n✅ Results saved to '{output_log}'")
        else:
            print("\n⚠️ No open redirect findings. Output file not created.")

        # Write errors
        if error_rows:
            with open(error_log_file, "w", newline="", encoding="utf-8") as errfile:
                error_fieldnames = ["Error_Message", "Base64_Request"]
                error_writer = csv.DictWriter(errfile, fieldnames=error_fieldnames, quoting=csv.QUOTE_ALL, escapechar='\\')
                error_writer.writeheader()
                error_writer.writerows(error_rows)
            print(f"❌ Errors logged to '{error_log_file}'")
        else:
            print("✅ No errors encountered.")

if __name__ == "__main__":
    main()