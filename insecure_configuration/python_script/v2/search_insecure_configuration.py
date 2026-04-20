import requests
import os
import csv
import sys
import re


def load_sensitive_patterns(config_file):
    """Load sensitive patterns from a configuration file."""
    try:
        with open(config_file, 'r') as file:
            patterns = [line.strip() for line in file if line.strip()]
        # Combine patterns into a single regex with OR (|) operator
        combined_pattern = r'\b(?:' + '|'.join(patterns) + r')\b'
        return re.compile(combined_pattern, re.IGNORECASE)
    except FileNotFoundError:
        print(f"Error: Configuration file {config_file} not found.")
        sys.exit(1)


def search_strings_in_response(url, regex_pattern):
    """Fetch URL content and check for sensitive strings using regex."""
    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            found_items = []
            matches = regex_pattern.finditer(response.text)
            for match in matches:
                key = match.group(0)  # The matched sensitive string
                start_index = match.start()
                # Extract the next 100 characters after the key
                context = response.text[start_index:start_index + len(key) + 100]
                found_items.append((key, context))
            return found_items

    except requests.exceptions.RequestException as e:
        print(f"URL: {url} - Request failed with error: {e}")

    return []


def process_file(file_path, regex_pattern, csv_writer):
    """Read URLs from file and check each for sensitive strings using regex."""
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            found_items = search_strings_in_response(line, regex_pattern)
            for key, context in found_items:
                csv_writer.writerow([line, key, context])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <domain_name>")
        sys.exit(1)

    domain_name = sys.argv[1]

    # Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
    output_dir = os.environ.get('OUTPUT_DIR', f"/mnt/{domain_name}")

    # Path to the configuration file
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_file = os.path.join(script_dir, "sensitive_patterns.txt")

    # Load sensitive patterns from the configuration file
    sensitive_pattern = load_sensitive_patterns(config_file)

    # Define the folder or file path dynamically based on the domain name
    file_path = f"{output_dir}/js_{domain_name}.txt"

    # Output CSV file
    output_csv = f"{output_dir}/js_keys_report.csv"

    # Open the CSV file for writing
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["URL", "Found Key", "Context (Next 100 Characters)"])

        if os.path.isfile(file_path):
            process_file(file_path, sensitive_pattern, csv_writer)
        else:
            print(f"File not found: {file_path}")
            sys.exit(1)

    print(f"Report saved to {output_csv}")