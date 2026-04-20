import requests
import os
import csv
import sys
import re
from urllib.parse import urlparse


# API Key regex patterns for various services
API_KEY_PATTERNS = {
    'AWS Access Key': r'AKIA[0-9A-Z]{16}',
    'AWS Secret Key': r'[A-Za-z0-9/+=]{40}',
    'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
    'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
    'Stripe Test Key': r'(pk|sk)_test_[0-9a-zA-Z]{24}',
    'GitHub Personal Access Token': r'ghp_[a-zA-Z0-9]{36}',
    'GitHub OAuth Token': r'gho_[a-zA-Z0-9]{36}',
    'GitHub App Token': r'ghu_[a-zA-Z0-9]{36}',
    'GitHub Server Token': r'ghs_[a-zA-Z0-9]{36}',
    'GitHub Fine-grained Token': r'ghr_[a-zA-Z0-9]{36}',
    'GitLab Personal Access Token': r'glpat-[a-zA-Z0-9_-]{20}',
    'GitLab OAuth Token': r'[a-zA-Z0-9_-]{64}',
    'Slack Bot Token': r'xoxb-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    'Slack User Token': r'xoxp-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
    'Slack Webhook': r'https://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}',
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'Google OAuth Token': r'ya29\.[0-9A-Za-z\-_]+',
    'Firebase Database Secret': r'[a-zA-Z0-9_-]{32}',
    'Firebase Custom Token': r'[a-zA-Z0-9.:_-]{100,}',
    'Twilio API Key': r'SK[0-9a-fA-F]{32}',
    'Twilio Account SID': r'AC[0-9a-fA-F]{32}',
    'Twilio Auth Token': r'[0-9a-fA-F]{32}',
    'Heroku API Key': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
    'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
    'Auth0 Client Secret': r'[a-zA-Z0-9_-]{64}',
    'Auth0 API Token': r'[a-zA-Z0-9_-]{24}',
    'Azure Storage Key': r'[a-zA-Z0-9+/]{88}==',
    'Azure App Service Key': r'[a-zA-Z0-9_-]{44}',
    'DigitalOcean API Token': r'doo_v_[a-zA-Z0-9]{64}',
    'Shopify API Token': r'shpat_[a-zA-Z0-9]{32}',
    'PayPal Client ID': r'[A-Za-z0-9]{64}',
    'PayPal Client Secret': r'[A-Za-z0-9._-]{80}',
    'Twitter API Key': r'[a-zA-Z0-9]{25}',
    'Twitter API Secret': r'[a-zA-Z0-9]{50}',
    'Twitter Bearer Token': r'A{22}[a-zA-Z0-9_%]{100,}',
    'Facebook Access Token': r'EAAB[a-zA-Z0-9]{100,}',
    'Square Access Token': r'sq0[a-z]{3}-[0-9A-Za-z_-]{22}',
    'Braintree Access Token': r'access_token\$[a-zA-Z0-9_\$]{20,}',
    'Algolia API Key': r'[a-zA-Z0-9_-]{32}',
    'Cloudflare API Token': r'[a-zA-Z0-9_-]{40}',
    'Cloudflare Account ID': r'[a-f0-9]{32}',
    'Pulumi Access Token': r'pul-[a-f0-9]{40}',
    'Datadog API Key': r'[a-zA-Z0-9]{32}',
    'New Relic License Key': r'[a-f0-9]{32}',
    'Rollbar Access Token': r'[a-zA-Z0-9_-]{40}',
    'Sentry DSN': r'https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+',
    'Bugsnag API Key': r'[a-f0-9]{32}',
    'Honeycomb API Key': r'[a-zA-Z0-9_-]{20}',
    'Postmark API Key': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
    'Pusher App Key': r'[a-zA-Z0-9_-]{20}',
    'Pusher App Secret': r'[a-zA-Z0-9_-]{20}',
    'Mapbox Access Token': r'pk\.[a-zA-Z0-9_-]{80}',
    'OpenAI API Key': r'sk-[a-zA-Z0-9]{48}',
    'HuggingFace API Token': r'hf_[a-zA-Z0-9]{34}',
    'Anthropic API Key': r'sk-ant-[a-zA-Z0-9_-]{95}',
    'Cohere API Key': r'[a-zA-Z0-9_-]{40}',
    'Pinecone API Key': r'[a-zA-Z0-9_-]{36}',
    'Supabase API Key': r'[a-zA-Z0-9_-]{40}',
    'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
}


def search_api_keys_in_response(url, patterns):
    """Fetch URL content and check for API keys using regex patterns."""
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            found_keys = []
            for key_name, pattern in patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    key_value = match.group(0)
                    # Validate the key (basic sanity check)
                    if is_valid_api_key(key_value, key_name):
                        start_index = match.start()
                        # Extract context around the key
                        context_start = max(0, start_index - 50)
                        context_end = min(len(response.text), start_index + len(key_value) + 50)
                        context = response.text[context_start:context_end]
                        found_keys.append((key_name, key_value, context))
            return found_keys
    
    except requests.exceptions.RequestException as e:
        print(f"URL: {url} - Request failed with error: {e}")
    
    return []


def is_valid_api_key(key_value, key_name):
    """Validate API key with basic sanity checks."""
    # Skip common false positives
    false_positives = [
        'AKIA0000000000000000',
        'sk_test_000000000000000000000000',
        'pk_test_000000000000000000000000',
        'YOUR_API_KEY',
        'your-api-key',
        'api-key',
        'API_KEY',
        'example',
        'test',
        'demo',
    ]
    
    if key_value in false_positives:
        return False
    
    # Check for repeated characters (likely placeholder)
    if len(set(key_value)) < 3:
        return False
    
    # Specific validation for certain key types
    if 'AWS' in key_name:
        # AWS keys should not have obvious patterns
        if 'AKIA' in key_value and key_value.count('0') > 5:
            return False
    
    return True


def process_file(file_path, patterns, csv_writer):
    """Read URLs from file and check each for API keys."""
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            found_keys = search_api_keys_in_response(line, patterns)
            for key_name, key_value, context in found_keys:
                csv_writer.writerow([line, key_name, key_value, context])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <domain_name>")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    
    # Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
    output_dir = os.environ.get('OUTPUT_DIR', f"/mnt/{domain_name}")
    
    # Define the folder or file path dynamically based on the domain name
    file_path = f"{output_dir}/js_{domain_name}.txt"
    
    # Output CSV file
    output_csv = f"{output_dir}/api_keys_report.csv"
    
    # Open the CSV file for writing
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["URL", "Key Type", "Key Value", "Context"])
        
        if os.path.isfile(file_path):
            process_file(file_path, API_KEY_PATTERNS, csv_writer)
        else:
            print(f"File not found: {file_path}")
            sys.exit(1)
    
    print(f"API key report saved to {output_csv}")
