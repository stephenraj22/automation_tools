import requests
import os
import csv
import sys


def search_strings_in_response(url, search_strings):
    """Fetch URL content and check for multiple search strings."""
    try:
        response = requests.get(url, timeout=10)

        if response.status_code == 200:
            found_items = []
            for s in search_strings:
                if s in response.text:
                    # Find all occurrences of the search string
                    start_index = response.text.find(s)
                    while start_index != -1:
                        # Extract the next 30 characters after the key
                        context = response.text[start_index:start_index + len(s) + 30]
                        found_items.append((s, context))
                        # Look for the next occurrence of the key
                        start_index = response.text.find(s, start_index + 1)

            if found_items:
                return found_items

    except requests.exceptions.RequestException as e:
        print(f"URL: {url} - Request failed with error: {e}")

    return []


def process_file(file_path, search_strings, csv_writer):
    """Read URLs from file and check each for search strings."""
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            found_items = search_strings_in_response(line, search_strings)
            for key, context in found_items:
                # Write the result to the CSV file
                csv_writer.writerow([line, key, context])


if __name__ == "__main__":
    # Check if the domain name is provided as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python3 script.py <domain_name>")
        sys.exit(1)

    # Get the domain name from the command-line argument
    domain_name = sys.argv[1]

    # Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
    output_dir = os.environ.get('OUTPUT_DIR', f"/mnt/{domain_name}")

    sensitive_keys = [
        "api_key", "apikey", "apiToken", "api-token", "api_secret", "api-secret", "apisecret", "apiSecret",
        "auth", "authorization", "auth_key", "authToken", "auth-token", "access_key", "accessKey", "access-token",
        "accessToken", "secret", "secret_key", "secretKey", "client_id", "clientId", "client_secret", "clientSecret",
        "password", "pass", "pwd", "private_key", "privateKey", "jwt", "jwt_token", "bearer_token", "oauth_token",
        "oauth", "refresh_token", "refreshToken", "session_key", "session_secret", "encryption_key", "ssh_key",
        "token", "user_password", "application-identifier", "credentials", "creds", "accountKey", "account_key",
        "account-key", "credential", "secure", "passwd", "code", "stripeKey", "awsKey", "googleApiKey", "githubToken",
        "gitlabToken", "azureKey", "slackToken", "discordToken", "oauthToken", "oauthSecret", "dbPassword",
        "databasePassword", "dbUser", "databaseUser", "dbPass", "databasePass", "sqlPassword", "mongoPassword",
        "redisPassword", "env", "environment", "config", "configuration", "settings", ".env", "ENV", "CONFIG",
        "SETTINGS", "process.env", "apikeys", "apikey", "passwords", "tokken", "secrete", "authtoken", "accesstoken"
    ]

    # Define the folder or file path dynamically based on the domain name
    file_path = f"{output_dir}/js_{domain_name}.txt"  # Adjust the path format as needed

    # Output CSV file
    output_csv = f"{output_dir}/js_keys_report.csv"

    # Open the CSV file for writing
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        # Write the header row
        csv_writer.writerow(["URL", "Found Key", "Context (Next 30 Characters)"])

        # Process a single file
        if os.path.isfile(file_path):
            process_file(file_path, sensitive_keys, csv_writer)
        else:
            print(f"File not found: {file_path}")
            sys.exit(1)

    print(f"Report saved to {output_csv}")