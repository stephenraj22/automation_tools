#!/usr/bin/env python3
import boto3
import sys
from botocore.exceptions import ClientError, NoCredentialsError

def check_bucket_access(bucket_name):
    s3 = boto3.client('s3')
    try:
        # Check if bucket exists
        s3.head_bucket(Bucket=bucket_name)
        print(f"[+] Bucket '{bucket_name}' exists.")

        # Try to list objects (public read access check)
        objects = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        if objects.get('KeyCount', 0) > 0:
            print(f"[!] Bucket '{bucket_name}' is PUBLICLY LISTABLE!")
            return True, True  # Exists, Publicly Listable
        else:
            print(f"[-] Bucket '{bucket_name}' exists but not publicly listable.")
            return True, False  # Exists, Not Public
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            print(f"[-] Bucket '{bucket_name}' does not exist.")
            return False, False
        elif error_code in ['403', 'AccessDenied']:
            print(f"[.] Bucket '{bucket_name}' exists but access denied.")
            return True, False
        else:
            print(f"[.] Error checking bucket '{bucket_name}': {e}")
            return False, False


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <domain_or_base_name> [wordlist]")
        sys.exit(1)

    base_name = sys.argv[1]

    wordlist_path = "wordlist.txt"
    if len(sys.argv) >= 3:
        wordlist_path = sys.argv[2]

    try:
        with open(wordlist_path, 'r') as f:
            wordlist = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"[!] Wordlist '{wordlist_path}' not found.")
        sys.exit(1)

    print(f"[*] Using wordlist: {wordlist_path}")
    output_file = f"{base_name}_buckets.txt"
    found_buckets = []

    for word in wordlist:
        bucket_name = word.replace("{{target}}", base_name).strip()
        exists, is_public = check_bucket_access(bucket_name)
        if exists:
            found_buckets.append({
                'name': bucket_name,
                'public': is_public
            })

    # Save results
    with open(output_file, 'w') as f:
        for b in found_buckets:
            f.write(f"{b['name']} - {'Public' if b['public'] else 'Private'}\n")

    print(f"\n[*] Scan complete. Results saved to '{output_file}'")
    print(f"Found {len(found_buckets)} buckets.")


if __name__ == "__main__":
    main()