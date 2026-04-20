#!/bin/bash

# === CONFIGURATION ===
DOMAIN="$1"
OUTPUT_DIR="recon_output"
S3_BUCKET_WORDLIST="/path/to/bucket_finder/wordlist.txt"  # Update this path
SSH_USER="admin"
SSH_PASS="admin"

# === CREATE OUTPUT FOLDER ===
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR" || exit

# === FUNCTION: Check if command exists ===
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "[!] Error: $1 not found. Please install it first."
        exit 1
    fi
}

# === CHECK REQUIRED TOOLS ===
check_tool subfinder
check_tool httprobe
check_tool nmap
check_tool aws

# === 1. SUBDOMAIN ENUMERATION ===
echo "[+] Enumerating subdomains..."
subfinder -d "$DOMAIN" -o subdomains.txt --silent

# === 2. PROBE FOR ALIVE DOMAINS ===
echo "[+] Probing for alive domains..."
cat subdomains.txt | httprobe > alive.txt

# === 3. PORT SCANNING ===
echo "[+] Scanning open ports on live hosts..."
nmap -iL alive.txt -p 22,80,443,8080,3306,5432,27017 --open -sV -oN open_ports.txt

# === 4. S3 BUCKET ENUMERATION ===
echo "[+] Checking for S3 buckets related to $DOMAIN..."
grep -i "s3" subdomains.txt | while read -r line; do
    echo "[*] Checking bucket: $line"
    aws s3 ls "s3://$line" 2>&1 | grep -v "NoSuchBucket" | tee -a s3_buckets.txt
done

# If you want to use bucket_finder:
if [ -f "$S3_BUCKET_WORDLIST" ]; then
    echo "[+] Using custom wordlist with bucket_finder..."
    python3 /path/to/bucket_finder/bucket_finder.py --download "$DOMAIN" -w "$S3_BUCKET_WORDLIST"
fi

# === 5. CLOUD ENUMERATION (AWS) ===
echo "[+] Enumerating AWS resources..."

# Public RDS Instances
echo "[*] Checking public RDS instances..."
aws rds describe-db-instances | jq -r '.DBInstances[] | select(.PubliclyAccessible == true) | .DBInstanceIdentifier' 2>/dev/null >> aws_public_rds.txt

# IAM Policies
echo "[*] Listing IAM policies..."
aws iam list-policies --scope Local --query 'PolicyNames[]' --output text >> iam_policies.txt

# === 6. DEFAULT CREDENTIAL CHECK (SSH EXAMPLE) ===
echo "[+] Testing default credentials on open SSH hosts..."
grep -A 5 "open port 22" open_ports.txt | grep "Nmap scan report" | awk '{print $NF}' | sort -u | while read -r ip; do
    echo "[*] Trying admin/admin on $ip..."
    timeout 3 sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no "$SSH_USER@$ip" "echo 'Login successful'" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[!] Success: Default credentials work on $ip" >> default_creds_found.txt
    else
        echo "[-] Failed on $ip"
    fi
done

# === 7. VERBOSE ERROR DETECTION ===
echo "[+] Checking for verbose errors..."
while read -r url; do
    echo "[*] Testing $url"
    curl -s -I "$url"
    response=$(curl -s "$url/nonexistent-path-1234")
    if [[ "$response" == *"Traceback"* || "$response" ==*"Exception"* ]]; then
        echo "[!] Verbose error detected at $url" >> verbose_errors.txt
    fi
done < alive.txt

# === DONE ===
echo "[+] Recon completed. Results saved in $OUTPUT_DIR/"