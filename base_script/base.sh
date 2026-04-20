#!/bin/bash

# Check if the input file is provided as an argument
#if [ -z "$1" ]; then
#  echo "Usage: $0 <domains_file>"
#  exit 1
#fi

DOMAINS_FILE="/mnt/automation_tools/base_script/base_domains.txt"

# Check if the domains file exists
if [ ! -f "$DOMAINS_FILE" ]; then
  echo "Error: File $DOMAINS_FILE not found."
  exit 1
fi

# Read the list of domains from the file
DOMAINS=$(cat "$DOMAINS_FILE" | tr '\r' '\n' | sed 's/[[:space:]]*$//')

# Tools to execute
JS_ANALYSIS_SCRIPT="/mnt/automation_tools/recon/js_analysis.sh"
SQLI_SCRIPT="/mnt/automation_tools/sqli/shell_script/v1/sqli.sh"
DIR_TRAVERSAL_SCRIPT="/mnt/automation_tools/directory_traversal/python_script/v1/directory_traversal.py"
INSECURE_CONFIG_SCRIPT="/mnt/automation_tools/insecure_configuration/python_script/v2/search_insecure_configuration.py"
RCE_SCRIPT="/mnt/automation_tools/rce/shell_script/test_rce_in_urls.sh"

# Ensure all scripts exist
for script_path in \
  "$JS_ANALYSIS_SCRIPT" \
  "$SQLI_SCRIPT" \
  "$DIR_TRAVERSAL_SCRIPT" \
  "$INSECURE_CONFIG_SCRIPT" \
  "$RCE_SCRIPT"; do
  if [ ! -f "$script_path" ]; then
    echo "Error: Required script not found at $script_path"
    exit 1
  fi
done

# Loop through each domain and execute the tools
for DOMAIN in $DOMAINS; do
  # Clean domain name
  CLEANED_DOMAIN=$(echo "$DOMAIN" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  if [ -z "$CLEANED_DOMAIN" ]; then
    echo "[-] Skipping empty or invalid domain entry."
    continue
  fi

  echo "[+] Processing domain: $CLEANED_DOMAIN"

  # Run JS Analysis
  echo "[+] Running JS Analysis for $CLEANED_DOMAIN..."
  sudo sh "$JS_ANALYSIS_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] JS Analysis failed for $CLEANED_DOMAIN"
  fi

  # Run SQL Injection
  echo "[+] Running SQL Injection analysis for $CLEANED_DOMAIN..."
  sudo sh "$SQLI_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] SQL Injection analysis failed for $CLEANED_DOMAIN"
  fi

  # Run Directory Traversal
  echo "[+] Running Directory Traversal analysis for $CLEANED_DOMAIN..."
  sudo python3 "$DIR_TRAVERSAL_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] Directory Traversal analysis failed for $CLEANED_DOMAIN"
  fi

  # Run Insecure Configuration
  echo "[+] Running Insecure Configuration analysis for $CLEANED_DOMAIN..."
  sudo python3 "$INSECURE_CONFIG_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] Insecure Configuration analysis failed for $CLEANED_DOMAIN"
  fi

  # Run RCE Checker
  echo "[+] Running RCE scan for $CLEANED_DOMAIN..."
  sudo bash "$RCE_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] RCE scan failed for $CLEANED_DOMAIN"
  fi

  echo "[+] Finished processing domain: $CLEANED_DOMAIN"
  echo "==============================================="
done

echo "[+] All domains processed."