#!/bin/bash

DOMAINS_FILE="/mnt/automation_tools/base_script/base_domains.txt"

# Check if the domains file exists
if [ ! -f "$DOMAINS_FILE" ]; then
  echo "Error: File $DOMAINS_FILE not found."
  exit 1
fi

# Read the list of domains from the file
DOMAINS=$(cat "$DOMAINS_FILE")

# Tools to execute
JS_ANALYSIS_SCRIPT="/mnt/automation_tools/recon/js_analysis.sh" #recon
SQLI_SCRIPT="/mnt/automation_tools/sqli/shell_script/v1/sqli.sh" #sqli
DIR_TRAVERSAL_SCRIPT="/mnt/automation_tools/directory_traversal/python_script/v1/directory_traversal.py" #directoryTraversal
INSECURE_CONFIG_SCRIPT="/mnt/automation_tools/insecure_configuration/python_script/v1/search_insecure_configuration.py" #securityMisconfiguration
RCE_SCRIPT="/mnt/automation_tools/rce/shell_script/test_rce_in_urls.sh" #rce
SUBDOMAIN_TAKEOVER_SCRIPT="/mnt/automation_tools/subdomain_takeover/subdomain_takeover.py" #subdomainTakeover

# Ensure all scripts exist
for script_path in \
  "$JS_ANALYSIS_SCRIPT" \
  "$SQLI_SCRIPT" \
  "$DIR_TRAVERSAL_SCRIPT" \
  "$INSECURE_CONFIG_SCRIPT" \
  "$RCE_SCRIPT" \
  "$SUBDOMAIN_TAKEOVER_SCRIPT"; do
  if [ ! -f "$script_path" ]; then
    echo "Error: Required script not found at $script_path"
    exit 1
  fi
done

# Function to process a single domain
process_domain() {
  local DOMAIN="$1"

  # Clean domain: remove CR (\r), trim leading/trailing whitespace
  CLEANED_DOMAIN=$(echo "$DOMAIN" | tr -d '\r' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

  # Skip empty or invalid domain entries
  if [ -z "$CLEANED_DOMAIN" ]; then
    echo "[-] Skipping empty or invalid domain entry."
    return
  fi

  echo "[+] Processing domain: $CLEANED_DOMAIN"

  # Run JS Analysis
  echo "[+] Running JS Analysis for $CLEANED_DOMAIN..."
  sudo bash "$JS_ANALYSIS_SCRIPT" "$CLEANED_DOMAIN"
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

  # Run RCE Scan
  echo "[+] Running RCE scan for $CLEANED_DOMAIN..."
  sudo bash "$RCE_SCRIPT" "$CLEANED_DOMAIN"
  if [ $? -ne 0 ]; then
    echo "[-] RCE scan failed for $CLEANED_DOMAIN"
  fi

  # Run Subdomain Takeover Analysis
#  echo "[+] Running Subdomain Takeover analysis for $CLEANED_DOMAIN..."
#  sudo "/mnt/automation_tools/venv/Scripts/python.exe" "$SUBDOMAIN_TAKEOVER_SCRIPT" -f "/mnt/$CLEANED_DOMAIN/domains_$CLEANED_DOMAIN.txt" -d "$CLEANED_DOMAIN"
#  if [ $? -ne 0 ]; then
#    echo "[-] Subdomain Takeover analysis failed for $CLEANED_DOMAIN"
#  fi

  echo "[+] Finished processing domain: $CLEANED_DOMAIN"
}

# Maximum number of parallel processes
MAX_PARALLEL_JOBS=5

# Counter to track active jobs
active_jobs=0

# Loop through each domain and process them in parallel
for DOMAIN in $DOMAINS; do
  # Launch the domain processing in the background
  process_domain "$DOMAIN" &

  # Increment the active job counter
  active_jobs=$((active_jobs + 1))

  # If max jobs reached, wait for one to finish
  if [ $active_jobs -ge $MAX_PARALLEL_JOBS ]; then
    wait -n
    active_jobs=$((active_jobs - 1))
  fi
done

# Wait for any remaining background jobs
wait

echo "[+] All domains processed."