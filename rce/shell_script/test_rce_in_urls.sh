#!/bin/bash

# === Domain-Wide RCE Scanner with Single Report ===
# Usage: ./domain_rce_report.sh example.com

DOMAIN="$1"
URL_FILE="/mnt/${DOMAIN}/urls_${DOMAIN}.txt"
OUTPUT_DIR="/mnt/${DOMAIN}/rce_scan_results"
REPORT_FILE="$OUTPUT_DIR/report_${DOMAIN}_$(date +"%Y-%m-%d").txt"
RCE_SCRIPT="./rce_scanner.sh"

if [ -z "$DOMAIN" ]; then
    echo "[!] Usage: $0 <domain>"
    exit 1
fi

if [ ! -f "$URL_FILE" ]; then
    echo "[-] URL file not found: $URL_FILE"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
> "$REPORT_FILE"

echo "[+] Starting domain-wide RCE scan for: $DOMAIN" | tee -a "$REPORT_FILE"
echo "[+] Using URLs from: $URL_FILE" | tee -a "$REPORT_FILE"
echo "[+] Output directory: $OUTPUT_DIR" | tee -a "$REPORT_FILE"

TOTAL_URLS=$(wc -l < "$URL_FILE")
echo "[+] Found $TOTAL_URLS URLs to scan." | tee -a "$REPORT_FILE"

counter=1
findings_found=0

while IFS= read -r URL; do
    [[ -z "$URL" ]] && continue

    SCAN_DIR="$OUTPUT_DIR/scan_$counter"
    mkdir -p "$SCAN_DIR"
    cd "$SCAN_DIR" || exit

    echo "[+] [$counter/$TOTAL_URLS] Scanning: $URL" | tee -a "$REPORT_FILE"

    # Run RCE scanner script
    echo "[*] Running scan..." | tee -a "$REPORT_FILE"
    timeout 120 "$RCE_SCRIPT" "$URL" >> "$SCAN_DIR/output.log" 2>&1

    # Check for findings from Commix
    commix_find=""

    COMMIX_PATH="$SCAN_DIR/rce_scan_results/commix/results.txt"

    if [ -f "$COMMIX_PATH" ]; then
        commix_find=$(cat "$COMMIX_PATH" | grep -A5 -B5 'Vulnerable' | sed 's/^/    /')
    fi

    if [[ -n "$commix_find" ]]; then
        echo "[!] Potential RCE found in: $URL" >> "$REPORT_FILE"
        ((findings_found++))

        echo "Commix Results:" >> "$REPORT_FILE"
        echo "$commix_find" >> "$REPORT_FILE"
        echo "-----------------------------" >> "$REPORT_FILE"
    else
        echo "[*] No RCE patterns detected." >> "$REPORT_FILE"
    fi

    counter=$((counter + 1))
    cd /mnt/"$DOMAIN" || exit
done < "$URL_FILE"

# === Final Summary ===
echo "" >> "$REPORT_FILE"
echo "[+] Scan complete for domain: $DOMAIN" >> "$REPORT_FILE"
echo "[+] Total URLs scanned: $TOTAL_URLS" >> "$REPORT_FILE"
echo "[+] Potential RCE findings: $findings_found" >> "$REPORT_FILE"
echo "[+] Full logs saved in: $OUTPUT_DIR" >> "$REPORT_FILE"

echo ""
echo "[+] Final report generated at: $REPORT_FILE"