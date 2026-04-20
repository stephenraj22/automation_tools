#!/bin/bash

# === CONFIGURATION === #
BASE_DOMAIN="rubygems.org"
OUTPUT_DIR="/mnt/recon_output"
SUBDOMAINS_FILE="$OUTPUT_DIR/subdomains.txt"
ALIVE_URLS_FILE="$OUTPUT_DIR/alive_urls.txt"
PORT_SCAN_FILE="$OUTPUT_DIR/port_scan.txt"
SCREENSHOT_DIR="$OUTPUT_DIR/screenshots"
NUCLEI_TEMPLATES="/home/stephen/nuclei-templates"

# === FLAGS === #
RUN_SUBDOMAIN=false
RUN_PORTSCAN=false
RUN_SCREENSHOT=false
RUN_NUCLEI=false

# === HELP FUNCTION === #
usage() {
    echo "Usage: $0 [--sub] [--port] [--screenshot] [--nuclei] [--all]"
    exit 1
}

# === PARSE COMMAND LINE ARGS === #
while [ "$1" != "" ]; do
    case $1 in
        --sub ) RUN_SUBDOMAIN=true ;;
        --port ) RUN_PORTSCAN=true ;;
        --screenshot ) RUN_SCREENSHOT=true ;;
        --nuclei ) RUN_NUCLEI=true ;;
        --all )
            RUN_SUBDOMAIN=true
            RUN_PORTSCAN=true
            RUN_SCREENSHOT=true
            RUN_NUCLEI=true
            ;;
        * ) usage ;;
    esac
    shift
done

# === CREATE OUTPUT DIR === #
mkdir -p "$OUTPUT_DIR" "$SCREENSHOT_DIR"

echo "[+] Starting Modular Recon for $BASE_DOMAIN"

# === MODULE 1: SUBDOMAIN ENUMERATION === #
if $RUN_SUBDOMAIN; then
    echo "[*] Running Subdomain Enumeration..."
    subfinder -d $BASE_DOMAIN -o "$OUTPUT_DIR/subfinder_subs.txt" -silent
    #assetfinder --subs-only $BASE_DOMAIN > "$OUTPUT_DIR/assetfinder_subs.txt"
    cat "$OUTPUT_DIR/subfinder_subs.txt" "$OUTPUT_DIR/assetfinder_subs.txt" | sort -u > "$SUBDOMAINS_FILE"
    echo "[+] Subdomains saved to $SUBDOMAINS_FILE"
fi

# === MODULE 2: PORT SCANNING === #
if $RUN_PORTSCAN; then
    echo "[*] Running Port Scanning..."
    naabu -list "$SUBDOMAINS_FILE" -p - -rate 1000 -o "$PORT_SCAN_FILE" -silent
    echo "[+] Open ports saved to $PORT_SCAN_FILE"
fi

# === MODULE 3: HTTPX + SCREENSHOTS === #
if $RUN_SCREENSHOT; then
    echo "[*] Probing URLs and Taking Screenshots..."
    httpx -l "$SUBDOMAINS_FILE" -silent -threads 50 | tee "$ALIVE_URLS_FILE"
    gowitness file -f "$ALIVE_URLS_FILE" -P "$SCREENSHOT_DIR" --disable-db --no-headless
    echo "[+] Screenshots saved to $SCREENSHOT_DIR/"
fi

# === MODULE 4: NUCLEI SCAN === #
if $RUN_NUCLEI && [ -f "$ALIVE_URLS_FILE" ] && [ -s "$ALIVE_URLS_FILE" ]; then
    echo "[*] Running Nuclei Scan..."
    nuclei -u "$ALIVE_URLS_FILE" -t "$NUCLEI_TEMPLATES" -severity low,medium,high,critical -o "$OUTPUT_DIR/nuclei_results.txt"
    echo "[+] Nuclei results saved to $OUTPUT_DIR/nuclei_results.txt"
elif $RUN_NUCLEI; then
    echo "[!] No alive URLs found. Skipping Nuclei scan."
fi

echo "[+] Recon complete!"