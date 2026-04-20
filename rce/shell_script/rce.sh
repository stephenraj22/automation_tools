#!/bin/bash

# === RCE Vulnerability Finder Tool ===
# Designed for ethical hacking and security assessments
# WITHOUT ffuf or Nuclei

TARGET="$1"

if [ -z "$TARGET" ]; then
    echo "[!] Usage: $0 <target-url>"
    exit 1
fi

OUTPUT_DIR="rce_scan_results"
mkdir -p "$OUTPUT_DIR/commix"

echo "[*] Running Commix for command injection detection on $TARGET..."
python3 /home/stephen/github_tools/commix/commix.py --url="$TARGET" --batch --output-dir="$OUTPUT_DIR/commix"

#python3 commix.py --url="http://example.com/page.php?param=value" \
 #--batch \
 #--technique=CMD \
 #--level=3 \
 #--risk=2 \
 #--timeout=10 \
 #--os-cmd="id"

#--batch: Skips all prompts (non-interactive).
#
#--technique=CMD: Focus only on command injection (skip other types).
#
#--level=3: Tests more parameters (more aggressive).
#
#--risk=2: Increase payload risk level.
#
#--timeout=10: Set request timeout.
#
#--os-cmd="id": Automatically run a command like id.

#/mnt/example.com/
#├── urls_example.com.txt      <-- List of URLs to scan
#└── rce_scan_results/
#    ├── report_example.com_YYYY-MM-DD.txt   <-- Final summary
#    ├── scan_1/
#    │   ├── output.log
#    │   └── rce_scan_results/
#    │       └── commix/
#    │           └── results.txt
#    └── scan_2/
#        ├── output.log
#        └── rce_scan_results/
#            └── commix/
#                └── results.txt