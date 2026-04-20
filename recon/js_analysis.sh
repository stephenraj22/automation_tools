#!/bin/bash

# Check if a domain is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

domain="$1"
# Use OUTPUT_DIR environment variable if set, otherwise fallback to /mnt
output_dir="${OUTPUT_DIR:-/mnt/${domain}}"
mkdir -p "$output_dir"
# Create filenames with domain included
domains_file="${output_dir}/domains_${domain}.txt"
urls_file="${output_dir}/urls_${domain}.txt"
js_file="${output_dir}/js_${domain}.txt"
json_file="${output_dir}/json_${domain}.txt"
txt_file="${output_dir}/txt_${domain}.txt"

# Run subfinder and save to domains_<domain>.txt
subfinder -d "$domain" | tee "$domains_file"

# Check if the file is empty
if [[ ! -s "$domains_file" ]]; then
    # File is empty, so write the base domain into it
    echo "$domain" > "$domains_file"
fi

# Run waybackurls and save to urls_<domain>.txt
cat "$domains_file" | waybackurls > "$urls_file"

# Extract JavaScript URLs and save to js_<domain>.txt
cat "$urls_file" | grep "\.js" | tee "$js_file"
cat "$urls_file" | grep "\.json" | tee "$json_file"
cat "$urls_file" | grep "\.txt" | tee "$txt_file"

# Run nuclei against the JavaScript URLs
#nuclei -l "$js_file" -t ~/nuclei-templates/http/exposures


# Clean up temporary files (optional)
#rm "$domains_file" "$urls_file" "$js_file"

echo "Nuclei scan completed for $domain."
