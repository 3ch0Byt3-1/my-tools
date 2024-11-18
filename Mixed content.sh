#!/bin/bash

# Prompt for the target website URL
read -p "Enter the HTTPS website URL (e.g., https://example.com): " url

# Fetch the webpage and extract all resource URLs
echo "Scanning $url for mixed content..."
resources=$(curl -s "$url" | grep -Eo 'http[s]?://[^"]+')

# Check each resource for insecure HTTP
mixed_content=false
while IFS= read -r resource; do
    if [[ "$resource" == http://* ]]; then
        echo "Mixed Content Found: $resource"
        mixed_content=true
    fi
done <<< "$resources"

if [ "$mixed_content" = false ]; then
    echo "No mixed content detected on $url."
else
    echo "Mixed content detected. Ensure all resources are loaded over HTTPS."
fi
