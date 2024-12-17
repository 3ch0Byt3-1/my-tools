#!/bin/bash
----
# Prompt the user for the target URL
read -p "Enter the target URL (e.g., https://example.com): " url

read -p "Enter the parameter name to test (e.g., message): " param

read -p "Enter the payload to inject (e.g., TestInjection): " payload
# Construct the full URL with the parameter and payload
full_url="${url}?${param}=${payload}"
echo "Testing URL: $full_url"

# Send a GET request to the URL
response=$(curl -s "$full_url")
# Check if the payload appears in the response
if echo "$response" | grep -q "$payload"; then
    echo "Potential Text Injection Vulnerability Found!"
    echo "Injected Payload: $payload"
    echo "First 500 characters of response:"
    echo "$response" | head -c 500
else
    echo "No Text Injection Detected."
fi
