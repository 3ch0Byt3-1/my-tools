#!/bin/bash
# Prompt the user for a website
read -p "Enter the website URL (e.g., bytecapsule.io): " website
# Resolve the domain to an IP address using dig
ip_address=$(dig +short "$website" | head -n 1)

# Check if an IP address was found
if [[ -z "$ip_address" ]]; then
    echo "Error: Unable to resolve domain name"
    exit 1
fi
# Query ipinfo.io for detailed IP information
api_token="3c9355c23d88d9"  # Replace with your ipinfo.io API token
response=$(curl -s "https://ipinfo.io/$ip_address/json?token=$api_token")

# Check if the response contains valid data
if echo "$response" | grep -q '"ip"'; then
    echo "Information for $website (IP: $ip_address):"
    echo "$response" | jq
else
    echo "Error: Unable to retrieve information for IP $ip_address"
fi
