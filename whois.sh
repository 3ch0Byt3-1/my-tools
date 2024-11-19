#!/bin/bash

# API Keys
shodan_key="R8C45zz370Hvp0prryFmF3bED2AZbZE8"
virustotal_key="ae781046ae89ddad6cc80608ad71b9995aecd953bf96ce3de12391529d36f78d"
securitytrails_key="sY2Cq8MTA4BwN7diurC6VM5fpwjyG1DL"
whois_key="at_pF77rN8RmJJKFU2We1l7rqzlD6h7W"

# Function to perform Shodan scan
shodan_scan() {
    echo "Performing Shodan scan for $1..."
    result=$(curl -s "https://api.shodan.io/shodan/host/$1?key=$shodan_key")
    echo -e "\nShodan Results for $1:" 
    echo "$result"
}

# Function to perform VirusTotal scan
virustotal_scan() {
    echo "Performing VirusTotal scan for $1..."
    result=$(curl -s "https://www.virustotal.com/api/v3/files/$1" -H "x-apikey: $virustotal_key")
    echo -e "\nVirusTotal Results for $1:" 
    echo "$result"
}

# Function to perform SecurityTrails lookup
securitytrails_lookup() {
    echo "Performing SecurityTrails lookup for $1..."
    result=$(curl -s "https://api.securitytrails.com/v1/domain/$1" -H "APIKEY: $securitytrails_key")
    echo -e "\nSecurityTrails Results for $1:"
    echo "$result"
}

# Function to perform Whois lookup
whois_lookup() {
    echo "Performing Whois lookup for $1..."
    result=$(curl -s "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$whois_key&domainName=$1&outputFormat=JSON")
    echo -e "\nWhois Results for $1:" 
    echo "$result"
}

# Main script entry
main() {
    # Prompt for user input
    echo "Enter the target domain or IP:"
    read target

    # Validate target input
    if [ -z "$target" ]; then
        echo "Error: No target provided."
        exit 1
    fi

    # Start scanning the target
    echo "Starting scan for target: $target"

    shodan_scan "$target"
    virustotal_scan "$target"
    securitytrails_lookup "$target"
    whois_lookup "$target"

    echo "Scan completed for $target."
}

# Start the process
main

