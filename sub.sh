#!/bin/bash
#--------------------------------------------------------------------
# Author: Tarun
# Date: 2024-11-17
# Description: This script fetches subdomains of a given domain using the SecurityTrails API and appends the domain name.#------------------------------------------------------------------------------------------------------------------------# Prompt for the domain name
#--------------------------------------------------------------------
read -p "Enter the domain (e.g., apple.com): " domain
#--------------------------------------------------------------------
curl "https://api.securitytrails.com/v1/domain/$domain/subdomains" \
-H "apikey: sY2Cq8MTA4BwN7diurC6VM5fpwjyG1DL" | \
jq -r ".subdomains[] + \".$domain\""

