#!/bin/bash
#--------------------------------------------------------------------
# Get the website domain as input
read -p "Enter the website URL (e.g., example.com): " website
#--------------------------------------------------------------------
# Input custom wordlist for XSS
read -p "Enter the path to your XSS payload wordlist (e.g., xss_wordlist.txt): " xss_wordlist
#--------------------------------------------------------------------
# Step 1: Subdomain Enumeration with Subfinder, display, and save output to sub1.txt
echo "[+] Running subdomain enumeration on $website..."
subfinder -d "$website" | tee sub1.txt
echo "Subdomains saved to sub1.txt"
#--------------------------------------------------------------------
# Step 3: Run SQLMap on each subdomain, display, and save output to sql.txt
echo "[+] Testing SQL Injection on subdomains from sub1.txt..."
while IFS= read -r domain; do
    sqlmap -u "$domain" --random-agent --batch --forms --threads=5 --level=5 --risk=3 | tee -a sql.txt
done < sub1.txt
echo "SQL Injection results saved to sql.txt"
#--------------------------------------------------------------------
# Step 4: Run Nuclei for vulnerability scanning on each subdomain, display, and save output to nuclei.txt
echo "[+] Running Nuclei vulnerability scan on subdomains from sub1.txt..."
nuclei -l sub1.txt -o nuclei.txt | tee -a nuclei.txt
echo "Nuclei scan results saved to nuclei.txt"
#--------------------------------------------------------------------
# Step 5: Use Httpx to check alive subdomains from sub1.txt, display, and save to alive.txt
echo "[+] Checking for alive subdomains with Httpx..."
httpx -l sub1.txt -o alive.txt | tee alive.txt
echo "Alive subdomains saved to alive.txt"
# Step 7: Run Httpx on results from alive.txt, display, and save to last-dir.txt
echo "[+] Running Httpx on alive domains from alive.txt..."
httpx -l alive.txt -o last-dir.txt | tee last-dir.txt
echo "Final Httpx results saved to last-dir.txt"
#--------------------------------------------------------------------
# Step 6: Run Katana on alive domains from alive.txt, display, and save to alivejs.txt
echo "[+] Running Katana on alive domains from alive.txt..."
katana -l alive.txt -o alivejs.txt | tee alivejs.txt
echo "Katana results saved to alivejs.txt"
#--------------------------------------------------------------------
# Step 2: Run Nmap port scan on subdomains in sub1.txt, display, and save output to nmap.txt
echo "[+] Running port scan on subdomains from sub1.txt..."
nmap -v -A sub1.txt | tee nmap.txt
echo "Nmap results saved to nmap.txt"

#--------------------------------------------------------------------

echo "All tasks completed."
