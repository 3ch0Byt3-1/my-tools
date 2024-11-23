#!/bin/bash

# Tool Installer for Kali Linux
# Author: Tarun
# Purpose: Automate the installation of common penetration testing tools

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Kali Tool Installer Script...${NC}"
echo "------------------------------------------"

# Step 1: Update and upgrade the system
echo -e "${GREEN}Updating and upgrading the system...${NC}"
sudo apt update && sudo apt upgrade -y

# Step 2: Install Go
echo -e "${GREEN}Installing Go programming language...${NC}"
sudo apt install -y golang
export PATH=$PATH:/usr/local/go/bin
echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
source ~/.bashrc

# Step 3: Install tools
install_tool() {
    local tool=$1
    echo -e "${GREEN}Installing $tool...${NC}"
    if sudo apt install -y "$tool"; then
        echo -e "${GREEN}$tool installed successfully!${NC}"
    else
        echo -e "${RED}Failed to install $tool.${NC}"
    fi
}

# Install specific tools
echo -e "${GREEN}Installing Subfinder...${NC}"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo -e "${GREEN}Installing Sublist3r...${NC}"
sudo apt install -y sublist3r

echo -e "${GREEN}Installing Nuclei...${NC}"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

echo -e "${GREEN}Installing Katana...${NC}"
go install github.com/projectdiscovery/katana/cmd/katana@latest

install_tool "sqlmap"
install_tool "nmap"
install_tool "gobuster"

echo -e "${GREEN}Installing Httpx...${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo -e "${GREEN}Installing Ffuf...${NC}"
go install -v github.com/ffuf/ffuf@latest

install_tool "hydra"

# Final Steps
echo -e "${GREEN}Installation completed! Verifying tool installations...${NC}"
echo "----------------------------------------------------"
echo "Subfinder: $(which subfinder)"
echo "Nuclei: $(which nuclei)"
echo "Katana: $(which katana)"
echo "Httpx: $(which httpx)"
echo "Ffuf: $(which ffuf)"
echo "SQLMap: $(which sqlmap)"
echo "Nmap: $(which nmap)"
echo "Gobuster: $(which gobuster)"
echo "Hydra: $(which hydra)"

echo -e "${GREEN}All tools are installed and ready to use!${NC}"
