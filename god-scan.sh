#!/bin/bash

# Advanced Firewall Assessment & Bypass Tool
# Author: Security Professional
# Version: 2.0
# Usage: ./firewall_audit.sh <target> [options]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Global variables
TARGET=""
AGGRESSIVE=false
STEALTH=false
OUTPUT_DIR="scan_results"
CURRENT_DATE=$(date +"%Y-%m-%d_%H-%M-%S")

# Check if running as root
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root${NC}"
        exit 1
    fi
}

# Check for required tools
check_tools() {
    local required_tools=("nmap" "hping3" "curl" "netcat" "dnsenum" "whois" "ike-scan" "sslscan" "nikto" "whatweb")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing tools: ${missing_tools[*]}${NC}"
        echo "Install them with: sudo apt install ${missing_tools[*]}"
        read -p "Attempt to install missing tools? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            sudo apt update && sudo apt install -y "${missing_tools[@]}"
        else
            exit 1
        fi
    fi
}

# Create output directory
setup_environment() {
    if [ ! -d "$OUTPUT_DIR" ]; then
        mkdir -p "$OUTPUT_DIR"
    fi
    mkdir -p "$OUTPUT_DIR/$TARGET/$CURRENT_DATE"
}

# Banner
show_banner() {
    echo -e "${PURPLE}"
    echo "  ____ ___ _   _ _____ ____   ___  _   _ _____ ____ _____ ___  ____  "
    echo " | __ )_ _| \ | |  ___|  _ \ / _ \| | | |_   _/ ___|_   _/ _ \|  _ \ "
    echo " |  _ \| ||  \| | |_  | |_) | | | | | | | | | \___ \ | || | | | |_) |"
    echo " | |_) | || |\  |  _| |  _ <| |_| | |_| | | |  ___) || || |_| |  __/ "
    echo " |____/___|_| \_|_|   |_| \_\\___/ \___/  |_| |____/ |_| \___/|_|    "
    echo -e "${NC}"
    echo "                   Advanced Firewall Assessment Suite"
    echo "===================================================================="
}

# Help menu
show_help() {
    echo -e "${GREEN}Usage: $0 <target> [options]${NC}"
    echo
    echo "Options:"
    echo "  --aggressive  Run intensive scans (takes longer)"
    echo "  --stealth     Use slower, stealthier scanning techniques"
    echo "  --help        Show this help message"
    echo
    echo "Examples:"
    echo "  $0 192.168.1.1"
    echo "  $0 example.com --aggressive"
    echo "  $0 10.0.0.1/24 --stealth"
}

# Basic reconnaissance
basic_recon() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/basic_recon.txt"
    
    echo -e "${YELLOW}[*] Performing basic reconnaissance...${NC}"
    
    # WHOIS lookup
    echo -e "${BLUE}[>] WHOIS lookup...${NC}"
    whois "$TARGET" | tee -a "$output_file"
    
    # DNS enumeration
    echo -e "${BLUE}[>] DNS enumeration...${NC}"
    dnsenum "$TARGET" | tee -a "$output_file"
    
    # Ping sweep if network range
    if [[ "$TARGET" == *"/"* ]]; then
        echo -e "${BLUE}[>] Ping sweep...${NC}"
        nmap -sn -PE "$TARGET" | tee -a "$output_file"
    fi
}

# Port scanning
port_scanning() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/port_scanning.txt"
    
    echo -e "${YELLOW}[*] Starting port scanning...${NC}"
    
    # Initial quick scan
    echo -e "${BLUE}[>] Quick scan (top 1000 ports)...${NC}"
    nmap -T4 -Pn -n --top-ports 1000 --open -oN "$OUTPUT_DIR/$TARGET/$CURRENT_DATE/quick_scan.txt" "$TARGET"
    
    # Service detection
    open_ports=$(grep 'open' "$OUTPUT_DIR/$TARGET/$CURRENT_DATE/quick_scan.txt" | awk -F '/' '{print $1}' | tr '\n' ',')
    if [ -n "$open_ports" ]; then
        echo -e "${BLUE}[>] Service detection on open ports...${NC}"
        nmap -sV -sC -O -T4 -Pn -n -p "$open_ports" -oN "$OUTPUT_DIR/$TARGET/$CURRENT_DATE/service_scan.txt" "$TARGET"
    fi
    
    # Full port scan if aggressive
    if [ "$AGGRESSIVE" = true ]; then
        echo -e "${BLUE}[>] Full port scan (aggressive)...${NC}"
        nmap -p- -T4 -Pn -n --max-retries 1 -oN "$OUTPUT_DIR/$TARGET/$CURRENT_DATE/full_scan.txt" "$TARGET"
    fi
    
    # UDP scan if aggressive
    if [ "$AGGRESSIVE" = true ]; then
        echo -e "${BLUE}[>] UDP top 100 ports scan...${NC}"
        nmap -sU -T4 -Pn -n --top-ports 100 -oN "$OUTPUT_DIR/$TARGET/$CURRENT_DATE/udp_scan.txt" "$TARGET"
    fi
}

# Firewall detection
firewall_detection() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/firewall_detection.txt"
    
    echo -e "${YELLOW}[*] Detecting firewall presence and rules...${NC}"
    
    # ACK scan for stateful firewalls
    echo -e "${BLUE}[>] ACK scan...${NC}"
    nmap -sA -T4 -Pn -n -oN "$output_file" "$TARGET"
    
    # Window scan for rule detection
    echo -e "${BLUE}[>] Window scan...${NC}"
    nmap -sW -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # FIN scan for stateless firewalls
    echo -e "${BLUE}[>] FIN scan...${NC}"
    nmap -sF -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # NULL scan
    echo -e "${BLUE}[>] NULL scan...${NC}"
    nmap -sN -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # XMAS scan
    echo -e "${BLUE}[>] XMAS scan...${NC}"
    nmap -sX -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # Firewalking
    echo -e "${BLUE}[>] Firewalking test...${NC}"
    hping3 -S -p 80 "$TARGET" -c 3 | tee -a "$output_file"
}

# Firewall bypass techniques
firewall_bypass() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/firewall_bypass.txt"
    
    echo -e "${YELLOW}[*] Attempting firewall bypass techniques...${NC}"
    
    # Fragmented packets
    echo -e "${BLUE}[>] Fragmented packets...${NC}"
    nmap -f -T4 -Pn -n -oN "$output_file" "$TARGET"
    
    # MTU fragmentation
    echo -e "${BLUE}[>] MTU fragmentation (24 bytes)...${NC}"
    nmap --mtu 24 -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # Decoy scan
    echo -e "${BLUE}[>] Decoy scan...${NC}"
    nmap -D RND:10 -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # Source port scan
    echo -e "${BLUE}[>] Source port 53 (DNS)...${NC}"
    nmap -g 53 -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    echo -e "${BLUE}[>] Source port 80 (HTTP)...${NC}"
    nmap -g 80 -T4 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # Timing template
    echo -e "${BLUE}[>] Slow scan (T1)...${NC}"
    nmap -T1 -Pn -n -oN "$output_file" -append-output "$TARGET"
    
    # IP spoofing test
    echo -e "${BLUE}[>] IP spoofing test...${NC}"
    hping3 -a 192.168.1.100 -S -p 80 "$TARGET" -c 3 | tee -a "$output_file"
    
    # DNS tunneling test
    echo -e "${BLUE}[>] DNS tunneling test...${NC}"
    dnsenum "$TARGET" | tee -a "$output_file"
}

# Web application tests
web_tests() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/web_tests.txt"
    
    echo -e "${YELLOW}[*] Running web application tests...${NC}"
    
    # Check common HTTP ports
    local ports="80 443 8080 8443 8000 8008 8888"
    for port in $ports; do
        echo -e "${BLUE}[>] Testing HTTP on port $port...${NC}"
        curl -v --connect-timeout 5 "http://$TARGET:$port" 2>&1 | grep -i "server\|http" | tee -a "$output_file"
        curl -v --connect-timeout 5 -k "https://$TARGET:$port" 2>&1 | grep -i "server\|http" 2>/dev/null | tee -a "$output_file"
    done
    
    # HTTP header manipulation
    echo -e "${BLUE}[>] HTTP header manipulation...${NC}"
    curl -v --connect-timeout 5 -H "X-Forwarded-For: 192.168.1.100" "http://$TARGET" | tee -a "$output_file"
    curl -v --connect-timeout 5 -H "User-Agent: Mozilla/5.0" "http://$TARGET" | tee -a "$output_file"
    curl -v --connect-timeout 5 -H "Host: example.com" "http://$TARGET" | tee -a "$output_file"
    
    # HTTP methods test
    echo -e "${BLUE}[>] HTTP methods test...${NC}"
    curl -v -X OPTIONS "http://$TARGET" | tee -a "$output_file"
    curl -v -X TRACE "http://$TARGET" | tee -a "$output_file"
    curl -v -X TEST "http://$TARGET" | tee -a "$output_file"
    
    # SSL/TLS scanning
    echo -e "${BLUE}[>] SSL/TLS scanning...${NC}"
    sslscan "$TARGET" | tee -a "$output_file"
    
    # Nikto scan if aggressive
    if [ "$AGGRESSIVE" = true ]; then
        echo -e "${BLUE}[>] Nikto web vulnerability scan...${NC}"
        nikto -h "$TARGET" | tee -a "$output_file"
    fi
    
    # WhatWeb scan
    echo -e "${BLUE}[>] WhatWeb technology detection...${NC}"
    whatweb -a 3 "$TARGET" | tee -a "$output_file"
}

# VPN/IPSEC tests
vpn_tests() {
    local output_file="$OUTPUT_DIR/$TARGET/$CURRENT_DATE/vpn_tests.txt"
    
    echo -e "${YELLOW}[*] Running VPN/IPSEC tests...${NC}"
    
    # IKE scanning
    echo -e "${BLUE}[>] IKE scan...${NC}"
    ike-scan "$TARGET" | tee -a "$output_file"
    
    # IPSEC ports check
    echo -e "${BLUE}[>] IPSEC ports scan...${NC}"
    nmap -sU -p 500,4500 "$TARGET" | tee -a "$output_file"
}

# Main function
main() {
    check_root
    check_tools
    show_banner
    
    # Parse arguments
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    TARGET="$1"
    shift
    
    while [ $# -gt 0 ]; do
        case "$1" in
            --aggressive)
                AGGRESSIVE=true
                ;;
            --stealth)
                STEALTH=true
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Unknown option: $1${NC}"
                show_help
                exit 1
                ;;
        esac
        shift
    done
    
    echo -e "${GREEN}[+] Target: $TARGET${NC}"
    echo -e "${GREEN}[+] Aggressive mode: $AGGRESSIVE${NC}"
    echo -e "${GREEN}[+] Stealth mode: $STEALTH${NC}"
    echo -e "${GREEN}[+] Output directory: $OUTPUT_DIR/$TARGET/$CURRENT_DATE${NC}"
    
    setup_environment
    basic_recon
    port_scanning
    firewall_detection
    firewall_bypass
    web_tests
    vpn_tests
    
    echo -e "${GREEN}[+] Scan completed! Results saved to $OUTPUT_DIR/$TARGET/$CURRENT_DATE${NC}"
    
    # Zip results
    zip -r "$OUTPUT_DIR/$TARGET/$CURRENT_DATE.zip" "$OUTPUT_DIR/$TARGET/$CURRENT_DATE" > /dev/null 2>&1
    echo -e "${GREEN}[+] Results archived to $OUTPUT_DIR/$TARGET/$CURRENT_DATE.zip${NC}"
}

main "$@"
