#!/bin/bash
# Enhanced Rootkit Detection Demo - Fixed Version

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Global variable for PIDs
declare -a CLEANUP_PIDS=()

# Setup environment and create test program
setup_environment() {
    echo -e "${GREEN}[+] Setting up enhanced test environment...${NC}"
    mkdir -p /tmp/rootkit_demo
    cd /tmp/rootkit_demo || {
        echo -e "${RED}[-] Failed to create/access test directory${NC}"
        exit 1
    }
    
    # Create a more sophisticated test program
    cat > test_program.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    printf("Test program running with PID: %d\n", getpid());
    
    // Create test files safely
    if (access("/tmp/rootkit_demo", W_OK) == 0) {
        system("touch /tmp/rootkit_demo/hidden_file");
        system("chmod 777 /tmp/rootkit_demo/hidden_file");
    }
    
    // Create a test network connection if netcat is available
    if (system("which nc >/dev/null 2>&1") == 0) {
        system("nc -l -p 12345 >/dev/null 2>&1 &");
    }
    
    while(1) {
        sleep(1);
    }
    return 0;
}
EOF
    
    # Compile with error checking
    if ! gcc -g test_program.c -o test_program 2>/dev/null; then
        echo -e "${RED}[-] Failed to compile test program${NC}"
        exit 1
    else
        echo -e "${GREEN}[+] Test program compiled successfully${NC}"
        chmod +x test_program
    fi
}

check_hidden_processes() {
    echo -e "${GREEN}[+] Checking for hidden processes...${NC}"
    ps_list=$(ps aux)
    proc_list=$(ls /proc 2>/dev/null | grep -E "^[0-9]+$")
    
    for pid in $proc_list; do
        if ! echo "$ps_list" | grep -q " $pid "; then
            echo -e "${RED}[!] WARNING: Found potentially hidden process: $pid${NC}"
            if [ -r "/proc/$pid/exe" ]; then
                exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
                cmd_line=$(cat "/proc/$pid/cmdline" 2>/dev/null)
                echo -e "${YELLOW}    → Executable: ${exe_path:-Unknown}${NC}"
                echo -e "${YELLOW}    → Command line: ${cmd_line:-Unknown}${NC}"
            fi
        fi
    done
}

check_file_permissions() {
    echo -e "${GREEN}[+] Checking file permissions and suspicious files...${NC}"
    
    # Check world-writable files with timeout
    echo -e "${YELLOW}[*] Checking world-writable files:${NC}"
    timeout 30 find /bin /sbin /usr/bin /usr/sbin -type f -perm /o+w 2>/dev/null | while read -r file; do
        echo -e "${RED}[!] WARNING: Found world-writable file: $file${NC}"
    done
    
    # Check for hidden files in safe locations
    echo -e "${YELLOW}[*] Checking for hidden files:${NC}"
    find /tmp /var/tmp -type f -name ".*" 2>/dev/null | while read -r file; do
        echo -e "${RED}[!] WARNING: Found hidden file: $file${NC}"
    done
}

check_network() {
    echo -e "${GREEN}[+] Performing network checks...${NC}"
    
    if ! command -v netstat >/dev/null 2>&1; then
        echo -e "${RED}[-] netstat not found, skipping network checks${NC}"
        return 1
    fi
    
    # Check listening ports
    echo -e "${YELLOW}[*] Checking listening ports:${NC}"
    netstat -tulpn 2>/dev/null | grep LISTEN
    
    # Check suspicious ports
    echo -e "${YELLOW}[*] Checking for suspicious ports:${NC}"
    suspicious_ports="12345 31337 4444 5555"
    for port in $suspicious_ports; do
        if netstat -an 2>/dev/null | grep -q ":$port "; then
            echo -e "${RED}[!] WARNING: Found suspicious port: $port${NC}"
        fi
    done
}

check_system_integrity() {
    echo -e "${GREEN}[+] Checking system integrity...${NC}"
    
    # Check for modified system binaries
    echo -e "${YELLOW}[*] Checking common system binaries:${NC}"
    for binary in /bin/ls /bin/ps /bin/netstat /bin/passwd; do
        if [ -f "$binary" ] && [ -r "$binary" ]; then
            md5sum "$binary" 2>/dev/null
        fi
    done
    
    # Check loaded kernel modules
    if command -v lsmod >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] Checking loaded kernel modules:${NC}"
        lsmod | head -n 5
    fi
}

cleanup() {
    echo -e "${GREEN}[+] Cleaning up...${NC}"
    
    # Kill all tracked PIDs
    for pid in "${CLEANUP_PIDS[@]}"; do
        kill $pid 2>/dev/null || true
    done
    
    # Kill any remaining nc processes
    pkill -f "nc -l -p 12345" 2>/dev/null || true
    
    # Remove test directory safely
    if [ -d "/tmp/rootkit_demo" ]; then
        rm -rf /tmp/rootkit_demo
    fi
    
    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

check_dependencies() {
    local missing_tools=()
    
    for tool in gcc netstat find md5sum lsmod nc; do
        if ! command -v $tool >/dev/null 2>&1; then
            missing_tools+=($tool)
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo -e "${YELLOW}[*] Installing missing tools: ${missing_tools[*]}${NC}"
        apt-get update && apt-get install -y build-essential net-tools netcat-openbsd
        # Check again after installation
        for tool in "${missing_tools[@]}"; do
            if ! command -v $tool >/dev/null 2>&1; then
                echo -e "${RED}[-] Failed to install: $tool${NC}"
                exit 1
            fi
        done
    fi
}

main() {
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        echo -e "${RED}[-] Please run as root (use sudo)${NC}"
        exit 1
    fi
    
    # Set up cleanup trap
    trap cleanup EXIT INT TERM
    
    # Check dependencies
    check_dependencies
    
    # Setup
    setup_environment
    
    echo -e "${GREEN}[+] Starting test program...${NC}"
    ./test_program & # Start test program in background
    TEST_PID=$!
    CLEANUP_PIDS+=($TEST_PID)
    echo -e "${GREEN}[+] Test program started with PID: $TEST_PID${NC}"
    
    # Wait for test program to setup
    sleep 2
    
    # Run detection
    run_detection
}

run_detection() {
    echo -e "${GREEN}[+] Starting enhanced detection scan...${NC}"
    check_hidden_processes
    check_file_permissions
    check_network
    check_system_integrity
    echo -e "${GREEN}[+] Scan complete.${NC}"
}

# Run main function
main
