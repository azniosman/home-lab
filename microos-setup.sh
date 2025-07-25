#!/bin/bash

#######################################################################
# openSUSE MicroOS Post-Installation Setup Script
# Simple, reliable, and actually works
#######################################################################

set -e

# Configuration
SCRIPT_NAME="$(basename "$0")"
LOG_FILE="$HOME/microos-setup.log"
PACKAGES_INSTALLED=()
FAILED_OPERATIONS=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

#######################################################################
# Basic Functions
#######################################################################

print_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        *) echo "[$level] $message" ;;
    esac
}

check_root() {
    if [[ $(id -u) -eq 0 ]]; then
        print_message "ERROR" "Don't run this script as root"
        print_message "INFO" "Run as your regular user - we'll use sudo when needed"
        exit 1
    fi
    print_message "SUCCESS" "Running as user: $(whoami) (UID: $(id -u))"
}

get_sudo() {
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "WARN" "TEST MODE: Skipping sudo check"
        return 0
    fi
    
    print_message "INFO" "This script needs sudo access for system changes"
    if ! sudo -v; then
        print_message "ERROR" "Need sudo access to continue"
        print_message "INFO" "For testing without sudo: TEST_MODE=true $0"
        exit 1
    fi
    print_message "SUCCESS" "Got sudo access"
}

check_microos() {
    if [[ -f /etc/os-release ]] && grep -q "MicroOS" /etc/os-release; then
        local version=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
        print_message "SUCCESS" "Detected openSUSE MicroOS version: $version"
        return 0
    elif [[ "${FORCE_RUN:-}" == "true" ]]; then
        print_message "WARN" "Not MicroOS but FORCE_RUN is set - continuing"
        return 0
    else
        print_message "ERROR" "This script is for openSUSE MicroOS"
        print_message "INFO" "To run anyway: FORCE_RUN=true $0"
        exit 1
    fi
}

detect_variant() {
    if command -v pkcon >/dev/null 2>&1; then
        VARIANT="desktop"
        print_message "INFO" "Detected Desktop variant (pkcon available)"
    elif command -v transactional-update >/dev/null 2>&1; then
        VARIANT="server"
        print_message "INFO" "Detected Server variant (transactional-update)"
    else
        VARIANT="unknown"
        print_message "WARN" "Cannot detect variant, assuming server"
        VARIANT="server"
    fi
}

#######################################################################
# Package Management
#######################################################################

install_package() {
    local package="$1"
    local description="${2:-$package}"
    
    print_message "INFO" "Installing $description..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        PACKAGES_INSTALLED+=("$package")
        print_message "SUCCESS" "TEST: Would install $description"
        return 0
    fi
    
    if [[ "$VARIANT" == "desktop" ]]; then
        if sudo pkcon install -y "$package" >/dev/null 2>&1; then
            PACKAGES_INSTALLED+=("$package")
            print_message "SUCCESS" "Installed $description"
            return 0
        fi
    else
        if sudo transactional-update pkg install -y "$package" >/dev/null 2>&1; then
            PACKAGES_INSTALLED+=("$package")
            print_message "SUCCESS" "Installed $description (reboot needed)"
            return 0
        fi
    fi
    
    FAILED_OPERATIONS+=("Install $description")
    print_message "ERROR" "Failed to install $description"
    return 1
}

update_system() {
    print_message "INFO" "Updating system..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would update system"
        return 0
    fi
    
    if [[ "$VARIANT" == "desktop" ]]; then
        if sudo pkcon update -y >/dev/null 2>&1; then
            print_message "SUCCESS" "System updated"
        else
            print_message "ERROR" "System update failed"
            return 1
        fi
    else
        if sudo transactional-update up >/dev/null 2>&1; then
            print_message "SUCCESS" "System updated (reboot needed)"
        else
            print_message "ERROR" "System update failed"
            return 1
        fi
    fi
}

#######################################################################
# Installation Functions
#######################################################################

install_essentials() {
    print_message "INFO" "Installing essential packages..."
    
    local packages=(
        "curl"
        "wget" 
        "git"
        "vim"
        "htop"
        "zip"
        "unzip"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

install_development() {
    print_message "INFO" "Installing development tools..."
    
    local packages=(
        "docker"
        "python3"
        "nodejs"
        "npm"
        "gcc"
        "make"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
    
    # Setup docker for user
    if [[ "${TEST_MODE:-}" != "true" ]] && command -v docker >/dev/null 2>&1; then
        sudo usermod -aG docker "$(whoami)" 2>/dev/null || true
        sudo systemctl enable --now docker >/dev/null 2>&1 || true
    fi
}

setup_firewall() {
    print_message "INFO" "Setting up firewall..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup firewall"
        return 0
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        sudo systemctl enable --now firewalld >/dev/null 2>&1 || true
        sudo firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        sudo firewall-cmd --reload >/dev/null 2>&1 || true
        print_message "SUCCESS" "Firewall configured"
    else
        install_package "firewalld" "Firewall"
    fi
}

setup_ssh() {
    print_message "INFO" "Setting up SSH..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup SSH"
        return 0
    fi
    
    sudo systemctl enable --now sshd >/dev/null 2>&1 || true
    
    if [[ ! -f "$HOME/.ssh/id_rsa" ]]; then
        ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N "" >/dev/null 2>&1 || true
        print_message "SUCCESS" "SSH key generated"
    fi
}

#######################################################################
# Menu System
#######################################################################

show_banner() {
    clear
    echo "=================================================="
    echo "  openSUSE MicroOS Post-Installation Setup"
    echo "=================================================="
    echo "User: $(whoami) | Variant: ${VARIANT:-unknown}"
    echo "Log: $LOG_FILE"
    echo "=================================================="
    echo
}

show_menu() {
    show_banner
    echo "1) Update System"
    echo "2) Install Essential Packages"
    echo "3) Install Development Tools"
    echo "4) Setup Firewall"
    echo "5) Setup SSH"
    echo "6) Install Everything (Quick Setup)"
    echo "7) Show Log"
    echo "8) Exit"
    echo
    read -p "Choose option [1-8]: " choice
}

show_log() {
    clear
    echo "=== Installation Log ==="
    echo
    if [[ -f "$LOG_FILE" ]]; then
        tail -20 "$LOG_FILE"
    else
        echo "No log file found"
    fi
    echo
    read -p "Press Enter to continue..."
}

show_summary() {
    echo
    echo "=== Installation Summary ==="
    echo "Packages installed: ${#PACKAGES_INSTALLED[@]}"
    echo "Failed operations: ${#FAILED_OPERATIONS[@]}"
    
    if [[ ${#PACKAGES_INSTALLED[@]} -gt 0 ]]; then
        echo
        echo "Installed packages:"
        printf '  - %s\n' "${PACKAGES_INSTALLED[@]}"
    fi
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        echo
        echo "Failed operations:"
        printf '  - %s\n' "${FAILED_OPERATIONS[@]}"
    fi
    
    if [[ "$VARIANT" == "server" ]] && [[ ${#PACKAGES_INSTALLED[@]} -gt 0 ]]; then
        echo
        print_message "INFO" "Server variant detected - reboot recommended"
    fi
    
    echo
}

quick_setup() {
    print_message "INFO" "Starting quick setup..."
    
    update_system
    install_essentials  
    install_development
    setup_firewall
    setup_ssh
    
    show_summary
    print_message "SUCCESS" "Quick setup completed!"
}

#######################################################################
# Main Function
#######################################################################

main() {
    # Initialize
    echo "Starting openSUSE MicroOS Setup..." > "$LOG_FILE"
    
    # Basic checks
    check_root
    get_sudo
    check_microos
    detect_variant
    
    # Menu loop
    while true; do
        show_menu
        
        case $choice in
            1)
                update_system
                read -p "Press Enter to continue..."
                ;;
            2) 
                install_essentials
                read -p "Press Enter to continue..."
                ;;
            3)
                install_development  
                read -p "Press Enter to continue..."
                ;;
            4)
                setup_firewall
                read -p "Press Enter to continue..."
                ;;
            5)
                setup_ssh
                read -p "Press Enter to continue..."
                ;;
            6)
                quick_setup
                read -p "Press Enter to continue..."
                ;;
            7)
                show_log
                ;;
            8)
                show_summary
                print_message "INFO" "Goodbye!"
                exit 0
                ;;
            *)
                print_message "ERROR" "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Check for help
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << EOF
Usage: $SCRIPT_NAME [options]

Simple post-installation setup for openSUSE MicroOS

Options:
  --help, -h    Show this help
  
Environment Variables:
  FORCE_RUN=true    Run on non-MicroOS systems (for testing)
  TEST_MODE=true    Skip sudo operations (for testing)

Examples:
  $SCRIPT_NAME                          # Interactive menu
  FORCE_RUN=true $SCRIPT_NAME           # Force run on any system
  TEST_MODE=true FORCE_RUN=true $SCRIPT_NAME  # Complete test mode
EOF
    exit 0
fi

# Run main function
main "$@"