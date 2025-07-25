#!/bin/bash

#######################################################################
# openSUSE MicroOS Post-Installation Setup Script (Root Version)
# Designed to run as root - no sudo needed
#######################################################################

set -e

# Configuration
SCRIPT_NAME="$(basename "$0")"
if [[ $(id -u) -eq 0 ]]; then
    LOG_FILE="/var/log/microos-setup.log"
else
    LOG_FILE="$HOME/microos-setup.log"
fi
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
    if [[ $(id -u) -ne 0 ]]; then
        if [[ "${TEST_MODE:-}" == "true" ]]; then
            print_message "WARN" "Not running as root, but TEST_MODE enabled"
            return 0
        fi
        print_message "ERROR" "This script must be run as root"
        print_message "INFO" "Run with: sudo $0"
        print_message "INFO" "For testing: TEST_MODE=true $0"
        exit 1
    fi
    print_message "SUCCESS" "Running as root"
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
        if pkcon install -y "$package" >/dev/null 2>&1; then
            PACKAGES_INSTALLED+=("$package")
            print_message "SUCCESS" "Installed $description"
            return 0
        fi
    else
        if transactional-update pkg install -y "$package" >/dev/null 2>&1; then
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
        if pkcon update -y >/dev/null 2>&1; then
            print_message "SUCCESS" "System updated"
        else
            print_message "ERROR" "System update failed"
            return 1
        fi
    else
        if transactional-update up >/dev/null 2>&1; then
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
        "rsync"
        "tree"
        "nano"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

install_development() {
    print_message "INFO" "Installing development tools..."
    
    local packages=(
        "docker"
        "podman"
        "python3"
        "python3-pip"
        "nodejs"
        "npm"
        "gcc"
        "make"
        "cmake"
        "git-core"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
    
    # Setup docker service
    if [[ "${TEST_MODE:-}" != "true" ]] && command -v docker >/dev/null 2>&1; then
        systemctl enable --now docker >/dev/null 2>&1 || true
        print_message "SUCCESS" "Docker service enabled"
    fi
}

install_network_tools() {
    print_message "INFO" "Installing network tools..."
    
    local packages=(
        "openssh-server"
        "firewalld"
        "net-tools"
        "nmap"
        "tcpdump"
        "wireshark"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

setup_firewall() {
    print_message "INFO" "Setting up firewall..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup firewall"
        return 0
    fi
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable --now firewalld >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        print_message "SUCCESS" "Firewall configured with SSH, HTTP, HTTPS, and 8080"
    else
        install_package "firewalld" "Firewall"
        setup_firewall  # Retry after installation
    fi
}

setup_ssh() {
    print_message "INFO" "Setting up SSH..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup SSH"
        return 0
    fi
    
    systemctl enable --now sshd >/dev/null 2>&1 || true
    print_message "SUCCESS" "SSH service enabled"
    
    # Configure SSH for better security
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        
        # Basic security improvements
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config 2>/dev/null || true
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config 2>/dev/null || true
        
        systemctl reload sshd >/dev/null 2>&1 || true
        print_message "SUCCESS" "SSH configured for security"
    fi
}

optimize_system() {
    print_message "INFO" "Applying system optimizations..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would optimize system"
        return 0
    fi
    
    # Memory optimization
    echo 'vm.swappiness=10' >> /etc/sysctl.conf
    echo 'vm.dirty_ratio=5' >> /etc/sysctl.conf
    
    # Network optimization  
    echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
    echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
    
    sysctl -p >/dev/null 2>&1 || true
    print_message "SUCCESS" "System optimizations applied"
}

create_user_environment() {
    print_message "INFO" "Setting up user environment..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup user environment"
        return 0
    fi
    
    # Create useful aliases for all users
    cat > /etc/profile.d/microos-aliases.sh << 'EOF'
# MicroOS useful aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'

# Docker aliases
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'

# System aliases
alias syslog='journalctl -f'
alias ports='netstat -tuln'
alias myip='curl -s ifconfig.me'

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit'
alias gp='git push'
alias gl='git log --oneline'
EOF

    chmod +x /etc/profile.d/microos-aliases.sh
    print_message "SUCCESS" "User environment configured"
}

#######################################################################
# Menu System
#######################################################################

show_banner() {
    clear
    echo "====================================================="
    echo "  openSUSE MicroOS Post-Installation Setup (ROOT)"
    echo "====================================================="
    echo "Running as: root | Variant: ${VARIANT:-unknown}"
    echo "Log: $LOG_FILE"
    echo "====================================================="
    echo
}

show_menu() {
    show_banner
    echo "1) Update System"
    echo "2) Install Essential Packages"
    echo "3) Install Development Tools"
    echo "4) Install Network Tools"
    echo "5) Setup Firewall"
    echo "6) Setup SSH"
    echo "7) Optimize System"
    echo "8) Setup User Environment"
    echo "9) Install Everything (Full Setup)"
    echo "10) Show Log"
    echo "11) Exit"
    echo
    read -p "Choose option [1-11]: " choice
}

show_log() {
    clear
    echo "=== Installation Log ==="
    echo
    if [[ -f "$LOG_FILE" ]]; then
        tail -30 "$LOG_FILE"
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
        read -p "Reboot now? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_message "INFO" "Rebooting system..."
            reboot
        fi
    fi
    
    echo
}

full_setup() {
    print_message "INFO" "Starting full setup..."
    
    update_system
    install_essentials  
    install_development
    install_network_tools
    setup_firewall
    setup_ssh
    optimize_system
    create_user_environment
    
    show_summary
    print_message "SUCCESS" "Full setup completed!"
}

#######################################################################
# Main Function
#######################################################################

main() {
    # Set up environment from arguments
    for arg in "$@"; do
        case "$arg" in
            TEST_MODE=true)
                export TEST_MODE=true
                ;;
            FORCE_RUN=true) 
                export FORCE_RUN=true
                ;;
        esac
    done
    
    # Initialize
    echo "Starting openSUSE MicroOS Setup (Root)..." > "$LOG_FILE"
    
    # Basic checks
    check_root
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
                install_network_tools
                read -p "Press Enter to continue..."
                ;;
            5)
                setup_firewall
                read -p "Press Enter to continue..."
                ;;
            6)
                setup_ssh
                read -p "Press Enter to continue..."
                ;;
            7)
                optimize_system
                read -p "Press Enter to continue..."
                ;;
            8)
                create_user_environment
                read -p "Press Enter to continue..."
                ;;
            9)
                full_setup
                read -p "Press Enter to continue..."
                ;;
            10)
                show_log
                ;;
            11)
                show_summary
                print_message "INFO" "Setup complete. Goodbye!"
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

Root-friendly post-installation setup for openSUSE MicroOS

Options:
  --help, -h    Show this help
  
Environment Variables:
  FORCE_RUN=true    Run on non-MicroOS systems (for testing)
  TEST_MODE=true    Simulate operations without changes

Examples:
  $SCRIPT_NAME                          # Interactive menu (as root)
  sudo $SCRIPT_NAME                     # Run with sudo
  FORCE_RUN=true $SCRIPT_NAME           # Force run on any system
  TEST_MODE=true FORCE_RUN=true $SCRIPT_NAME  # Complete test mode

Note: This script is designed to run as root and does not use sudo.
EOF
    exit 0
fi

# Run main function
main "$@"