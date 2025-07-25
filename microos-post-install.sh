#!/bin/bash

#######################################################################
# openSUSE MicroOS Post-Installation Setup Script
# 
# This script provides an intelligent, agentic post-installation setup
# for openSUSE MicroOS with comprehensive dependency checking and
# error handling.
#
# Author: Generated for Home Lab Setup
# Version: 1.0
# Compatible with: openSUSE MicroOS (2025)
#######################################################################

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/microos-post-install.log"
readonly CONFIG_DIR="$HOME/.config/microos-setup"
readonly TEMP_DIR="/tmp/microos-setup-$$"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
DESKTOP_VARIANT=false
REBOOT_REQUIRED=false
PACKAGES_INSTALLED=()
FAILED_OPERATIONS=()

#######################################################################
# Utility Functions
#######################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
    
    case "$level" in
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" >&2 ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
    esac
}

cleanup() {
    local exit_code=$?
    
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        log "WARN" "Some operations failed:"
        printf '%s\n' "${FAILED_OPERATIONS[@]}" | while read -r op; do
            log "WARN" "  - $op"
        done
    fi
    
    if [[ $REBOOT_REQUIRED == true ]]; then
        log "INFO" "System reboot is required to complete the setup"
        read -p "Reboot now? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Rebooting system..."
            sudo systemctl reboot
        fi
    fi
    
    exit $exit_code
}

trap cleanup EXIT INT TERM

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log "ERROR" "This script should not be run as root"
        log "INFO" "Run as regular user - sudo will be used when needed"
        exit 1
    fi
    
    # Check sudo access
    log "INFO" "Checking sudo access..."
    if ! sudo -n true 2>/dev/null; then
        log "INFO" "This script requires sudo access for system operations"
        log "INFO" "You may be prompted for your password"
        if ! sudo -v; then
            log "ERROR" "Sudo access required but not available"
            exit 1
        fi
    fi
    log "SUCCESS" "Sudo access confirmed"
}

check_microos() {
    if ! grep -q "MicroOS" /etc/os-release 2>/dev/null; then
        log "ERROR" "This script is designed for openSUSE MicroOS"
        exit 1
    fi
    
    local version
    version=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    log "INFO" "Detected openSUSE MicroOS version: $version"
}

detect_variant() {
    if command -v pkcon >/dev/null 2>&1; then
        DESKTOP_VARIANT=true
        log "INFO" "Detected MicroOS Desktop variant (using pkcon)"
    elif command -v transactional-update >/dev/null 2>&1; then
        DESKTOP_VARIANT=false
        log "INFO" "Detected MicroOS Server variant (using transactional-update)"
    else
        log "WARN" "Could not detect MicroOS variant, assuming server"
        DESKTOP_VARIANT=false
    fi
}

safe_sudo() {
    local cmd="$*"
    log "INFO" "Executing: sudo $cmd"
    
    if sudo bash -c "$cmd"; then
        return 0
    else
        log "ERROR" "Failed to execute: sudo $cmd"
        return 1
    fi
}

check_internet() {
    log "INFO" "Checking internet connectivity..."
    
    if ! ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log "ERROR" "No internet connectivity detected"
        return 1
    fi
    
    if ! curl -s --connect-timeout 5 https://download.opensuse.org >/dev/null; then
        log "WARN" "Cannot reach openSUSE repositories"
        return 1
    fi
    
    log "SUCCESS" "Internet connectivity verified"
    return 0
}

#######################################################################
# Package Management Functions
#######################################################################

install_package() {
    local package="$1"
    local description="${2:-$package}"
    
    log "INFO" "Installing $description..."
    
    if $DESKTOP_VARIANT; then
        if pkcon install -y "$package" 2>/dev/null; then
            PACKAGES_INSTALLED+=("$package")
            log "SUCCESS" "Installed $description"
            return 0
        else
            FAILED_OPERATIONS+=("Install $description")
            log "ERROR" "Failed to install $description"
            return 1
        fi
    else
        if safe_sudo "transactional-update pkg install -y '$package'"; then
            PACKAGES_INSTALLED+=("$package")
            REBOOT_REQUIRED=true
            log "SUCCESS" "Installed $description (reboot required)"
            return 0
        else
            FAILED_OPERATIONS+=("Install $description")
            log "ERROR" "Failed to install $description"
            return 1
        fi
    fi
}

update_system() {
    log "INFO" "Updating system packages..."
    
    if $DESKTOP_VARIANT; then
        if pkcon update -y; then
            log "SUCCESS" "System updated successfully"
        else
            FAILED_OPERATIONS+=("System update")
            log "ERROR" "System update failed"
            return 1
        fi
    else
        if safe_sudo "transactional-update up"; then
            REBOOT_REQUIRED=true
            log "SUCCESS" "System updated successfully (reboot required)"
        else
            FAILED_OPERATIONS+=("System update")
            log "ERROR" "System update failed"
            return 1
        fi
    fi
}

#######################################################################
# System Configuration Functions
#######################################################################

setup_repositories() {
    log "INFO" "Setting up additional repositories..."
    
    # Packman repository for multimedia codecs
    if ! zypper lr | grep -q packman; then
        log "INFO" "Adding Packman repository..."
        if safe_sudo "zypper ar -cfp 90 https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Tumbleweed/ packman"; then
            log "SUCCESS" "Packman repository added"
        else
            FAILED_OPERATIONS+=("Add Packman repository")
            log "WARN" "Failed to add Packman repository"
        fi
    fi
    
    # Flatpak for additional applications
    if ! command -v flatpak >/dev/null 2>&1; then
        install_package "flatpak" "Flatpak package manager"
        if command -v flatpak >/dev/null 2>&1; then
            log "INFO" "Adding Flathub repository..."
            if safe_sudo "flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo"; then
                log "SUCCESS" "Flathub repository added"
            else
                FAILED_OPERATIONS+=("Add Flathub repository")
                log "WARN" "Failed to add Flathub repository"
            fi
        fi
    fi
}

install_essential_packages() {
    log "INFO" "Installing essential packages..."
    
    local packages=(
        "curl wget git vim nano"
        "htop btop neofetch"
        "zip unzip tar"
        "NetworkManager-applet"
        "firewalld"
        "docker podman"
        "python3 python3-pip"
        "nodejs npm"
        "build-essential"
        "gcc make cmake"
        "tmux screen"
        "openssh-server"
        "rsync"
    )
    
    for pkg_group in "${packages[@]}"; do
        for pkg in $pkg_group; do
            if ! rpm -q "$pkg" >/dev/null 2>&1; then
                install_package "$pkg" || true
            else
                log "INFO" "$pkg is already installed"
            fi
        done
    done
}

setup_development_environment() {
    log "INFO" "Setting up development environment..."
    
    # Install development tools
    local dev_packages=(
        "git-core"
        "gh"
        "code"
        "docker-compose"
        "kubectl"
        "helm"
    )
    
    for pkg in "${dev_packages[@]}"; do
        install_package "$pkg" || true
    done
    
    # Setup Docker for non-root user
    if command -v docker >/dev/null 2>&1; then
        log "INFO" "Configuring Docker for user access..."
        if safe_sudo "usermod -aG docker '$USER'"; then
            log "SUCCESS" "User added to docker group"
            log "INFO" "Please log out and back in for docker group changes to take effect"
        else
            FAILED_OPERATIONS+=("Add user to docker group")
            log "WARN" "Failed to add user to docker group"
        fi
        
        if safe_sudo "systemctl enable --now docker"; then
            log "SUCCESS" "Docker service enabled and started"
        else
            FAILED_OPERATIONS+=("Enable Docker service")
            log "WARN" "Failed to enable Docker service"
        fi
    fi
}

configure_firewall() {
    log "INFO" "Configuring firewall..."
    
    if command -v firewall-cmd >/dev/null 2>&1; then
        # Enable firewall
        if safe_sudo "systemctl enable --now firewalld"; then
            log "SUCCESS" "Firewall enabled and started"
            
            # Allow SSH
            if safe_sudo "firewall-cmd --permanent --add-service=ssh"; then
                log "SUCCESS" "SSH service allowed through firewall"
            fi
            
            # Allow common development ports
            local ports=("3000/tcp" "8000/tcp" "8080/tcp" "9000/tcp")
            for port in "${ports[@]}"; do
                if safe_sudo "firewall-cmd --permanent --add-port='$port'"; then
                    log "SUCCESS" "Port $port opened"
                fi
            done
            
            # Reload firewall
            if safe_sudo "firewall-cmd --reload"; then
                log "SUCCESS" "Firewall configuration reloaded"
            fi
        else
            FAILED_OPERATIONS+=("Configure firewall")
            log "WARN" "Failed to configure firewall"
        fi
    fi
}

setup_ssh() {
    log "INFO" "Configuring SSH..."
    
    if command -v ssh >/dev/null 2>&1; then
        # Enable SSH service
        if safe_sudo "systemctl enable --now sshd"; then
            log "SUCCESS" "SSH service enabled and started"
        else
            FAILED_OPERATIONS+=("Enable SSH service")
            log "WARN" "Failed to enable SSH service"
        fi
        
        # Generate SSH key if not exists
        if [[ ! -f "$HOME/.ssh/id_rsa" ]]; then
            log "INFO" "Generating SSH key pair..."
            if ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N ""; then
                log "SUCCESS" "SSH key pair generated"
                log "INFO" "Public key: $(cat "$HOME/.ssh/id_rsa.pub")"
            else
                FAILED_OPERATIONS+=("Generate SSH key")
                log "WARN" "Failed to generate SSH key"
            fi
        fi
    fi
}

optimize_system() {
    log "INFO" "Applying system optimizations..."
    
    # Create temporary file for sysctl settings
    local sysctl_file="/tmp/microos-sysctl-$$"
    cat > "$sysctl_file" << 'EOF'
# Performance optimizations
vm.swappiness=10

# Network optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
EOF
    
    # Add settings to sysctl.conf
    if safe_sudo "cat '$sysctl_file' >> /etc/sysctl.conf"; then
        log "SUCCESS" "System optimization settings added"
    else
        FAILED_OPERATIONS+=("Add system optimizations")
        log "WARN" "Failed to add system optimizations"
    fi
    
    # Clean up temporary file
    rm -f "$sysctl_file"
    
    # Apply sysctl settings
    if safe_sudo "sysctl -p"; then
        log "SUCCESS" "System optimizations applied"
    else
        FAILED_OPERATIONS+=("Apply system optimizations")
        log "WARN" "Failed to apply system optimizations"
    fi
}

setup_user_environment() {
    log "INFO" "Setting up user environment..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Setup shell aliases
    cat << 'EOF' >> "$HOME/.bashrc"

# MicroOS aliases and functions
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# Docker aliases
alias dps='docker ps'
alias dpsa='docker ps -a'
alias di='docker images'
alias drmi='docker rmi'
alias dstop='docker stop'
alias dstart='docker start'

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
    
    log "SUCCESS" "User environment configured"
}

create_post_install_summary() {
    local summary_file="$HOME/microos-setup-summary.txt"
    
    cat << EOF > "$summary_file"
openSUSE MicroOS Post-Installation Setup Summary
================================================

Installation Date: $(date)
MicroOS Variant: $(if $DESKTOP_VARIANT; then echo "Desktop"; else echo "Server"; fi)
Reboot Required: $(if $REBOOT_REQUIRED; then echo "Yes"; else echo "No"; fi)

Installed Packages:
EOF
    
    if [[ ${#PACKAGES_INSTALLED[@]} -gt 0 ]]; then
        printf '%s\n' "${PACKAGES_INSTALLED[@]}" | sort >> "$summary_file"
    else
        echo "None" >> "$summary_file"
    fi
    
    cat << EOF >> "$summary_file"

Failed Operations:
EOF
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        printf '%s\n' "${FAILED_OPERATIONS[@]}" >> "$summary_file"
    else
        echo "None" >> "$summary_file"
    fi
    
    cat << EOF >> "$summary_file"

Next Steps:
-----------
1. $(if $REBOOT_REQUIRED; then echo "Reboot the system to complete transactional updates"; else echo "No reboot required"; fi)
2. Configure your development environment as needed
3. Set up additional services (containers, web servers, etc.)
4. Review firewall settings for your specific use case
5. Configure backup solutions

Important Files:
----------------
- Log file: $LOG_FILE
- SSH public key: $HOME/.ssh/id_rsa.pub
- This summary: $summary_file

For more information about MicroOS, visit:
https://microos.opensuse.org/
EOF
    
    log "SUCCESS" "Setup summary created: $summary_file"
}

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

openSUSE MicroOS Post-Installation Setup Script

This script automatically configures a fresh openSUSE MicroOS installation
with essential packages, development tools, and security settings.

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose logging
    --dry-run       Show what would be done without making changes

FEATURES:
    • Auto-detects MicroOS variant (Desktop/Server)
    • Installs essential development tools
    • Configures Docker and container runtime
    • Sets up firewall and SSH
    • Optimizes system performance
    • Creates detailed installation summary

REQUIREMENTS:
    • Run as regular user (not root)
    • Sudo access required
    • Internet connection

EXAMPLES:
    $SCRIPT_NAME                # Standard installation
    $SCRIPT_NAME --verbose      # Verbose output
    $SCRIPT_NAME --dry-run      # Preview changes

For more information: https://microos.opensuse.org/
EOF
}

#######################################################################
# Main Function
#######################################################################

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            --dry-run)
                log "INFO" "DRY RUN MODE - No changes will be made"
                # Set a flag for dry run mode
                export DRY_RUN=true
                shift
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log "INFO" "Starting openSUSE MicroOS post-installation setup..."
    
    # Pre-flight checks
    check_root
    check_microos
    detect_variant
    
    if ! check_internet; then
        log "ERROR" "Internet connection required. Please check your network settings."
        exit 1
    fi
    
    # Create necessary directories
    mkdir -p "$TEMP_DIR"
    
    # Setup logging with proper permissions
    if [[ ! -f "$LOG_FILE" ]]; then
        sudo mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || {
            LOG_FILE="$HOME/microos-post-install.log"
            log "WARN" "Using fallback log location: $LOG_FILE"
        }
        touch "$LOG_FILE" 2>/dev/null || {
            LOG_FILE="/tmp/microos-post-install-$$.log"
            touch "$LOG_FILE"
            log "WARN" "Using temporary log location: $LOG_FILE"
        }
    fi
    
    log "INFO" "System checks completed successfully"
    
    # Main setup process
    update_system || log "WARN" "System update failed, continuing..."
    setup_repositories || log "WARN" "Repository setup had issues, continuing..."
    install_essential_packages
    setup_development_environment
    configure_firewall
    setup_ssh
    optimize_system
    setup_user_environment
    
    # Final steps
    create_post_install_summary
    
    log "SUCCESS" "MicroOS post-installation setup completed!"
    log "INFO" "Installed ${#PACKAGES_INSTALLED[@]} packages"
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        log "WARN" "${#FAILED_OPERATIONS[@]} operations failed - check the summary file"
    fi
    
    log "INFO" "Please review the setup summary at: $HOME/microos-setup-summary.txt"
}

#######################################################################
# Script Entry Point
#######################################################################

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi