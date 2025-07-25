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

check_user_privileges() {
    local current_user=$(whoami)
    local user_id=$(id -u)
    
    log "INFO" "Current user: $current_user (UID: $user_id)"
    
    # Check if running as root
    if [[ $user_id -eq 0 ]]; then
        log "ERROR" "This script should not be run as root"
        log "INFO" "Please run as a regular user - sudo will be used when needed"
        log "INFO" "Example: su - username -c './microos-post-install.sh'"
        return 1
    fi
    
    # Check if user exists in /etc/passwd (not just a process user)
    if ! getent passwd "$current_user" >/dev/null 2>&1; then
        log "ERROR" "User $current_user not found in system database"
        return 1
    fi
    
    # Check sudo access
    log "INFO" "Checking sudo access for user $current_user..."
    if ! sudo -n true 2>/dev/null; then
        log "INFO" "This script requires sudo access for system operations"
        log "INFO" "You may be prompted for your password"
        if ! sudo -v; then
            log "ERROR" "Sudo access required but not available"
            log "INFO" "Please ensure user $current_user has sudo privileges"
            return 1
        fi
    fi
    
    log "SUCCESS" "User privileges verified - proceeding as $current_user"
    return 0
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

run_pre_checks() {
    log "INFO" "Running comprehensive pre-installation checks..."
    local check_failed=false
    
    # Check 1: User privileges
    if ! check_user_privileges; then
        check_failed=true
    fi
    
    # Check 2: Operating system
    if ! check_microos; then
        check_failed=true
    fi
    
    # Check 3: MicroOS variant detection
    detect_variant
    
    # Check 4: Internet connectivity
    if ! check_internet; then
        log "WARN" "Internet connectivity issues detected"
        read -p "Continue anyway? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            check_failed=true
        fi
    fi
    
    # Check 5: Disk space
    log "INFO" "Checking available disk space..."
    local available_space=$(df / | awk 'NR==2 {print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    
    if [[ $available_gb -lt 2 ]]; then
        log "ERROR" "Insufficient disk space. At least 2GB required, found ${available_gb}GB"
        check_failed=true
    else
        log "SUCCESS" "Disk space check passed: ${available_gb}GB available"
    fi
    
    # Check 6: System load
    log "INFO" "Checking system load..."
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    log "INFO" "Current system load: $load_avg"
    
    # Check 7: Memory availability
    log "INFO" "Checking memory availability..."
    local mem_available=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [[ $mem_available -lt 500 ]]; then
        log "WARN" "Low memory available: ${mem_available}MB"
    else
        log "SUCCESS" "Memory check passed: ${mem_available}MB available"
    fi
    
    # Check 8: Package manager functionality
    log "INFO" "Testing package manager..."
    if $DESKTOP_VARIANT; then
        if ! pkcon --version >/dev/null 2>&1; then
            log "ERROR" "PackageKit (pkcon) not working properly"
            check_failed=true
        else
            log "SUCCESS" "PackageKit is functional"
        fi
    else
        if ! command -v transactional-update >/dev/null 2>&1; then
            log "ERROR" "transactional-update not found"
            check_failed=true
        else
            log "SUCCESS" "transactional-update is available"
        fi
    fi
    
    if [[ $check_failed == true ]]; then
        log "ERROR" "Pre-checks failed. Please resolve the issues above before continuing."
        return 1
    fi
    
    log "SUCCESS" "All pre-checks passed successfully!"
    return 0
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

show_banner() {
    clear
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║           openSUSE MicroOS Post-Installation Setup           ║
║                                                               ║
║    Intelligent configuration script for fresh MicroOS        ║
║                         installations                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo
}

show_system_info() {
    local current_user=$(whoami)
    local microos_version=$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "Unknown")
    local variant=$(if $DESKTOP_VARIANT; then echo "Desktop"; else echo "Server"; fi)
    local uptime_info=$(uptime -p 2>/dev/null || uptime)
    
    echo -e "${BLUE}System Information:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "User: $current_user"
    echo "MicroOS Version: $microos_version"
    echo "Variant: $variant"
    echo "Uptime: $uptime_info"
    echo "Log File: $LOG_FILE"
    echo
}

show_main_menu() {
    show_banner
    show_system_info
    
    echo -e "${GREEN}Main Menu:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1) Run Pre-Installation Checks"
    echo "2) Quick Setup (All Components)"
    echo "3) Custom Installation Menu"
    echo "4) System Information & Status"
    echo "5) View Installation Log"
    echo "6) Help & Documentation"
    echo "7) Exit"
    echo
}

show_custom_menu() {
    show_banner
    
    echo -e "${GREEN}Custom Installation Menu:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "1) Update System Packages"
    echo "2) Setup Additional Repositories"
    echo "3) Install Essential Packages"
    echo "4) Setup Development Environment"
    echo "5) Configure Firewall & Security"
    echo "6) Setup SSH Access"
    echo "7) Apply System Optimizations"
    echo "8) Configure User Environment"
    echo "9) Generate Setup Summary"
    echo "0) Return to Main Menu"
    echo
}

show_help() {
    clear
    cat << EOF
${BLUE}openSUSE MicroOS Post-Installation Setup - Help${NC}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${GREEN}OVERVIEW:${NC}
This script provides an intelligent, menu-driven setup process for 
openSUSE MicroOS installations. It automatically detects your system 
variant and provides appropriate configuration options.

${GREEN}KEY FEATURES:${NC}
• Comprehensive pre-installation checks
• Auto-detection of MicroOS variant (Desktop/Server)
• Smart package management (pkcon vs transactional-update)
• Development environment setup
• Security configuration (firewall, SSH)
• System optimization
• Detailed logging and error handling

${GREEN}REQUIREMENTS:${NC}
• openSUSE MicroOS (Desktop or Server variant)
• Regular user account (not root)
• Sudo privileges
• Internet connection (recommended)
• At least 2GB free disk space

${GREEN}USAGE TIPS:${NC}
1. Always run pre-checks first (Option 1)
2. Use Quick Setup for standard installations
3. Use Custom Menu for selective installation
4. Check logs if issues occur (Option 5)
5. Reboot after transactional updates when prompted

${GREEN}COMPONENTS INSTALLED:${NC}
• Essential tools: git, curl, wget, vim, htop
• Development: Docker, Node.js, Python, build tools
• Security: firewall configuration, SSH setup
• System: performance optimizations, user environment

${GREEN}SUPPORT:${NC}
• MicroOS Documentation: https://microos.opensuse.org/
• Log file location: $LOG_FILE
• Report issues to system administrator

Press any key to return to main menu...
EOF
    read -n 1 -s
}

pause_for_user() {
    echo
    echo -e "${YELLOW}Press any key to continue...${NC}"
    read -n 1 -s
    echo
}

#######################################################################
# Main Function
#######################################################################

quick_setup() {
    log "INFO" "Starting Quick Setup - All Components"
    echo
    
    # Setup logging
    setup_logging
    
    # Main setup process with progress indication
    local total_steps=8
    local current_step=0
    
    echo -e "${BLUE}Progress: Installing all components...${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    ((current_step++))
    echo "[$current_step/$total_steps] Updating system packages..."
    update_system || log "WARN" "System update failed, continuing..."
    
    ((current_step++))
    echo "[$current_step/$total_steps] Setting up repositories..."
    setup_repositories || log "WARN" "Repository setup had issues, continuing..."
    
    ((current_step++))
    echo "[$current_step/$total_steps] Installing essential packages..."
    install_essential_packages
    
    ((current_step++))
    echo "[$current_step/$total_steps] Setting up development environment..."
    setup_development_environment
    
    ((current_step++))
    echo "[$current_step/$total_steps] Configuring firewall..."
    configure_firewall
    
    ((current_step++))
    echo "[$current_step/$total_steps] Setting up SSH..."
    setup_ssh
    
    ((current_step++))
    echo "[$current_step/$total_steps] Applying system optimizations..."
    optimize_system
    
    ((current_step++))
    echo "[$current_step/$total_steps] Configuring user environment..."
    setup_user_environment
    
    # Final steps
    create_post_install_summary
    
    echo
    log "SUCCESS" "Quick Setup completed!"
    log "INFO" "Installed ${#PACKAGES_INSTALLED[@]} packages"
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        log "WARN" "${#FAILED_OPERATIONS[@]} operations failed - check the summary file"
    fi
    
    log "INFO" "Setup summary available at: $HOME/microos-setup-summary.txt"
    pause_for_user
}

setup_logging() {
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
}

show_system_status() {
    clear
    show_banner
    
    echo -e "${GREEN}Detailed System Status:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Basic system info
    echo -e "${BLUE}System Information:${NC}"
    echo "Hostname: $(hostname)"
    echo "User: $(whoami) (UID: $(id -u))"
    echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo
    
    # Resource usage
    echo -e "${BLUE}Resource Usage:${NC}"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    
    # Memory info
    local mem_info=$(free -h | awk 'NR==2{printf "Used: %s/%s (%.0f%%)", $3,$2,$3*100/$2}')
    echo "Memory: $mem_info"
    
    # Disk space
    echo "Disk Usage (/):"
    df -h / | tail -1 | awk '{printf "  Used: %s/%s (%s)\n", $3, $2, $5}'
    echo
    
    # Package manager status
    echo -e "${BLUE}Package Manager:${NC}"
    if $DESKTOP_VARIANT; then
        echo "Type: PackageKit (Desktop variant)"
        if command -v pkcon >/dev/null 2>&1; then
            echo "Status: Available"
        else
            echo "Status: Not available"
        fi
    else
        echo "Type: Transactional Update (Server variant)"
        if command -v transactional-update >/dev/null 2>&1; then
            echo "Status: Available"
        else
            echo "Status: Not available"
        fi
    fi
    echo
    
    # Network status
    echo -e "${BLUE}Network Status:${NC}"
    if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
        echo "Internet: Connected"
    else
        echo "Internet: Disconnected"
    fi
    
    # Active services
    echo
    echo -e "${BLUE}Key Services:${NC}"
    for service in sshd docker firewalld; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "$service: Active"
        else
            echo "$service: Inactive"
        fi
    done
    
    echo
    pause_for_user
}

view_log() {
    clear
    echo -e "${BLUE}Installation Log: $LOG_FILE${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    
    if [[ -f "$LOG_FILE" ]]; then
        echo "Last 50 lines of the log file:"
        echo
        tail -50 "$LOG_FILE" | while IFS= read -r line; do
            if [[ $line == *"[ERROR]"* ]]; then
                echo -e "${RED}$line${NC}"
            elif [[ $line == *"[WARN]"* ]]; then
                echo -e "${YELLOW}$line${NC}"
            elif [[ $line == *"[SUCCESS]"* ]]; then
                echo -e "${GREEN}$line${NC}"
            else
                echo "$line"
            fi
        done
    else
        echo "Log file not found at: $LOG_FILE"
    fi
    
    echo
    pause_for_user
}

handle_custom_menu() {
    while true; do
        show_custom_menu
        read -p "Select option [0-9]: " choice
        echo
        
        case $choice in
            1) update_system; pause_for_user ;;
            2) setup_repositories; pause_for_user ;;
            3) install_essential_packages; pause_for_user ;;
            4) setup_development_environment; pause_for_user ;;
            5) configure_firewall; pause_for_user ;;
            6) setup_ssh; pause_for_user ;;
            7) optimize_system; pause_for_user ;;
            8) setup_user_environment; pause_for_user ;;
            9) create_post_install_summary; pause_for_user ;;
            0) break ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}"; sleep 2 ;;
        esac
    done
}

main() {
    # Initialize logging first
    setup_logging
    
    # Parse command line arguments for backward compatibility
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            --auto)
                # Auto mode for non-interactive use
                log "INFO" "Running in automatic mode"
                if run_pre_checks; then
                    quick_setup
                    exit 0
                else
                    exit 1
                fi
                ;;
            *)
                log "ERROR" "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Main menu loop
    while true; do
        show_main_menu
        read -p "Select option [1-7]: " choice
        echo
        
        case $choice in
            1)
                if run_pre_checks; then
                    log "SUCCESS" "All pre-checks passed! You can now proceed with installation."
                else
                    log "ERROR" "Pre-checks failed. Please resolve issues before continuing."
                fi
                pause_for_user
                ;;
            2)
                if run_pre_checks; then
                    quick_setup
                else
                    log "ERROR" "Pre-checks failed. Cannot proceed with installation."
                    pause_for_user
                fi
                ;;
            3)
                if run_pre_checks; then
                    handle_custom_menu
                else
                    log "ERROR" "Pre-checks failed. Cannot proceed with installation."
                    pause_for_user
                fi
                ;;
            4)
                detect_variant
                show_system_status
                ;;
            5)
                view_log
                ;;
            6)
                show_help
                ;;
            7)
                echo -e "${GREEN}Thank you for using openSUSE MicroOS Post-Installation Setup!${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                sleep 2
                ;;
        esac
    done
}

#######################################################################
# Script Entry Point
#######################################################################

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi