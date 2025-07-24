#!/bin/bash

# configure-vlans.sh
# Advanced VLAN configuration and management script
# Provides VLAN configuration, testing, and troubleshooting utilities

set -euo pipefail

# Configuration
BRIDGE_NAME="br0"
SYSTEMD_NETWORK_DIR="/etc/systemd/network"

# VLAN definitions
declare -A VLAN_CONFIG=(
    # Format: [ID]="network/cidr:description:gateway:dhcp_start:dhcp_end"
    [10]="192.168.10.0/28:Management:192.168.10.1:192.168.10.5:192.168.10.14"
    [20]="192.168.20.0/24:LAN:192.168.20.1:192.168.20.100:192.168.20.199"
    [30]="192.168.30.0/28:DMZ:192.168.30.1:192.168.30.10:192.168.30.14"
    [40]="192.168.40.0/26:Guest:192.168.40.1:192.168.40.10:192.168.40.60"
)

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }

# Display usage
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
    configure       Configure VLAN interfaces and bridge
    status          Show VLAN and bridge status
    test            Test VLAN connectivity
    add-vlan        Add a new VLAN
    remove-vlan     Remove a VLAN
    restart         Restart networking services
    troubleshoot    Run network troubleshooting
    backup          Backup network configuration
    restore         Restore network configuration

Options:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    -y, --yes       Auto-confirm actions

Examples:
    $0 configure
    $0 status
    $0 test --vlan 10
    $0 add-vlan --id 50 --network "192.168.50.0/24" --desc "New VLAN"
EOF
}

# Parse command line arguments
parse_args() {
    COMMAND=""
    VERBOSE=false
    AUTO_CONFIRM=false
    VLAN_ID=""
    NETWORK=""
    DESCRIPTION=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            configure|status|test|add-vlan|remove-vlan|restart|troubleshoot|backup|restore)
                COMMAND="$1"
                shift
                ;;
            --vlan)
                VLAN_ID="$2"
                shift 2
                ;;
            --network)
                NETWORK="$2" 
                shift 2
                ;;
            --desc)
                DESCRIPTION="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -y|--yes)
                AUTO_CONFIRM=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    if [[ -z "$COMMAND" ]]; then
        usage
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Get VLAN configuration details
get_vlan_info() {
    local vlan_id="$1"
    local config="${VLAN_CONFIG[$vlan_id]}"
    
    IFS=':' read -r network description gateway dhcp_start dhcp_end <<< "$config"
    
    echo "network=$network"
    echo "description=$description" 
    echo "gateway=$gateway"
    echo "dhcp_start=$dhcp_start"
    echo "dhcp_end=$dhcp_end"
}

# Configure VLAN interfaces
configure_vlans() {
    log "Configuring VLAN interfaces..."
    
    if [[ "$AUTO_CONFIRM" == false ]]; then
        warn "This will reconfigure VLAN interfaces"
        read -p "Continue? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
    
    # Ensure bridge exists
    if ! ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        error "Bridge $BRIDGE_NAME does not exist. Run setup-host-networking.sh first."
    fi
    
    # Configure each VLAN
    for vlan_id in "${!VLAN_CONFIG[@]}"; do
        configure_single_vlan "$vlan_id"
    done
    
    # Apply configuration
    systemctl restart systemd-networkd
    sleep 3
    
    log "VLAN configuration completed"
}

# Configure a single VLAN
configure_single_vlan() {
    local vlan_id="$1"
    local vlan_name="${BRIDGE_NAME}.${vlan_id}"
    
    eval "$(get_vlan_info "$vlan_id")"
    
    log "Configuring VLAN $vlan_id ($description)..."
    
    # Create VLAN netdev if it doesn't exist
    if [[ ! -f "$SYSTEMD_NETWORK_DIR/25-${vlan_name}.netdev" ]]; then
        cat > "$SYSTEMD_NETWORK_DIR/25-${vlan_name}.netdev" << EOF
# $description VLAN interface
[NetDev]
Name=${vlan_name}
Kind=vlan

[VLAN]
Id=${vlan_id}
EOF
    fi
    
    # Update VLAN network configuration
    cat > "$SYSTEMD_NETWORK_DIR/30-${vlan_name}.network" << EOF
# $description VLAN network configuration  
[Match]
Name=${vlan_name}

[Network]
DHCP=no
IPv6AcceptRA=false

# Bridge VLAN configuration
[Bridge]
PVID=${vlan_id}
VLAN=${vlan_id}
EOF

    if [[ "$VERBOSE" == true ]]; then
        info "Created configuration for VLAN $vlan_id: $network ($description)"
    fi
}

# Show VLAN status
show_status() {
    echo -e "${BLUE}=== Home Lab VLAN Status ===${NC}"
    echo
    
    # Bridge information
    echo -e "${CYAN}Bridge Information:${NC}"
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
        ip addr show "$BRIDGE_NAME" | grep -E "$BRIDGE_NAME:|inet "
        echo
        
        # Bridge VLAN table
        echo -e "${CYAN}Bridge VLAN Table:${NC}"
        if bridge vlan show >/dev/null 2>&1; then
            bridge vlan show | grep -E "^$BRIDGE_NAME|^[[:space:]]"
        else
            warn "Bridge VLAN filtering not available"
        fi
        echo
    else
        error "Bridge $BRIDGE_NAME not found"
    fi
    
    # VLAN interfaces
    echo -e "${CYAN}VLAN Interfaces:${NC}"
    for vlan_id in "${!VLAN_CONFIG[@]}"; do
        local vlan_name="${BRIDGE_NAME}.${vlan_id}"
        eval "$(get_vlan_info "$vlan_id")"
        
        if ip link show "$vlan_name" >/dev/null 2>&1; then
            local status=$(ip link show "$vlan_name" | grep -o "state [A-Z]*" | awk '{print $2}')
            printf "  %-10s %-12s %-20s %s\n" "VLAN $vlan_id" "($status)" "$network" "$description"
        else
            printf "  %-10s %-12s %-20s %s\n" "VLAN $vlan_id" "(MISSING)" "$network" "$description"
        fi
    done
    echo
    
    # Routing information
    echo -e "${CYAN}Routing Table:${NC}"
    ip route show | head -10
    echo
    
    # Network services
    echo -e "${CYAN}Network Services:${NC}"
    printf "  %-20s %s\n" "systemd-networkd:" "$(systemctl is-active systemd-networkd)"
    printf "  %-20s %s\n" "systemd-resolved:" "$(systemctl is-active systemd-resolved)"
    printf "  %-20s %s\n" "firewalld:" "$(systemctl is-active firewalld 2>/dev/null || echo 'inactive')"
}

# Test VLAN connectivity
test_connectivity() {
    local test_vlan="$VLAN_ID"
    
    echo -e "${BLUE}=== VLAN Connectivity Test ===${NC}"
    echo
    
    if [[ -n "$test_vlan" ]]; then
        test_single_vlan "$test_vlan"
    else
        # Test all VLANs
        for vlan_id in "${!VLAN_CONFIG[@]}"; do
            test_single_vlan "$vlan_id"
        done
    fi
}

# Test single VLAN connectivity
test_single_vlan() {
    local vlan_id="$1"
    local vlan_name="${BRIDGE_NAME}.${vlan_id}"
    
    eval "$(get_vlan_info "$vlan_id")"
    
    echo -e "${CYAN}Testing VLAN $vlan_id ($description):${NC}"
    
    # Check interface exists
    if ! ip link show "$vlan_name" >/dev/null 2>&1; then
        echo "  ❌ Interface $vlan_name does not exist"
        return 1
    fi
    
    # Check interface is up
    local state=$(ip link show "$vlan_name" | grep -o "state [A-Z]*" | awk '{print $2}')
    if [[ "$state" == "UP" ]]; then
        echo "  ✅ Interface is UP"
    else
        echo "  ❌ Interface is $state"
    fi
    
    # Test gateway connectivity (if this is not the gateway)
    if [[ "$gateway" != "192.168.${vlan_id}.2" ]]; then
        if ping -c 1 -W 2 -I "$vlan_name" "$gateway" >/dev/null 2>&1; then
            echo "  ✅ Gateway $gateway reachable"
        else
            echo "  ❌ Gateway $gateway unreachable"
        fi
    fi
    
    # Test DNS resolution
    if nslookup google.com "$gateway" >/dev/null 2>&1; then
        echo "  ✅ DNS resolution working"
    else
        echo "  ❌ DNS resolution failed"
    fi
    
    echo
}

# Add new VLAN
add_vlan() {
    if [[ -z "$VLAN_ID" ]] || [[ -z "$NETWORK" ]] || [[ -z "$DESCRIPTION" ]]; then
        error "Missing required parameters. Use: --vlan ID --network CIDR --desc DESCRIPTION"
    fi
    
    log "Adding VLAN $VLAN_ID ($DESCRIPTION) with network $NETWORK"
    
    # Validate VLAN ID
    if [[ ! "$VLAN_ID" =~ ^[0-9]+$ ]] || [[ "$VLAN_ID" -lt 1 ]] || [[ "$VLAN_ID" -gt 4094 ]]; then
        error "Invalid VLAN ID. Must be 1-4094"
    fi
    
    # Check if VLAN already exists
    if [[ -n "${VLAN_CONFIG[$VLAN_ID]:-}" ]]; then
        error "VLAN $VLAN_ID already exists"
    fi
    
    # Parse network to get gateway
    local network_base=$(echo "$NETWORK" | cut -d'/' -f1)
    local gateway="${network_base%.*}.1"
    
    # Add to configuration
    VLAN_CONFIG[$VLAN_ID]="$NETWORK:$DESCRIPTION:$gateway:${network_base%.*}.10:${network_base%.*}.50"
    
    # Configure the new VLAN
    configure_single_vlan "$VLAN_ID"
    systemctl restart systemd-networkd
    
    log "VLAN $VLAN_ID added successfully"
}

# Remove VLAN
remove_vlan() {
    if [[ -z "$VLAN_ID" ]]; then
        error "Missing VLAN ID. Use: --vlan ID"
    fi
    
    if [[ -z "${VLAN_CONFIG[$VLAN_ID]:-}" ]]; then
        error "VLAN $VLAN_ID does not exist"
    fi
    
    warn "Removing VLAN $VLAN_ID"
    if [[ "$AUTO_CONFIRM" == false ]]; then
        read -p "Continue? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
    
    local vlan_name="${BRIDGE_NAME}.${VLAN_ID}"
    
    # Remove configuration files
    rm -f "$SYSTEMD_NETWORK_DIR/25-${vlan_name}.netdev"
    rm -f "$SYSTEMD_NETWORK_DIR/30-${vlan_name}.network"
    
    # Remove from runtime configuration
    unset VLAN_CONFIG[$VLAN_ID]
    
    systemctl restart systemd-networkd
    
    log "VLAN $VLAN_ID removed successfully"
}

# Restart networking
restart_networking() {
    log "Restarting network services..."
    
    systemctl restart systemd-networkd
    systemctl restart systemd-resolved
    
    # Wait for network to stabilize
    sleep 5
    
    log "Network services restarted"
    show_status
}

# Network troubleshooting
troubleshoot() {
    echo -e "${BLUE}=== Network Troubleshooting ===${NC}"
    echo
    
    # Basic connectivity
    echo -e "${CYAN}Basic Connectivity:${NC}"
    if ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo "  ✅ Internet connectivity working"
    else
        echo "  ❌ Internet connectivity failed"
    fi
    
    if ping -c 1 192.168.10.1 >/dev/null 2>&1; then
        echo "  ✅ Management gateway reachable"
    else
        echo "  ❌ Management gateway unreachable"
    fi
    echo
    
    # Service status
    echo -e "${CYAN}Service Status:${NC}"
    for service in systemd-networkd systemd-resolved firewalld; do
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
        if [[ "$status" == "active" ]]; then
            echo "  ✅ $service: $status"
        else
            echo "  ❌ $service: $status"
        fi
    done
    echo
    
    # Configuration validation
    echo -e "${CYAN}Configuration Validation:${NC}"
    if systemd-analyze verify "$SYSTEMD_NETWORK_DIR"/*.network "$SYSTEMD_NETWORK_DIR"/*.netdev >/dev/null 2>&1; then
        echo "  ✅ systemd-networkd configuration valid"
    else
        echo "  ❌ systemd-networkd configuration issues detected"
        echo "Run: systemd-analyze verify $SYSTEMD_NETWORK_DIR/*.network $SYSTEMD_NETWORK_DIR/*.netdev"
    fi
    echo
    
    # Recent logs
    echo -e "${CYAN}Recent Network Logs:${NC}"
    journalctl -u systemd-networkd --since "5 minutes ago" --no-pager -q | tail -5
    echo
    
    # Suggestions
    echo -e "${CYAN}Troubleshooting Suggestions:${NC}"
    echo "  1. Check physical network connection"
    echo "  2. Verify upstream router VLAN configuration"
    echo "  3. Restart networking: $0 restart"
    echo "  4. Check firewall rules: firewall-cmd --list-all"
    echo "  5. Monitor logs: journalctl -u systemd-networkd -f"
}

# Backup configuration
backup_config() {
    local backup_dir="/root/network-backups"
    local backup_file="network-config-$(date +%Y%m%d_%H%M%S).tar.gz"
    
    log "Creating network configuration backup..."
    
    mkdir -p "$backup_dir"
    
    tar -czf "$backup_dir/$backup_file" -C / \
        etc/systemd/network \
        etc/firewalld 2>/dev/null || true
    
    log "Backup created: $backup_dir/$backup_file"
}

# Restore configuration
restore_config() {
    local backup_dir="/root/network-backups"
    
    echo -e "${CYAN}Available backups:${NC}"
    ls -la "$backup_dir"/*.tar.gz 2>/dev/null || {
        warn "No backups found in $backup_dir"
        exit 1
    }
    
    echo
    read -p "Enter backup filename to restore: " backup_file
    
    if [[ ! -f "$backup_dir/$backup_file" ]]; then
        error "Backup file not found: $backup_dir/$backup_file"
    fi
    
    warn "This will overwrite current network configuration"
    if [[ "$AUTO_CONFIRM" == false ]]; then
        read -p "Continue? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 0
    fi
    
    tar -xzf "$backup_dir/$backup_file" -C /
    systemctl restart systemd-networkd
    
    log "Configuration restored from $backup_file"
}

# Main execution
main() {
    parse_args "$@"
    
    case "$COMMAND" in
        configure)
            check_root
            configure_vlans
            ;;
        status)
            show_status
            ;;
        test)
            test_connectivity
            ;;
        add-vlan)
            check_root
            add_vlan
            ;;
        remove-vlan)
            check_root
            remove_vlan
            ;;
        restart)
            check_root
            restart_networking
            ;;
        troubleshoot)
            troubleshoot
            ;;
        backup)
            check_root
            backup_config
            ;;
        restore)
            check_root
            restore_config
            ;;
        *)
            error "Unknown command: $COMMAND"
            ;;
    esac
}

# Execute main function
main "$@"