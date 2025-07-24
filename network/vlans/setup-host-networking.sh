#!/bin/bash

# setup-host-networking.sh
# Configure VLAN-aware bridge networking on openSUSE MicroOS host
# This script sets up the bridge interface and VLAN configuration

set -euo pipefail

# Configuration variables
BRIDGE_NAME="br0"
PHYSICAL_INTERFACE="eth0"
SYSTEMD_NETWORK_DIR="/etc/systemd/network"

# VLAN configuration
declare -A VLANS=(
    [10]="192.168.10.0/28"  # Management
    [20]="192.168.20.0/24"  # LAN
    [30]="192.168.30.0/28"  # DMZ
    [40]="192.168.40.0/26"  # Guest
)

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

# Backup existing network configuration
backup_config() {
    log "Backing up existing network configuration..."
    
    if [[ -d "$SYSTEMD_NETWORK_DIR" ]]; then
        cp -r "$SYSTEMD_NETWORK_DIR" "${SYSTEMD_NETWORK_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
        log "Backup created: ${SYSTEMD_NETWORK_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
    fi
}

# Detect physical network interface
detect_interface() {
    log "Detecting physical network interface..."
    
    # Try to detect the primary network interface
    DETECTED_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    
    if [[ -n "$DETECTED_INTERFACE" ]]; then
        log "Detected interface: $DETECTED_INTERFACE"
        read -p "Use detected interface $DETECTED_INTERFACE? [Y/n]: " -r
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            read -p "Enter physical interface name: " PHYSICAL_INTERFACE
        else
            PHYSICAL_INTERFACE="$DETECTED_INTERFACE"
        fi
    else
        read -p "Enter physical interface name (e.g., eth0, enp0s3): " PHYSICAL_INTERFACE
    fi
    
    # Verify interface exists
    if ! ip link show "$PHYSICAL_INTERFACE" >/dev/null 2>&1; then
        error "Interface $PHYSICAL_INTERFACE does not exist"
    fi
    
    log "Using physical interface: $PHYSICAL_INTERFACE"
}

# Create bridge netdev configuration
create_bridge_netdev() {
    log "Creating bridge netdev configuration..."
    
    cat > "$SYSTEMD_NETWORK_DIR/10-${BRIDGE_NAME}.netdev" << EOF
# Bridge netdev configuration for VLAN-aware bridge
[NetDev]
Name=${BRIDGE_NAME}
Kind=bridge

[Bridge]
# Enable Spanning Tree Protocol
STP=true
# Set default PVID to management VLAN
DefaultPVID=10
# Enable VLAN filtering on bridge
VLANFiltering=true
# Forward delay (seconds)
ForwardDelaySec=4
# Hello time (seconds)
HelloTimeSec=2
# Max age (seconds)
MaxAgeSec=12
EOF

    log "Created bridge netdev: $SYSTEMD_NETWORK_DIR/10-${BRIDGE_NAME}.netdev"
}

# Bind physical interface to bridge
bind_physical_interface() {
    log "Binding physical interface to bridge..."
    
    cat > "$SYSTEMD_NETWORK_DIR/15-${PHYSICAL_INTERFACE}.network" << EOF
# Bind physical interface to bridge
[Match]
Name=${PHYSICAL_INTERFACE}

[Network]
# Bind to bridge
Bridge=${BRIDGE_NAME}
# Enable IPv6
IPv6AcceptRA=false
DHCP=no

# Optional: Configure physical interface settings
[Link]
# Set MTU if needed
#MTUBytes=1500
EOF

    log "Created physical interface config: $SYSTEMD_NETWORK_DIR/15-${PHYSICAL_INTERFACE}.network"
}

# Create bridge network configuration
create_bridge_network() {
    log "Creating bridge network configuration..."
    
    cat > "$SYSTEMD_NETWORK_DIR/20-${BRIDGE_NAME}.network" << EOF
# Bridge network configuration
[Match]
Name=${BRIDGE_NAME}

[Network]
# Disable DHCP on bridge itself
DHCP=no
# Enable IP forwarding
IPForward=yes
# Disable IPv6 router advertisements
IPv6AcceptRA=false

# Create VLAN interfaces on bridge
VLAN=${BRIDGE_NAME}.10
VLAN=${BRIDGE_NAME}.20
VLAN=${BRIDGE_NAME}.30
VLAN=${BRIDGE_NAME}.40

# Management VLAN IP address (host management)
[Address]
Address=192.168.10.2/28

[Route]
# Default route via management VLAN gateway
Gateway=192.168.10.1
Destination=0.0.0.0/0
EOF

    log "Created bridge network config: $SYSTEMD_NETWORK_DIR/20-${BRIDGE_NAME}.network"
}

# Create VLAN interface configurations
create_vlan_interfaces() {
    log "Creating VLAN interface configurations..."
    
    for vlan_id in "${!VLANS[@]}"; do
        local vlan_name="${BRIDGE_NAME}.${vlan_id}"
        local vlan_desc=""
        
        case $vlan_id in
            10) vlan_desc="Management" ;;
            20) vlan_desc="LAN" ;;
            30) vlan_desc="DMZ" ;;
            40) vlan_desc="Guest" ;;
        esac
        
        # Create VLAN netdev
        cat > "$SYSTEMD_NETWORK_DIR/25-${vlan_name}.netdev" << EOF
# ${vlan_desc} VLAN interface
[NetDev]
Name=${vlan_name}
Kind=vlan

[VLAN]
Id=${vlan_id}
EOF

        # Create VLAN network configuration
        cat > "$SYSTEMD_NETWORK_DIR/30-${vlan_name}.network" << EOF
# ${vlan_desc} VLAN network configuration
[Match]
Name=${vlan_name}

[Network]
# VLAN interfaces don't need IP addresses on host
# (pfSense VM will handle routing)
DHCP=no
IPv6AcceptRA=false

# Set up VLAN filtering rules if needed
[Bridge]
PVID=${vlan_id}
VLAN=${vlan_id}
EOF

        log "Created VLAN $vlan_id (${vlan_desc}) configuration"
    done
}

# Configure firewall rules for host
configure_host_firewall() {
    log "Configuring host firewall rules..."
    
    # Enable firewalld if not already enabled
    systemctl enable firewalld
    
    # Create management zone for VLAN 10
    firewall-cmd --permanent --new-zone=mgmt 2>/dev/null || true
    firewall-cmd --permanent --zone=mgmt --add-interface=${BRIDGE_NAME}.10
    firewall-cmd --permanent --zone=mgmt --add-service=ssh
    firewall-cmd --permanent --zone=mgmt --add-service=libvirt
    firewall-cmd --permanent --zone=mgmt --add-port=9200/tcp  # Elasticsearch
    firewall-cmd --permanent --zone=mgmt --add-port=5601/tcp  # Kibana
    
    # Remove bridge and VLAN interfaces from public zone
    firewall-cmd --permanent --zone=public --remove-interface=${BRIDGE_NAME} 2>/dev/null || true
    for vlan_id in "${!VLANS[@]}"; do
        firewall-cmd --permanent --zone=public --remove-interface=${BRIDGE_NAME}.${vlan_id} 2>/dev/null || true
    done
    
    log "Firewall configuration applied"
}

# Validate network configuration
validate_config() {
    log "Validating network configuration..."
    
    # Check for syntax errors in networkd config files
    if ! systemd-analyze verify "$SYSTEMD_NETWORK_DIR"/*.network "$SYSTEMD_NETWORK_DIR"/*.netdev; then
        warn "Configuration validation failed, but continuing..."
    fi
    
    log "Configuration validation completed"
}

# Apply network configuration
apply_config() {
    log "Applying network configuration..."
    
    # Restart systemd-networkd
    systemctl restart systemd-networkd
    systemctl enable systemd-networkd
    
    # Restart systemd-resolved
    systemctl restart systemd-resolved
    systemctl enable systemd-resolved
    
    # Wait for network to come up
    sleep 5
    
    # Show network status
    log "Network interfaces status:"
    ip addr show | grep -E "^[0-9]+:|inet "
    
    log "Bridge VLAN configuration:"
    bridge vlan show 2>/dev/null || warn "Bridge VLAN filtering not available"
}

# Create helper scripts
create_helper_scripts() {
    log "Creating helper scripts..."
    
    # Network status script
    cat > /usr/local/bin/homelab-network-status << 'EOF'
#!/bin/bash
# Display home lab network status

echo "=== Home Lab Network Status ==="
echo

echo "Bridge Interfaces:"
ip addr show br0 | grep -E "br0:|inet "
echo

echo "VLAN Interfaces:"
for vlan in br0.10 br0.20 br0.30 br0.40; do
    if ip link show $vlan >/dev/null 2>&1; then
        echo "$vlan: $(ip addr show $vlan | grep inet | awk '{print $2}')"
    fi
done
echo

echo "Bridge VLAN Configuration:"
bridge vlan show 2>/dev/null || echo "VLAN filtering not available"
echo

echo "Routing Table:"
ip route show
echo

echo "Active Network Connections:"
ss -tuln | head -10
EOF

    chmod +x /usr/local/bin/homelab-network-status
    
    # Network restart script
    cat > /usr/local/bin/homelab-network-restart << 'EOF'
#!/bin/bash
# Restart home lab networking

echo "Restarting home lab networking..."
systemctl restart systemd-networkd
systemctl restart systemd-resolved
sleep 5
echo "Network restart completed"
homelab-network-status
EOF

    chmod +x /usr/local/bin/homelab-network-restart
    
    log "Helper scripts created:"
    log "  - homelab-network-status: Show network status"
    log "  - homelab-network-restart: Restart networking"
}

# Main execution
main() {
    echo -e "${BLUE}"
    echo "=============================================="
    echo "    Home Lab VLAN Bridge Configuration"
    echo "=============================================="
    echo -e "${NC}"
    
    check_root
    
    log "Starting network configuration setup..."
    log "Bridge: $BRIDGE_NAME"
    log "VLANs: ${!VLANS[*]}"
    
    # Confirm before proceeding
    echo
    warn "This will modify your network configuration."
    warn "Ensure you have console access in case of network issues."
    read -p "Continue? [y/N]: " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Configuration cancelled by user"
        exit 0
    fi
    
    backup_config
    detect_interface
    
    # Create systemd-networkd directory if it doesn't exist
    mkdir -p "$SYSTEMD_NETWORK_DIR"
    
    create_bridge_netdev
    bind_physical_interface
    create_bridge_network
    create_vlan_interfaces
    configure_host_firewall
    validate_config
    apply_config
    create_helper_scripts
    
    echo
    log "Network configuration completed successfully!"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Verify network connectivity: homelab-network-status"
    echo "2. Configure pfSense VM with VLAN interfaces"
    echo "3. Test inter-VLAN connectivity"
    echo
    echo -e "${YELLOW}Important:${NC}"
    echo "- Host management IP: 192.168.10.2"
    echo "- pfSense management will be: 192.168.10.1"
    echo "- Ensure upstream router routes VLANs to pfSense"
    echo
}

# Execute main function
main "$@"