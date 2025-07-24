# openSUSE MicroOS Installation Guide

This guide provides step-by-step instructions for installing and configuring openSUSE MicroOS as the immutable host OS for your secure home lab environment.

## Overview

openSUSE MicroOS is an immutable Linux distribution designed for containerized and virtualized workloads. It uses transactional updates, providing atomic updates and rollback capabilities, making it ideal for a secure and maintainable home lab infrastructure.

## Prerequisites

### Hardware Requirements
- **CPU**: x86_64 with virtualization extensions (Intel VT-x or AMD-V)
- **RAM**: Minimum 16GB (32GB recommended)
- **Storage**: 200GB+ NVMe SSD (500GB recommended)
- **Network**: Single gigabit NIC capable of VLAN trunking
- **UEFI**: Modern UEFI firmware with Secure Boot support

### Network Planning
Before installation, plan your network configuration:
```
Physical NIC → br0 (VLAN trunk bridge)
├── VLAN 10: Management (192.168.10.0/28)
├── VLAN 20: LAN (192.168.20.0/24)
├── VLAN 30: DMZ (192.168.30.0/28)
└── VLAN 40: Guest (192.168.40.0/26)
```

## Installation Process

### Step 1: Download openSUSE MicroOS

1. **Download the ISO**:
   ```bash
   # Download from official repository
   wget https://download.opensuse.org/tumbleweed/iso/openSUSE-MicroOS-DVD-x86_64-Current.iso
   
   # Verify checksum
   wget https://download.opensuse.org/tumbleweed/iso/openSUSE-MicroOS-DVD-x86_64-Current.iso.sha256
   sha256sum -c openSUSE-MicroOS-DVD-x86_64-Current.iso.sha256
   ```

2. **Create installation media**:
   ```bash
   # Using dd (Linux/macOS)
   sudo dd if=openSUSE-MicroOS-DVD-x86_64-Current.iso of=/dev/sdX bs=4M status=progress
   
   # Or use Rufus/Etcher for Windows/GUI
   ```

### Step 2: Boot and Initial Setup

1. **Boot from installation media**
2. **Select installation options**:
   - Choose "Installation" from boot menu
   - Select language and keyboard layout
   - Accept license agreement

### Step 3: System Configuration

#### Disk Partitioning
Configure disk layout for optimal performance and security:

```
Partition Layout (500GB SSD example):
/dev/sda1    512MB   EFI System Partition (FAT32)
/dev/sda2    2GB     /boot (ext4)
/dev/sda3    32GB    swap
/dev/sda4    465GB   / (Btrfs with subvolumes)
```

**Recommended Btrfs subvolumes**:
```
@                    # Root filesystem
@/home              # User home directories
@/opt               # Optional software
@/srv               # Service data
@/tmp               # Temporary files
@/usr/local         # Local software
@/var               # Variable data
@/var/log           # System logs
@/var/lib/libvirt   # VM storage
```

#### Network Configuration
1. **Configure primary network interface**:
   - Set static IP on management VLAN
   - Configure as bridge interface (br0)
   - Enable VLAN trunking

2. **Example network configuration**:
   ```yaml
   # /etc/systemd/network/10-br0.netdev
   [NetDev]
   Name=br0
   Kind=bridge
   
   [Bridge]
   STP=true
   DefaultPVID=10
   VLANFiltering=true
   ```

   ```yaml
   # /etc/systemd/network/20-br0.network
   [Match]
   Name=br0
   
   [Network]
   DHCP=no
   IPForward=yes
   VLAN=br0.10
   VLAN=br0.20
   VLAN=br0.30
   VLAN=br0.40
   
   [Address]
   Address=192.168.10.10/28
   
   [Route]
   Gateway=192.168.10.1
   ```

#### User Account Setup
1. **Create administrative user**:
   - Username: `admin` (or your preferred name)
   - Strong password or SSH key authentication
   - Add to `wheel` group for sudo access

2. **Disable root login**:
   - Root account should be disabled for SSH access
   - Use sudo for administrative tasks

### Step 4: Post-Installation Configuration

#### Enable Essential Services
```bash
# Enable and start systemd-networkd
sudo systemctl enable systemd-networkd
sudo systemctl start systemd-networkd

# Enable and start systemd-resolved
sudo systemctl enable systemd-resolved
sudo systemctl start systemd-resolved

# Enable SSH daemon
sudo systemctl enable sshd
sudo systemctl start sshd

# Enable libvirtd for virtualization
sudo systemctl enable libvirtd
sudo systemctl start libvirtd
```

#### Install Required Packages
```bash
# Install virtualization packages
sudo transactional-update pkg install \
  qemu-kvm \
  libvirt \
  libvirt-client \
  virt-install \
  virt-manager \
  bridge-utils \
  vlan

# Install container runtime
sudo transactional-update pkg install \
  podman \
  buildah \
  skopeo

# Install network tools
sudo transactional-update pkg install \
  tcpdump \
  wireshark \
  nmap \
  iptables \
  ebtables

# Reboot to apply changes
sudo systemctl reboot
```

## Network Bridge Configuration

### Create VLAN-Aware Bridge

1. **Create bridge interface configuration**:
   ```bash
   sudo tee /etc/systemd/network/10-br0.netdev << EOF
   [NetDev]
   Name=br0
   Kind=bridge
   
   [Bridge]
   STP=true
   DefaultPVID=10
   VLANFiltering=true
   EOF
   ```

2. **Bind physical interface to bridge**:
   ```bash
   sudo tee /etc/systemd/network/15-eth0.network << EOF
   [Match]
   Name=eth0
   
   [Network]
   Bridge=br0
   EOF
   ```

3. **Configure bridge networking**:
   ```bash
   sudo tee /etc/systemd/network/20-br0.network << EOF
   [Match]
   Name=br0
   
   [Network]
   DHCP=no
   IPForward=yes
   
   # Management VLAN interface
   VLAN=br0.10
   
   [Address]
   Address=192.168.10.10/28
   
   [Route]
   Gateway=192.168.10.1
   Destination=0.0.0.0/0
   EOF
   ```

4. **Create VLAN interfaces**:
   ```bash
   # VLAN 10 (Management)
   sudo tee /etc/systemd/network/25-br0.10.netdev << EOF
   [NetDev]
   Name=br0.10
   Kind=vlan
   
   [VLAN]
   Id=10
   EOF
   
   # Repeat for other VLANs (20, 30, 40)
   ```

## Virtualization Setup

### Configure KVM/QEMU

1. **Verify virtualization support**:
   ```bash
   # Check CPU virtualization features
   lscpu | grep Virtualization
   
   # Verify KVM modules are loaded
   lsmod | grep kvm
   
   # Check libvirt status
   sudo systemctl status libvirtd
   ```

2. **Configure libvirt networking**:
   ```bash
   # Create isolated network for VMs
   sudo tee /tmp/isolated-network.xml << EOF
   <network>
     <name>isolated</name>
     <bridge name="virbr1" stp="on" delay="0"/>
     <domain name="isolated"/>
   </network>
   EOF
   
   # Define and start the network
   sudo virsh net-define /tmp/isolated-network.xml
   sudo virsh net-autostart isolated
   sudo virsh net-start isolated
   ```

3. **Configure VM storage**:
   ```bash
   # Create storage pool for VM images
   sudo mkdir -p /var/lib/libvirt/images
   
   # Set proper permissions
   sudo chown root:kvm /var/lib/libvirt/images
   sudo chmod 775 /var/lib/libvirt/images
   
   # Configure SELinux context (if enabled)
   sudo setsebool -P virt_use_nfs 1
   ```

### User and Group Configuration

1. **Add user to required groups**:
   ```bash
   # Add user to libvirt group
   sudo usermod -a -G libvirt $USER
   
   # Add user to kvm group
   sudo usermod -a -G kvm $USER
   
   # Verify group membership
   groups $USER
   ```

2. **Configure polkit for libvirt**:
   ```bash
   sudo tee /etc/polkit-1/rules.d/50-libvirt.rules << EOF
   polkit.addRule(function(action, subject) {
       if (action.id == "org.libvirt.unix.manage" &&
           subject.isInGroup("libvirt")) {
               return polkit.Result.YES;
       }
   });
   EOF
   ```

## Security Hardening

### SSH Configuration

1. **Configure SSH for key-based authentication**:
   ```bash
   # Generate SSH key pair (on client machine)
   ssh-keygen -t ed25519 -C "homelab-admin"
   
   # Copy public key to server
   ssh-copy-id admin@192.168.10.10
   ```

2. **Harden SSH configuration**:
   ```bash
   sudo tee -a /etc/ssh/sshd_config << EOF
   # Security hardening
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   AuthorizedKeysFile .ssh/authorized_keys
   Protocol 2
   Port 22
   MaxAuthTries 3
   ClientAliveInterval 300
   ClientAliveCountMax 2
   AllowUsers admin
   EOF
   
   # Restart SSH service
   sudo systemctl restart sshd
   ```

### Firewall Configuration

1. **Configure firewalld**:
   ```bash
   # Enable firewalld
   sudo systemctl enable firewalld
   sudo systemctl start firewalld
   
   # Configure management zone
   sudo firewall-cmd --permanent --new-zone=mgmt
   sudo firewall-cmd --permanent --zone=mgmt --add-interface=br0.10
   sudo firewall-cmd --permanent --zone=mgmt --add-service=ssh
   sudo firewall-cmd --permanent --zone=mgmt --add-service=libvirt
   
   # Apply configuration
   sudo firewall-cmd --reload
   ```

### Enable Automatic Updates

1. **Configure transactional-update**:
   ```bash
   sudo tee /etc/systemd/system/transactional-update.timer.d/override.conf << EOF
   [Timer]
   OnCalendar=daily
   Persistent=true
   RandomizedDelaySec=1h
   EOF
   
   # Enable automatic updates
   sudo systemctl enable transactional-update.timer
   sudo systemctl start transactional-update.timer
   ```

## Verification and Testing

### System Health Check

1. **Verify system status**:
   ```bash
   # Check system status
   systemctl status
   
   # Verify network configuration
   ip addr show
   ip route show
   
   # Check virtualization
   sudo virsh list --all
   sudo virsh net-list --all
   
   # Verify container runtime
   podman version
   ```

2. **Test network connectivity**:
   ```bash
   # Test internet connectivity
   ping -c 4 8.8.8.8
   
   # Test DNS resolution
   nslookup google.com
   
   # Test VLAN interfaces
   ping -c 4 192.168.10.1  # Management gateway
   ```

### Performance Baseline

1. **System resource check**:
   ```bash
   # CPU information
   lscpu
   
   # Memory usage
   free -h
   
   # Storage performance
   sudo hdparm -tT /dev/sda
   
   # Network interface status
   ethtool eth0
   ```

## Next Steps

After completing the MicroOS installation:

1. **Deploy pfSense VM**: Follow the [pfSense VM Setup Guide](../pfsense-vm/installation/vm-setup.md)
2. **Configure Network Topology**: Set up VLANs and firewall rules
3. **Deploy ELK Stack**: Install security monitoring infrastructure
4. **Apply Security Hardening**: Follow the [Security Hardening Guide](security-hardening.md)

## Troubleshooting

### Common Issues

#### Network Bridge Not Working
```bash
# Check bridge status
sudo brctl show

# Verify VLAN filtering
sudo bridge vlan show

# Check systemd-networkd logs
sudo journalctl -u systemd-networkd -f
```

#### Virtualization Not Available
```bash
# Check BIOS settings for VT-x/AMD-V
# Verify secure boot configuration
sudo dmesg | grep -i kvm

# Check libvirt daemon
sudo systemctl status libvirtd
sudo virsh capabilities
```

#### Transactional Updates Failing
```bash
# Check update logs
sudo journalctl -u transactional-update

# Manual rollback if needed
sudo transactional-update rollback
sudo systemctl reboot
```

For additional troubleshooting, see the main [Troubleshooting Guide](../pfsense-elk-security/docs/troubleshooting.md).

## Maintenance

### Regular Maintenance Tasks

1. **Monitor system health**:
   ```bash
   # Check system status weekly
   sudo systemctl status
   sudo journalctl --since "7 days ago" --priority=err
   ```

2. **Update system monthly**:
   ```bash
   # Check for updates
   sudo transactional-update dup
   sudo systemctl reboot
   ```

3. **Backup configuration**:
   ```bash
   # Backup network configuration
   sudo tar -czf network-config-$(date +%Y%m%d).tar.gz /etc/systemd/network/
   
   # Backup VM definitions
   sudo virsh dumpxml pfsense > pfsense-config-$(date +%Y%m%d).xml
   ```

This completes the openSUSE MicroOS installation and initial configuration. The system is now ready for pfSense VM deployment and additional security hardening.