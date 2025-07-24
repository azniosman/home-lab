# pfSense Virtual Machine Setup Guide

This guide provides comprehensive instructions for creating and configuring a pfSense virtual machine on openSUSE MicroOS using KVM/QEMU with libvirt.

## Overview

The pfSense VM serves as the central network firewall and router for the home lab environment, providing:
- VLAN-based network segmentation
- Inter-VLAN routing and security policies
- DHCP and DNS services
- Firewall protection and monitoring
- VPN gateway capabilities

## Prerequisites

### Host System Requirements
- openSUSE MicroOS with KVM/QEMU installed
- Minimum 2GB RAM allocated for pfSense VM
- 8GB disk space for pfSense installation
- VLAN-aware bridge networking configured
- Internet connectivity for pfSense ISO download

### Network Configuration
Ensure the host networking is properly configured with VLAN bridge:
```bash
# Verify bridge exists
ip link show br0

# Check VLAN interfaces
ip link show | grep br0\.

# Test bridge VLAN filtering
bridge vlan show
```

## pfSense VM Creation

### Step 1: Download pfSense ISO

1. **Download the latest pfSense ISO**:
   ```bash
   # Create ISO directory
   sudo mkdir -p /var/lib/libvirt/images/iso
   cd /var/lib/libvirt/images/iso
   
   # Download pfSense (replace URL with latest version)
   sudo wget https://files.netgate.com/file/pfSense-releases/2.7.0/pfSense-CE-2.7.0-RELEASE-amd64.iso.gz
   
   # Extract ISO
   sudo gunzip pfSense-CE-2.7.0-RELEASE-amd64.iso.gz
   
   # Verify download
   sudo ls -la pfSense-CE-*.iso
   ```

2. **Set proper permissions**:
   ```bash
   sudo chown root:kvm /var/lib/libvirt/images/iso/pfSense-CE-*.iso
   sudo chmod 644 /var/lib/libvirt/images/iso/pfSense-CE-*.iso
   ```

### Step 2: Create VM Storage

1. **Create disk image for pfSense**:
   ```bash
   # Create 8GB disk image
   sudo qemu-img create -f qcow2 /var/lib/libvirt/images/pfsense.qcow2 8G
   
   # Set permissions
   sudo chown root:kvm /var/lib/libvirt/images/pfsense.qcow2
   sudo chmod 644 /var/lib/libvirt/images/pfsense.qcow2
   ```

### Step 3: Define VM Network Interfaces

Create libvirt network configuration for VLAN interfaces:

1. **Create VLAN network definitions**:
   ```bash
   # Management VLAN (VLAN 10)
   sudo tee /tmp/vlan10-network.xml << EOF
   <network>
     <name>vlan10-mgmt</name>
     <forward mode='bridge'/>
     <bridge name='br0'/>
     <vlan tag='10'/>
     <virtualport type='openvswitch'/>
   </network>
   EOF
   
   # LAN VLAN (VLAN 20)
   sudo tee /tmp/vlan20-network.xml << EOF
   <network>
     <name>vlan20-lan</name>
     <forward mode='bridge'/>
     <bridge name='br0'/>
     <vlan tag='20'/>
     <virtualport type='openvswitch'/>
   </network>
   EOF
   
   # DMZ VLAN (VLAN 30)
   sudo tee /tmp/vlan30-network.xml << EOF
   <network>
     <name>vlan30-dmz</name>
     <forward mode='bridge'/>
     <bridge name='br0'/>
     <vlan tag='30'/>
     <virtualport type='openvswitch'/>
   </network>
   EOF
   
   # Guest VLAN (VLAN 40)
   sudo tee /tmp/vlan40-network.xml << EOF
   <network>
     <name>vlan40-guest</name>
     <forward mode='bridge'/>
     <bridge name='br0'/>
     <vlan tag='40'/>
     <virtualport type='openvswitch'/>
   </network>
   EOF
   ```

2. **Define and start networks**:
   ```bash
   # Define networks
   sudo virsh net-define /tmp/vlan10-network.xml
   sudo virsh net-define /tmp/vlan20-network.xml
   sudo virsh net-define /tmp/vlan30-network.xml
   sudo virsh net-define /tmp/vlan40-network.xml
   
   # Set networks to autostart
   sudo virsh net-autostart vlan10-mgmt
   sudo virsh net-autostart vlan20-lan
   sudo virsh net-autostart vlan30-dmz
   sudo virsh net-autostart vlan40-guest
   
   # Start networks
   sudo virsh net-start vlan10-mgmt
   sudo virsh net-start vlan20-lan
   sudo virsh net-start vlan30-dmz
   sudo virsh net-start vlan40-guest
   
   # Verify networks
   sudo virsh net-list --all
   ```

### Step 4: Create pfSense VM Definition

1. **Create VM XML configuration**:
   ```bash
   sudo tee /tmp/pfsense-vm.xml << EOF
   <domain type='kvm'>
     <name>pfsense</name>
     <uuid>$(uuidgen)</uuid>
     <memory unit='KiB'>2097152</memory>
     <currentMemory unit='KiB'>2097152</currentMemory>
     <vcpu placement='static'>2</vcpu>
     <os>
       <type arch='x86_64' machine='pc-q35-4.2'>hvm</type>
       <boot dev='cdrom'/>
       <boot dev='hd'/>
     </os>
     <features>
       <acpi/>
       <apic/>
       <vmport state='off'/>
     </features>
     <cpu mode='host-model' check='partial'/>
     <clock offset='utc'>
       <timer name='rtc' tickpolicy='catchup'/>
       <timer name='pit' tickpolicy='delay'/>
       <timer name='hpet' present='no'/>
     </clock>
     <on_poweroff>destroy</on_poweroff>
     <on_reboot>restart</on_reboot>
     <on_crash>destroy</on_crash>
     <pm>
       <suspend-to-mem enabled='no'/>
       <suspend-to-disk enabled='no'/>
     </pm>
     <devices>
       <emulator>/usr/bin/qemu-system-x86_64</emulator>
       <disk type='file' device='disk'>
         <driver name='qemu' type='qcow2'/>
         <source file='/var/lib/libvirt/images/pfsense.qcow2'/>
         <target dev='vda' bus='virtio'/>
         <address type='pci' domain='0x0000' bus='0x04' slot='0x00' function='0x0'/>
       </disk>
       <disk type='file' device='cdrom'>
         <driver name='qemu' type='raw'/>
         <source file='/var/lib/libvirt/images/iso/pfSense-CE-2.7.0-RELEASE-amd64.iso'/>
         <target dev='sda' bus='sata'/>
         <readonly/>
         <address type='drive' controller='0' bus='0' target='0' unit='0'/>
       </disk>
       <controller type='usb' index='0' model='qemu-xhci' ports='15'>
         <address type='pci' domain='0x0000' bus='0x02' slot='0x00' function='0x0'/>
       </controller>
       <controller type='sata' index='0'>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x1f' function='0x2'/>
       </controller>
       <controller type='pci' index='0' model='pcie-root'/>
       <controller type='pci' index='1' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='1' port='0x10'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0' multifunction='on'/>
       </controller>
       <controller type='pci' index='2' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='2' port='0x11'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x1'/>
       </controller>
       <controller type='pci' index='3' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='3' port='0x12'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x2'/>
       </controller>
       <controller type='pci' index='4' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='4' port='0x13'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x3'/>
       </controller>
       <controller type='pci' index='5' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='5' port='0x14'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x4'/>
       </controller>
       <controller type='pci' index='6' model='pcie-root-port'>
         <model name='pcie-root-port'/>
         <target chassis='6' port='0x15'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x5'/>
       </controller>
       <controller type='virtio-serial' index='0'>
         <address type='pci' domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
       </controller>
       <!-- Management Interface (VLAN 10) -->
       <interface type='network'>
         <mac address='52:54:00:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g; s/:$//")'/>
         <source network='vlan10-mgmt'/>
         <model type='virtio'/>
         <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
       </interface>
       <!-- LAN Interface (VLAN 20) -->
       <interface type='network'>
         <mac address='52:54:00:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g; s/:$//")'/>
         <source network='vlan20-lan'/>
         <model type='virtio'/>
         <address type='pci' domain='0x0000' bus='0x05' slot='0x00' function='0x0'/>
       </interface>
       <!-- DMZ Interface (VLAN 30) -->
       <interface type='network'>
         <mac address='52:54:00:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g; s/:$//")'/>
         <source network='vlan30-dmz'/>
         <model type='virtio'/>
         <address type='pci' domain='0x0000' bus='0x06' slot='0x00' function='0x0'/>
       </interface>
       <!-- Guest Interface (VLAN 40) -->
       <interface type='network'>
         <mac address='52:54:00:$(openssl rand -hex 3 | sed "s/\(..\)/\1:/g; s/:$//")'/>
         <source network='vlan40-guest'/>
         <model type='virtio'/>
         <address type='pci' domain='0x0000' bus='0x07' slot='0x00' function='0x0'/>
       </interface>
       <serial type='pty'>
         <target type='isa-serial' port='0'>
           <model name='isa-serial'/>
         </target>
       </serial>
       <console type='pty'>
         <target type='serial' port='0'/>
       </console>
       <channel type='unix'>
         <target type='virtio' name='org.qemu.guest_agent.0'/>
         <address type='virtio-serial' controller='0' bus='0' port='1'/>
       </channel>
       <input type='tablet' bus='usb'>
         <address type='usb' bus='0' port='1'/>
       </input>
       <input type='mouse' bus='ps2'/>
       <input type='keyboard' bus='ps2'/>
       <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>
         <listen type='address' address='127.0.0.1'/>
       </graphics>
       <sound model='ich9'>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x1b' function='0x0'/>
       </sound>
       <video>
         <model type='qxl' ram='65536' vram='65536' vgamem='16384' heads='1' primary='yes'/>
         <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x0'/>
       </video>
       <redirdev bus='usb' type='spicevmc'>
         <address type='usb' bus='0' port='2'/>
       </redirdev>
       <redirdev bus='usb' type='spicevmc'>
         <address type='usb' bus='0' port='3'/>
       </redirdev>
       <memballoon model='virtio'>
         <address type='pci' domain='0x0000' bus='0x08' slot='0x00' function='0x0'/>
       </memballoon>
       <rng model='virtio'>
         <backend model='random'>/dev/urandom</backend>
         <address type='pci' domain='0x0000' bus='0x09' slot='0x00' function='0x0'/>
       </rng>
     </devices>
   </domain>
   EOF
   ```

2. **Define and start the VM**:
   ```bash
   # Define the VM
   sudo virsh define /tmp/pfsense-vm.xml
   
   # Set VM to autostart
   sudo virsh autostart pfsense
   
   # Start the VM
   sudo virsh start pfsense
   
   # Verify VM is running
   sudo virsh list --all
   ```

## pfSense Installation

### Step 1: Connect to VM Console

1. **Connect via VNC**:
   ```bash
   # Find VNC port
   sudo virsh vncdisplay pfsense
   
   # Connect with VNC viewer (example with vncviewer)
   vncviewer localhost:5900
   ```

2. **Alternative: Use virsh console**:
   ```bash
   sudo virsh console pfsense
   ```

### Step 2: pfSense Installation Process

1. **Boot from ISO**:
   - VM should boot from the pfSense ISO
   - Select "Install pfSense" from the boot menu

2. **Installation Options**:
   - Accept the license agreement
   - Choose "Quick/Easy Install"
   - Select the target disk (should be the 8GB virtual disk)
   - Confirm installation

3. **Complete Installation**:
   - Wait for installation to complete
   - Remove ISO and reboot when prompted
   - VM will reboot into pfSense

### Step 3: Initial pfSense Configuration

1. **Console Setup**:
   - Wait for pfSense to boot
   - You'll see the pfSense console menu
   - Note the interface assignments (may need to configure)

2. **Interface Assignment**:
   ```
   Available interfaces:
   vtnet0 - Management (VLAN 10)
   vtnet1 - LAN (VLAN 20)  
   vtnet2 - DMZ (VLAN 30)
   vtnet3 - Guest (VLAN 40)
   ```

3. **Assign Interfaces** (Option 1 from console):
   ```
   WAN interface: vtnet0 (Management - will act as WAN for initial setup)
   LAN interface: vtnet1 (LAN)
   OPT1 interface: vtnet2 (DMZ)
   OPT2 interface: vtnet3 (Guest)
   ```

4. **Set Interface IP Addresses** (Option 2 from console):
   ```
   LAN Interface (vtnet1):
   IP Address: 192.168.20.1
   Subnet: 24
   DHCP: Yes
   DHCP Range: 192.168.20.100 to 192.168.20.199
   ```

## Network Interface Configuration

### Step 1: Configure Management Interface

1. **Set Management Interface** (Option 2 from console):
   ```
   Management Interface (vtnet0):
   IP Address: 192.168.10.1
   Subnet: 28 (255.255.255.240)
   Gateway: 192.168.10.1 (upstream router)
   ```

### Step 2: Configure Additional Interfaces

1. **DMZ Interface** (vtnet2):
   ```
   IP Address: 192.168.30.1
   Subnet: 28
   DHCP: Enabled
   DHCP Range: 192.168.30.10 to 192.168.30.14
   ```

2. **Guest Interface** (vtnet3):
   ```
   IP Address: 192.168.40.1
   Subnet: 26
   DHCP: Enabled
   DHCP Range: 192.168.40.10 to 192.168.40.60
   ```

### Step 3: Enable Web Interface Access

1. **Access Web Interface**:
   - Open browser on management network
   - Navigate to: https://192.168.10.1
   - Default credentials: admin/pfsense

2. **Initial Web Configuration**:
   - Complete the setup wizard
   - Change default password
   - Configure timezone and hostname
   - Update interface assignments if needed

## Advanced Configuration

### VLAN Configuration

1. **Navigate to Interfaces → Assignments → VLANs**
2. **Create VLANs** (if not already configured):
   ```
   VLAN 10: Management (vtnet0)
   VLAN 20: LAN (vtnet1)
   VLAN 30: DMZ (vtnet2)
   VLAN 40: Guest (vtnet3)
   ```

### Firewall Rules

1. **Configure Inter-VLAN Rules**:
   ```
   Management VLAN:
   - Allow all traffic (administrative access)
   
   LAN VLAN:
   - Allow internet access
   - Allow access to DMZ services (ports 80, 443)
   - Block access to Management VLAN
   
   DMZ VLAN:
   - Allow limited internet access (ports 80, 443, 53)
   - Block access to LAN and Management VLANs
   
   Guest VLAN:
   - Allow internet access only
   - Block all internal network access
   ```

### DHCP Configuration

1. **Configure DHCP Servers**:
   - Navigate to Services → DHCP Server
   - Configure each VLAN's DHCP settings
   - Set appropriate lease times and options

### DNS Configuration

1. **Configure DNS Resolver**:
   - Navigate to Services → DNS Resolver
   - Enable DNS resolver
   - Configure forwarding to upstream DNS servers
   - Set up custom host entries for internal services

## Security Hardening

### Web Interface Security

1. **Change Default Credentials**:
   - Navigate to System → User Manager
   - Change admin password to strong password
   - Consider creating additional administrative users

2. **Enable HTTPS**:
   - Navigate to System → Advanced → Admin Access
   - Enable HTTPS redirect
   - Consider installing custom SSL certificate

### Firewall Security

1. **Default Deny Policy**:
   - Ensure default deny rules are in place
   - Only allow necessary traffic

2. **Logging**:
   - Enable firewall logging
   - Configure remote syslog to ELK Stack
   - Navigate to Status → System Logs → Settings

### Network Security

1. **Disable Unused Services**:
   - Navigate to System → Advanced
   - Disable unnecessary services
   - Review and secure enabled services

2. **Enable Intrusion Detection**:
   - Consider installing Suricata or Snort
   - Navigate to System → Package Manager
   - Install and configure IDS/IPS

## Integration with ELK Stack

### Configure Remote Logging

1. **Navigate to Status → System Logs → Settings**
2. **Configure Remote Logging**:
   ```
   Remote Syslog Server: 192.168.10.3:514
   Remote Log Contents: Everything
   Source Address: 192.168.10.1
   ```

3. **Test Log Forwarding**:
   - Generate test traffic
   - Verify logs appear in ELK Stack
   - Check Kibana dashboards

## VM Management

### VM Operations

1. **Start/Stop VM**:
   ```bash
   # Start VM
   sudo virsh start pfsense
   
   # Stop VM gracefully
   sudo virsh shutdown pfsense
   
   # Force stop VM
   sudo virsh destroy pfsense
   
   # Check VM status
   sudo virsh list --all
   ```

2. **VM Information**:
   ```bash
   # Show VM info
   sudo virsh dominfo pfsense
   
   # Show VM configuration
   sudo virsh dumpxml pfsense
   
   # Show VM console
   sudo virsh console pfsense
   ```

### Backup and Snapshots

1. **Create VM Snapshot**:
   ```bash
   # Create snapshot
   sudo virsh snapshot-create-as pfsense snapshot1 "Initial configuration"
   
   # List snapshots
   sudo virsh snapshot-list pfsense
   
   # Restore snapshot
   sudo virsh snapshot-revert pfsense snapshot1
   ```

2. **Backup VM Configuration**:
   ```bash
   # Export pfSense configuration via web interface
   # Diagnostics → Backup & Restore → Download configuration
   
   # Backup VM definition
   sudo virsh dumpxml pfsense > pfsense-config-$(date +%Y%m%d).xml
   
   # Backup disk image
   sudo cp /var/lib/libvirt/images/pfsense.qcow2 \
          /var/lib/libvirt/images/pfsense-backup-$(date +%Y%m%d).qcow2
   ```

## Troubleshooting

### Common Issues

#### VM Won't Start
```bash
# Check VM configuration
sudo virsh dumpxml pfsense | grep -i error

# Check libvirt logs
sudo journalctl -u libvirtd

# Verify disk image
sudo qemu-img check /var/lib/libvirt/images/pfsense.qcow2
```

#### Network Connectivity Issues
```bash
# Check network configuration
sudo virsh net-list --all

# Test bridge connectivity
bridge link show

# Check VLAN configuration
bridge vlan show
```

#### Console Access Issues
```bash
# Check VNC port
sudo virsh vncdisplay pfsense

# Use serial console
sudo virsh console pfsense

# Check VM status
sudo virsh domstate pfsense
```

### Performance Optimization

1. **VM Performance Tuning**:
   ```bash
   # Edit VM configuration
   sudo virsh edit pfsense
   
   # Add performance optimizations:
   # - CPU pinning
   # - NUMA topology
   # - Disk cache settings
   ```

2. **Network Performance**:
   - Use virtio network drivers
   - Enable multi-queue networking
   - Optimize bridge settings

## Maintenance

### Regular Maintenance Tasks

1. **Update pfSense**:
   - Use web interface: System → Update
   - Monitor update logs
   - Test functionality after updates

2. **Monitor Resources**:
   ```bash
   # Check VM resource usage
   sudo virsh domstats pfsense
   
   # Monitor host resources
   htop
   iotop
   ```

3. **Backup Configuration**:
   - Weekly pfSense configuration backups
   - Monthly VM snapshot creation
   - Quarterly full disk image backup

This completes the pfSense VM setup. The virtual firewall is now ready to provide network segmentation and security for your home lab environment.