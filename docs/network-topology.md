# Network Topology and VLAN Configuration

This document provides comprehensive network topology design and VLAN configuration for the secure home lab environment.

## Network Architecture Overview

### Physical Network Topology

```
Internet (WAN)
    │
    ▼
┌─────────────────────┐
│  QNAP QHora-301W    │  ← Primary WAN Router
│  (WAN Gateway)      │    - Internet connectivity
└─────────────────────┘    - First NAT layer
    │
    ▼
┌─────────────────────┐
│ Cloud Gateway Ultra │  ← Intermediate Router/Switch
│  (VLAN Router)      │    - VLAN management
└─────────────────────┘    - Second NAT layer
    │ (VLAN Trunk)
    ▼
┌─────────────────────┐
│ openSUSE MicroOS    │  ← Virtualization Host
│  Physical Host      │    - Single NIC (VLAN trunk)
│     (br0)           │    - Bridge interface
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│    pfSense VM       │  ← Virtual Firewall
│ (Virtual Firewall)  │    - Multi-VLAN routing
└─────────────────────┘    - Inter-VLAN security
    │
    ├── VLAN 10 (Management)
    ├── VLAN 20 (LAN)
    ├── VLAN 30 (DMZ)
    └── VLAN 40 (Guest)
```

### Logical Network Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Physical Host Network                    │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   br0 (VLAN Trunk)                     ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      ││
│  │  │VLAN 10  │ │VLAN 20  │ │VLAN 30  │ │VLAN 40  │      ││
│  │  │ Mgmt    │ │  LAN    │ │  DMZ    │ │ Guest   │      ││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     pfSense VM                              │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           │
│  │   em0   │ │   em1   │ │   em2   │ │   em3   │           │
│  │VLAN 10  │ │VLAN 20  │ │VLAN 30  │ │VLAN 40  │           │
│  │ Mgmt    │ │  LAN    │ │  DMZ    │ │ Guest   │           │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘           │
└─────────────────────────────────────────────────────────────┘
                              │
                    ┌─────────┼─────────┐
                    ▼         ▼         ▼
            ┌─────────┐ ┌─────────┐ ┌─────────┐
            │   VM1   │ │   VM2   │ │   VM3   │
            │ (Web)   │ │  (DB)   │ │ (Mon)   │
            │VLAN 30  │ │VLAN 20  │ │VLAN 10  │
            └─────────┘ └─────────┘ └─────────┘
```

## VLAN Design and Allocation

### VLAN Allocation Table

| VLAN ID | Name       | Network Segment  | Purpose                    | Security Level |
|---------|------------|------------------|----------------------------|----------------|
| 10      | Management | 192.168.10.0/28  | Infrastructure management  | High          |
| 20      | LAN        | 192.168.20.0/24  | Trusted workstations       | Medium        |
| 30      | DMZ        | 192.168.30.0/28  | Public-facing services     | Medium        |
| 40      | Guest      | 192.168.40.0/26  | Guest and IoT devices      | Low           |

### Detailed Network Configuration

#### VLAN 10 - Management Network
```
Network:        192.168.10.0/28
Subnet Mask:    255.255.255.240
Gateway:        192.168.10.1 (pfSense)
DHCP Range:     192.168.10.5 - 192.168.10.14
Static IPs:     192.168.10.2 - 192.168.10.4

Device Assignments:
192.168.10.1    pfSense Management Interface
192.168.10.2    openSUSE MicroOS Host
192.168.10.3    ELK Stack (Elasticsearch/Kibana)
192.168.10.4    Reserved for additional infrastructure
192.168.10.5+   DHCP pool for management devices
```

**Purpose**: Critical infrastructure components requiring secure access.
**Security**: 
- Restricted SSH access only
- VPN required for remote access
- Monitoring and logging enabled
- No internet access for most services

#### VLAN 20 - LAN Network
```
Network:        192.168.20.0/24
Subnet Mask:    255.255.255.0
Gateway:        192.168.20.1 (pfSense)
DHCP Range:     192.168.20.100 - 192.168.20.199
Static IPs:     192.168.20.10 - 192.168.20.99

Device Assignments:
192.168.20.1    pfSense LAN Interface
192.168.20.10+  Static assignments for servers
192.168.20.100+ DHCP pool for workstations
```

**Purpose**: Trusted internal network for workstations and authenticated users.
**Security**:
- Full internet access
- Access to DMZ services
- No access to Management VLAN
- Standard firewall filtering

#### VLAN 30 - DMZ Network
```
Network:        192.168.30.0/28
Subnet Mask:    255.255.255.240
Gateway:        192.168.30.1 (pfSense)
DHCP Range:     192.168.30.10 - 192.168.30.14
Static IPs:     192.168.30.5 - 192.168.30.9

Device Assignments:
192.168.30.1    pfSense DMZ Interface
192.168.30.5    Web Server VM
192.168.30.6    Application Server VM
192.168.30.7    Database Server VM (if public-facing)
192.168.30.8    Reserved
192.168.30.9    Reserved
```

**Purpose**: Public-facing services accessible from the internet.
**Security**:
- Limited internet access (outbound only as needed)
- No access to LAN or Management VLANs
- Strict firewall rules
- Enhanced monitoring and logging

#### VLAN 40 - Guest Network
```
Network:        192.168.40.0/26
Subnet Mask:    255.255.255.192
Gateway:        192.168.40.1 (pfSense)
DHCP Range:     192.168.40.10 - 192.168.40.60
Static IPs:     192.168.40.5 - 192.168.40.9

Device Assignments:
192.168.40.1    pfSense Guest Interface
192.168.40.5+   IoT devices (static assignments)
192.168.40.10+  Guest devices (DHCP)
```

**Purpose**: Isolated network for guest devices and IoT equipment.
**Security**:
- Internet access only
- No access to other VLANs
- Bandwidth limitations
- Time-based access controls

## pfSense Network Interface Configuration

### Virtual Network Interface Mapping

| Interface | VLAN | Network          | Description           |
|-----------|------|------------------|-----------------------|
| em0       | 10   | 192.168.10.0/28  | Management Interface  |
| em1       | 20   | 192.168.20.0/24  | LAN Interface         |
| em2       | 30   | 192.168.30.0/28  | DMZ Interface         |
| em3       | 40   | 192.168.40.0/26  | Guest Interface       |

### pfSense Interface Configuration

#### Management Interface (em0 - VLAN 10)
```xml
<interface>
    <if>em0</if>
    <descr>MGMT</descr>
    <enable>1</enable>
    <ipaddr>192.168.10.1</ipaddr>
    <subnet>28</subnet>
    <blockbogons>1</blockbogons>
    <blockpriv>1</blockpriv>
</interface>
```

#### LAN Interface (em1 - VLAN 20)
```xml
<interface>
    <if>em1</if>
    <descr>LAN</descr>
    <enable>1</enable>
    <ipaddr>192.168.20.1</ipaddr>
    <subnet>24</subnet>
    <blockbogons>1</blockbogons>
</interface>
```

#### DMZ Interface (em2 - VLAN 30)
```xml
<interface>
    <if>em2</if>
    <descr>DMZ</descr>
    <enable>1</enable>
    <ipaddr>192.168.30.1</ipaddr>
    <subnet>28</subnet>
    <blockbogons>1</blockbogons>
    <blockpriv>1</blockpriv>
</interface>
```

#### Guest Interface (em3 - VLAN 40)
```xml
<interface>
    <if>em3</if>
    <descr>GUEST</descr>
    <enable>1</enable>
    <ipaddr>192.168.40.1</ipaddr>
    <subnet>26</subnet>
    <blockbogons>1</blockbogons>
    <blockpriv>1</blockpriv>
</interface>
```

## Firewall Rules and Security Policies

### Inter-VLAN Access Matrix

| Source → Destination | Management | LAN  | DMZ  | Guest | Internet |
|---------------------|------------|------|------|-------|----------|
| **Management**      | ✓         | ✓    | ✓    | ✓     | ✓        |
| **LAN**             | ✗         | ✓    | ✓    | ✗     | ✓        |
| **DMZ**             | ✗         | ✗    | ✓    | ✗     | Limited  |
| **Guest**           | ✗         | ✗    | ✗    | ✓     | ✓        |
| **Internet**        | ✗         | ✗    | Limited | ✗   | N/A      |

### Firewall Rule Templates

#### Management VLAN Rules
```bash
# Allow SSH from management network
pass in on $mgmt_if inet proto tcp from $mgmt_net to $mgmt_if port 22

# Allow management access to all VLANs (for administration)
pass in on $mgmt_if inet from $mgmt_net to any

# Allow HTTPS to pfSense WebGUI
pass in on $mgmt_if inet proto tcp from $mgmt_net to $mgmt_if port 443

# Block everything else
block in on $mgmt_if all
```

#### LAN VLAN Rules
```bash
# Allow LAN to internet
pass in on $lan_if inet from $lan_net to any

# Allow LAN to DMZ (web services)
pass in on $lan_if inet proto tcp from $lan_net to $dmz_net port { 80 443 }

# Block LAN to management VLAN
block in on $lan_if inet from $lan_net to $mgmt_net

# Block LAN to guest VLAN
block in on $lan_if inet from $lan_net to $guest_net
```

#### DMZ VLAN Rules
```bash
# Allow DMZ outbound for updates (specific ports)
pass in on $dmz_if inet proto tcp from $dmz_net to any port { 80 443 53 }
pass in on $dmz_if inet proto udp from $dmz_net to any port 53

# Block DMZ to internal networks
block in on $dmz_if inet from $dmz_net to $mgmt_net
block in on $dmz_if inet from $dmz_net to $lan_net
block in on $dmz_if inet from $dmz_net to $guest_net

# Allow DMZ internal communication
pass in on $dmz_if inet from $dmz_net to $dmz_net
```

#### Guest VLAN Rules
```bash
# Allow guest internet access only
pass in on $guest_if inet from $guest_net to any port { 80 443 53 }
pass in on $guest_if inet proto udp from $guest_net to any port 53

# Block guest to all internal networks
block in on $guest_if inet from $guest_net to $mgmt_net
block in on $guest_if inet from $guest_net to $lan_net
block in on $guest_if inet from $guest_net to $dmz_net

# Bandwidth limiting for guest network
```

## DHCP and DNS Configuration

### DHCP Server Configuration

#### Management VLAN DHCP
```xml
<dhcp>
    <mgmt>
        <enable>1</enable>
        <range>
            <from>192.168.10.5</from>
            <to>192.168.10.14</to>
        </range>
        <defaultleasetime>7200</defaultleasetime>
        <maxleasetime>86400</maxleasetime>
        <gateway>192.168.10.1</gateway>
        <domain>mgmt.homelab.local</domain>
        <dnsserver>192.168.10.1</dnsserver>
    </mgmt>
</dhcp>
```

#### LAN VLAN DHCP
```xml
<dhcp>
    <lan>
        <enable>1</enable>
        <range>
            <from>192.168.20.100</from>
            <to>192.168.20.199</to>
        </range>
        <defaultleasetime>86400</defaultleasetime>
        <maxleasetime>604800</maxleasetime>
        <gateway>192.168.20.1</gateway>
        <domain>lan.homelab.local</domain>
        <dnsserver>192.168.20.1</dnsserver>
    </lan>
</dhcp>
```

### DNS Configuration

#### DNS Resolver Settings
```xml
<dnsresolver>
    <enable>1</enable>
    <port>53</port>
    <interface>mgmt,lan,dmz,guest</interface>
    <dnssec>1</dnssec>
    <forwarding>1</forwarding>
    <system_domain_local_zone_type>transparent</system_domain_local_zone_type>
</dnsresolver>
```

#### Custom DNS Entries
```
# Infrastructure hosts
pfsense.mgmt.homelab.local      192.168.10.1
microos.mgmt.homelab.local      192.168.10.2
elk.mgmt.homelab.local          192.168.10.3

# Service hosts
web.dmz.homelab.local           192.168.30.5
app.dmz.homelab.local           192.168.30.6
db.dmz.homelab.local            192.168.30.7
```

## Network Monitoring and Logging

### Traffic Analysis Points

```
┌─────────────────────────────────────────────────────────────┐
│                   Monitoring Architecture                   │
│                                                             │
│  Internet ←→ QHora-301W ←→ Cloud Gateway ←→ MicroOS Host   │
│                    │             │            │            │
│                    ▼             ▼            ▼            │
│               [Log Point 1] [Log Point 2] [Log Point 3]    │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │  pfSense VM     │  │   ELK Stack     │                 │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │                 │
│  │ │ Firewall    │ │  │ │ Logstash    │ │                 │
│  │ │ Logs        │─┼─►│ │ Processing  │ │                 │
│  │ └─────────────┘ │  │ └─────────────┘ │                 │
│  │ ┌─────────────┐ │  │ ┌─────────────┐ │                 │
│  │ │ Traffic     │ │  │ │Elasticsearch│ │                 │
│  │ │ Analysis    │ │  │ │   Storage   │ │                 │
│  │ └─────────────┘ │  │ └─────────────┘ │                 │
│  └─────────────────┘  │ ┌─────────────┐ │                 │
│                       │ │   Kibana    │ │                 │
│                       │ │ Dashboards  │ │                 │
│                       │ └─────────────┘ │                 │
│                       └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

### Monitoring Configuration

#### VLAN Traffic Monitoring
```bash
# pfSense VLAN monitoring
interface_stats="mgmt,lan,dmz,guest"
monitoring_interval="60"
retention_period="30d"

# Key metrics to track:
# - Bandwidth utilization per VLAN
# - Packet counts (in/out)
# - Error rates
# - Top talkers per VLAN
```

#### Security Event Monitoring
```bash
# Security events to monitor:
# - Failed authentication attempts
# - Port scan detection
# - Unusual traffic patterns
# - Inter-VLAN access attempts
# - Bandwidth anomalies
# - DNS query analysis
```

## Routing Configuration

### Static Routes

#### Cloud Gateway Ultra Routes
```bash
# Route management traffic to pfSense
ip route add 192.168.10.0/28 via 192.168.10.1

# Route LAN traffic to pfSense
ip route add 192.168.20.0/24 via 192.168.20.1

# Route DMZ traffic to pfSense  
ip route add 192.168.30.0/28 via 192.168.30.1

# Route guest traffic to pfSense
ip route add 192.168.40.0/26 via 192.168.40.1
```

### Policy-Based Routing

#### pfSense Gateway Configuration
```xml
<gateways>
    <gateway_item>
        <interface>wan</interface>
        <gateway>192.168.1.1</gateway>
        <name>WAN_GW</name>
        <weight>1</weight>
        <ipprotocol>inet</ipprotocol>
        <interval>1</interval>
        <descr>WAN Gateway</descr>
    </gateway_item>
</gateways>
```

## Network Troubleshooting

### Common Network Issues

#### VLAN Connectivity Problems
```bash
# Check VLAN configuration on host
ip link show | grep vlan

# Verify bridge VLAN filtering
bridge vlan show

# Test inter-VLAN communication
ping -I br0.10 192.168.20.1

# Check pfSense VLAN interfaces
pfctl -s interfaces
```

#### DHCP Issues
```bash
# Check DHCP leases on pfSense
dhcp-lease-list

# Monitor DHCP requests
tcpdump -i em1 port 67 or port 68

# Verify DHCP server status
service dhcpd status
```

#### DNS Resolution Problems
```bash
# Test DNS resolution from each VLAN
nslookup google.com 192.168.10.1
nslookup google.com 192.168.20.1

# Check DNS forwarder logs
tail -f /var/log/resolver.log

# Verify DNS configuration
pfctl -s rules | grep "port 53"
```

### Performance Optimization

#### VLAN Performance Tuning
```bash
# Optimize bridge performance
echo 0 > /sys/class/net/br0/bridge/multicast_snooping

# Tune network buffer sizes
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf

# Apply changes
sysctl -p
```

This network topology provides a secure, scalable foundation for the home lab environment with proper segmentation and monitoring capabilities.