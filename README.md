# Secure Home Lab with pfSense + ELK Stack Security Monitoring

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)
[![ELK Stack](https://img.shields.io/badge/ELK-8.11.0-orange.svg)](https://www.elastic.co/)
[![pfSense](https://img.shields.io/badge/pfSense-2.7+-red.svg)](https://www.pfsense.org/)
[![openSUSE MicroOS](https://img.shields.io/badge/openSUSE-MicroOS-73ba25.svg)](https://microos.opensuse.org/)

A comprehensive secure home lab environment using openSUSE MicroOS as an immutable host OS, running pfSense VM for network segmentation, and ELK Stack for real-time security monitoring and threat detection.

## 🚀 Features

### Infrastructure Components
- **Immutable Host OS**: openSUSE MicroOS with transactional updates
- **Virtualized Firewall**: pfSense VM with VLAN-based network segmentation
- **Security Monitoring**: ELK Stack for real-time threat detection and visualization
- **Network Isolation**: VLAN trunking with isolated management, LAN, and DMZ networks

### Security Capabilities
- **Real-time Attack Map**: Global threat visualization with geographic correlation
- **Advanced Security Monitoring**: Brute force, port scan, and DDoS detection
- **Machine Learning**: Anomaly detection for unusual traffic patterns
- **Automated Alerting**: Slack/email notifications for critical events
- **Network Segmentation**: Inter-VM traffic control and isolation
- **Hardened Infrastructure**: SELinux/AppArmor policies and secure access controls

## 📁 Project Structure

```
home-lab/
├── host-os/                      # openSUSE MicroOS host configuration
│   ├── installation/             # Host OS installation guides
│   ├── networking/               # VLAN and bridge configuration
│   └── hardening/               # Security hardening scripts
├── pfsense-vm/                   # pfSense virtual machine setup
│   ├── installation/             # VM installation and configuration
│   ├── configs/                  # pfSense configuration templates
│   └── firewall-rules/          # VLAN firewall rules and policies
├── pfsense-elk-security/         # ELK Stack security monitoring
│   ├── configs/                  # Configuration files for ELK components
│   ├── docker-compose/           # Container deployment
│   ├── scripts/                  # Installation and maintenance automation
│   └── docs/                     # ELK-specific documentation
├── network/                      # Network topology and design
│   ├── topology/                 # Network diagrams and documentation
│   ├── vlans/                    # VLAN configuration scripts
│   └── monitoring/               # Network monitoring tools
└── docs/                         # Comprehensive guides and documentation
```

## 📋 Prerequisites

### Hardware Requirements
- **Minimum**: 16GB RAM, 8 CPU cores, 200GB SSD storage
- **Recommended**: 32GB RAM, 12+ CPU cores, 500GB NVMe SSD
- **Virtualization**: Intel VT-x/AMD-V support enabled in BIOS
- **Network**: Single physical NIC capable of VLAN trunking

### Network Infrastructure
- **Primary Router**: QNAP QHora-301W (WAN/Internet gateway)
- **Intermediate Router**: Cloud Gateway Ultra (NAT/VLAN management)
- **VLAN Support**: 802.1Q VLAN tagging capability
- **Management Access**: Dedicated management VLAN recommended

### Software Components
- **Host OS**: openSUSE MicroOS (immutable Linux distribution)
- **Virtualization**: KVM/QEMU with libvirt management
- **Firewall**: pfSense 2.7+ virtual machine
- **Monitoring**: ELK Stack 8.11+ (containerized)
- **Container Runtime**: Podman for additional services

## 🎯 Quick Start

### Phase 1: Host OS Installation
1. **Install openSUSE MicroOS**: Follow the [MicroOS Installation Guide](docs/micros-installation.md)
2. **Configure Host Networking**: Set up VLAN trunking and bridges
3. **Enable Virtualization**: Install KVM/QEMU with libvirt management

### Phase 2: pfSense VM Deployment
1. **Create pfSense VM**: Follow the [pfSense VM Setup Guide](pfsense-vm/installation/vm-setup.md)
2. **Configure VLANs**: Set up network segmentation and firewall rules
3. **Enable Remote Logging**: Configure syslog forwarding to ELK Stack

### Phase 3: Security Monitoring (ELK Stack)
```bash
# Clone the repository
git clone <repository-url>
cd home-lab/pfsense-elk-security

# Deploy ELK Stack
docker-compose -f docker-compose/docker-compose.yml up -d

# Verify deployment
docker-compose -f docker-compose/docker-compose.yml ps
```

### Phase 4: Security Hardening
1. **Apply Host Hardening**: Follow the [Security Hardening Guide](docs/security-hardening.md)
2. **Configure Access Controls**: Set up SSH keys and management VLAN access
3. **Enable Monitoring**: Deploy health checks and automated backups

### Access Points
- **pfSense WebGUI**: https://pfsense-mgmt-ip:443
- **Kibana Dashboard**: http://elk-host:5601
- **Host Management**: SSH to management VLAN IP

## 🔧 System Architecture

### Network Topology
```
Internet
    ↓
QNAP QHora-301W (WAN Router)
    ↓
Cloud Gateway Ultra (NAT/VLAN Router)
    ↓ (VLAN Trunk)
openSUSE MicroOS Host (br0 bridge)
    ↓
pfSense VM (Virtual Firewall)
    ├── VLAN 10 (Management)
    ├── VLAN 20 (LAN/Workstations)  
    ├── VLAN 30 (DMZ/Services)
    └── VLAN 40 (Guest Network)
```

### Data Flow Architecture
```
Network Traffic → pfSense Firewall → Syslog (UDP:514)
                      ↓
ELK Stack Processing → Logstash → Elasticsearch → Kibana
                      ↓
Security Analysis & Real-time Attack Map
```

### Virtual Machine Architecture
```
Physical Host (openSUSE MicroOS)
├── pfSense VM (Network Firewall)
├── ELK Stack (Containerized Security Monitoring)
├── Additional VMs (Isolated by VLAN)
└── Host Services (Podman Containers)
```

## 📊 Dashboards

- **Attack Map**: Real-time global threat visualization
- **Security Overview**: Summary of security events and trends
- **Threat Intelligence**: Analysis of attack patterns and sources

## 📸 Screenshots

> 🖼️ **Demo Screenshots Coming Soon**
> 
> Screenshots of the attack map, security dashboards, and alerting system will be added once the environment is deployed.

## 🚨 Alerting

- Brute force attack detection
- Port scanning identification
- DDoS attack monitoring
- Geographic anomaly detection
- Multi-stage attack correlation

## ⚙️ Configuration Examples

### pfSense Logging Setup
```bash
# Enable remote logging in pfSense
System → Advanced → Logging → Remote Logging
Remote Syslog Server: <ELK_SERVER_IP>:514
Remote Log Contents: Everything
```

### Logstash Pipeline Preview
```ruby
# Sample Logstash configuration for pfSense logs
input {
  udp {
    port => 514
    type => "syslog"
  }
}

filter {
  if [program] == "filterlog" {
    grok {
      match => {
        "message_body" => "%{INT:rule_number},%{WORD:action},%{IPV4:src_ip},%{IPV4:dest_ip},%{INT:src_port},%{INT:dest_port}"
      }
    }
    
    # GeoIP enrichment
    geoip {
      source => "src_ip"
      target => "src_geo"
    }
  }
}
```

### Environment Variables
```bash
# Required environment variables
ELASTIC_PASSWORD=your_secure_password
ELK_SERVER_IP=192.168.1.100
PFSENSE_IP=192.168.1.1
```

## 🔧 Performance & System Requirements

### Host System Requirements
- **RAM**: 16GB minimum (32GB recommended)
  - Host OS: 2GB
  - pfSense VM: 2GB
  - ELK Stack: 8GB (4GB Elasticsearch, 2GB Logstash, 1GB Kibana)
  - Additional VMs: 4GB+
- **CPU**: 8 cores minimum (12+ cores recommended)
- **Storage**: 200GB minimum NVMe SSD (500GB recommended)
- **Network**: Gigabit NIC with VLAN support

### VLAN Allocation Guidelines
```
VLAN 10 (Management): /28 (14 hosts) - Critical infrastructure
VLAN 20 (LAN):        /24 (254 hosts) - Workstations and trusted devices  
VLAN 30 (DMZ):        /28 (14 hosts) - Public-facing services
VLAN 40 (Guest):      /26 (62 hosts) - Guest and IoT devices
```

### Resource Allocation per Component
```
Component          CPU    RAM    Storage    Network
openSUSE MicroOS   2      2GB    20GB       VLAN trunk
pfSense VM         2      2GB    8GB        Multi-VLAN
ELK Stack          4      8GB    100GB      Management VLAN
Additional VMs     2+     2GB+   20GB+      Per VLAN
```

## 📚 Documentation

### Infrastructure Setup
- [openSUSE MicroOS Installation Guide](docs/micros-installation.md)
- [Network Topology and VLAN Configuration](docs/network-topology.md)
- [pfSense VM Setup and Configuration](pfsense-vm/installation/vm-setup.md)
- [Security Hardening Guide](docs/security-hardening.md)

### ELK Stack Security Monitoring
- [ELK Stack Installation Guide](pfsense-elk-security/docs/installation-guide.md)
- [Architecture Overview](pfsense-elk-security/docs/architecture.md)
- [Troubleshooting Guide](pfsense-elk-security/docs/troubleshooting.md)

### Maintenance and Operations
- [System Maintenance Procedures](docs/maintenance.md)
- [Backup and Recovery Guide](docs/backup-recovery.md)
- [Performance Optimization](docs/performance-tuning.md)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

MIT License - see LICENSE file for details
