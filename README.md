# 🏠 Complete Home Lab Deployment Suite

**One script to deploy your entire security monitoring infrastructure**

Deploy **openSUSE MicroOS + pfSense + ELK Stack + Attack Map Dashboard** with a single command.

## 🎯 **What This Deploys**

### **Complete Infrastructure Stack:**
- ✅ **openSUSE MicroOS** - Immutable, container-focused OS
- ✅ **ELK Stack** - Elasticsearch, Logstash, Kibana for log analysis
- ✅ **Attack Map Dashboard** - Real-time threat visualization
- ✅ **Monitoring Stack** - Prometheus, Grafana, Node Exporter
- ✅ **pfSense Integration** - Firewall log processing and visualization
- ✅ **Advanced Networking** - Optimized for high-throughput logging

### **42+ Packages Installed:**
```
Base System: curl, wget, git, vim, htop, btop, zip, unzip, rsync, tree, jq, yq
Network Tools: net-tools, bind-utils, tcpdump, nmap, iperf3
Containers: docker, docker-compose, podman, buildah, skopeo, kubernetes, helm
Monitoring: prometheus, grafana, node_exporter, logrotate, rsyslog, filebeat
Security: openssh-server, firewalld, fail2ban, clamav, rkhunter, nftables
```

## 🚀 **Quick Start**

### **Production Deployment:**
```bash
# Download the script
chmod +x complete-homelab-setup.sh

# Run as root (recommended)
sudo ./complete-homelab-setup.sh

# Choose option 11 for complete deployment
```

### **Testing:**
```bash
# Test without making changes
TEST_MODE=true FORCE_RUN=true ./complete-homelab-setup.sh
```

## 📋 **Menu Options**

### **📦 System Setup:**
1. **Install Base System Packages** - Essential tools and utilities
2. **Install Container Runtime** - Docker, Podman, Kubernetes tools
3. **Install Monitoring Tools** - Prometheus, Grafana, logging tools
4. **Install Security Tools** - Firewall, intrusion detection, scanning

### **🌐 Network Configuration:**
5. **Setup Advanced Firewall** - ELK, Attack Map, monitoring ports
6. **Configure Network Optimization** - High-throughput logging tuning

### **🔍 ELK Stack Deployment:**
7. **Deploy ELK Stack** - Complete logging infrastructure
8. **Setup pfSense Integration** - Firewall log processing

### **🗺️ Attack Map & Monitoring:**
9. **Deploy Attack Map Dashboard** - Real-time threat visualization
10. **Deploy Monitoring Stack** - System and service monitoring

### **🚀 Complete Deployment:**
11. **Deploy Everything** - Full automated setup

### **📊 Management:**
12. **Show System Status** - Health check and statistics
13. **Show Service URLs** - Access points for all services
14. **View Logs** - Installation and system logs
15. **Backup Configurations** - Export settings and configs

## 🌐 **Service Access URLs**

After deployment, access your services at:

| Service | URL | Credentials |
|---------|-----|-------------|
| **Kibana** (Log Analysis) | http://localhost:5601 | None |
| **Attack Map** | http://localhost:8080 | None |
| **Grafana** (Monitoring) | http://localhost:3000 | admin/admin123 |
| **Prometheus** | http://localhost:9090 | None |
| **Elasticsearch** | http://localhost:9200 | None |
| **pfSense** | https://192.168.1.1 | Manual config |

## 🔧 **Architecture Overview**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   pfSense       │    │  openSUSE       │    │   Attack Map    │
│   Firewall      │───▶│  MicroOS        │───▶│   Dashboard     │
│                 │    │                 │    │                 │
│ • Log Export    │    │ • ELK Stack     │    │ • Real-time     │
│ • Rule Logging  │    │ • Monitoring    │    │ • Geolocation   │
│ • Traffic Data  │    │ • Processing    │    │ • Visualization │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
                    ┌─────────────────┐
                    │   Monitoring    │
                    │   Stack         │
                    │                 │
                    │ • Grafana       │
                    │ • Prometheus    │
                    │ • Alerting      │
                    └─────────────────┘
```

## 📊 **ELK Stack Configuration**

### **Elasticsearch**
- Single-node cluster for home lab use
- 2GB heap size (configurable)
- Security disabled for internal use
- 30-day data retention

### **Logstash**
- pfSense log parsing with Grok patterns
- GeoIP enrichment for external IPs
- Firewall log classification
- UDP syslog input (port 5000)

### **Kibana**
- Pre-configured dashboards
- Index pattern: `homelab-logs-*`
- Visualization templates
- Search and filtering capabilities

### **Filebeat**
- System log collection
- Docker container log monitoring
- Automatic log shipping to Logstash

## 🗺️ **Attack Map Features**

### **Real-time Visualization**
- Live attack plotting on world map
- Geolocation of source IPs
- Attack statistics and trending
- Country-based threat analysis

### **Data Processing**
- Elasticsearch integration
- Redis caching for performance
- Python-based log processor
- Node.js web server

### **Interactive Dashboard**
- Socket.io for real-time updates
- Leaflet.js mapping
- Attack pulse animations
- Statistics sidebar

## 🛡️ **pfSense Integration**

### **Log Export Configuration**
```bash
# In pfSense web interface:
# 1. Status > System Logs > Settings
# 2. Enable Remote Logging
# 3. Set Remote Log Servers: <ELK-IP>:5000
# 4. Set Contents: Everything
```

### **Firewall Rules**
- Enable logging on block rules
- Configure geographic blocking
- Rate limiting for attack detection
- Custom rule descriptions

### **Backup Strategy**
- Automated configuration export
- Version control for configs
- Scheduled backup scripts
- Disaster recovery procedures

## 📈 **Monitoring Stack**

### **Prometheus Metrics**
- System resource monitoring
- Container performance tracking
- ELK Stack health monitoring
- Custom application metrics

### **Grafana Dashboards**
- System overview dashboard
- ELK Stack performance
- Attack statistics visualization
- Network traffic analysis

### **Alerting Rules**
- High CPU/memory usage
- Elasticsearch cluster health
- Failed authentication attempts
# Disk space warnings

## 🔧 **System Optimizations**

### **Network Tuning**
```bash
# TCP buffer sizes for high-throughput logging
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728

# BBR congestion control
net.ipv4.tcp_congestion_control = bbr

# Connection optimizations
net.ipv4.tcp_tw_reuse = 1
```

### **Memory Optimizations**
```bash
# Reduced swappiness for SSD
vm.swappiness = 1

# Elasticsearch memory mapping
vm.max_map_count = 262144

# Dirty page handling
vm.dirty_ratio = 15
```

### **File System Tuning**
```bash
# Increased file limits
fs.file-max = 2097152
fs.nr_open = 1048576
```

## 🔒 **Security Features**

### **Firewall Configuration**
- SSH access (port 22)
- ELK Stack ports (5601, 9200, 5044)
- Attack Map (8080)
- Monitoring (3000, 9090)
- Container port ranges

### **Service Hardening**
- SSH root login disabled
- Fail2ban intrusion prevention
- ClamAV antivirus scanning
- Rootkit detection

### **Log Security**
- Centralized logging
- Log rotation policies
- Secure log transport
- Access control lists

## 🔍 **Troubleshooting**

### **Common Issues**

#### **"Not running as root" Error**
```bash
# Run with sudo
sudo ./complete-homelab-setup.sh

# Check current user
whoami && id -u
```

#### **Docker Permission Issues**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart Docker service
sudo systemctl restart docker
```

#### **ELK Stack Memory Issues**
```bash
# Increase Elasticsearch heap
# Edit: /opt/homelab/elk/docker-compose.yml
# Change: ES_JAVA_OPTS=-Xms1g -Xmx1g
```

#### **pfSense Logs Not Appearing**
```bash
# Check Logstash logs
docker logs logstash

# Test connectivity
telnet <pfsense-ip> 5000

# Verify Elasticsearch indices
curl localhost:9200/_cat/indices
```

### **Log Locations**
- **Main log**: `/var/log/homelab-setup.log`
- **Docker logs**: `docker logs <container-name>`
- **Elasticsearch logs**: `docker logs elasticsearch`
- **System logs**: `/var/log/messages`

## 📁 **File Structure**

```
/opt/homelab/                    # Deployment directory
├── elk/                         # ELK Stack configuration
│   ├── docker-compose.yml
│   ├── elasticsearch/config/
│   ├── logstash/config/
│   ├── kibana/config/
│   └── filebeat/config/
├── attack-map/                  # Attack Map components
│   ├── docker-compose.yml
│   ├── server/                  # Node.js server
│   └── processor/               # Python log processor
├── monitoring/                  # Prometheus & Grafana
│   ├── docker-compose.yml
│   ├── prometheus/config/
│   └── grafana/provisioning/
├── pfsense/                     # pfSense integration
│   ├── pfsense-config.md
│   └── backup-pfsense.sh
└── backups/                     # Configuration backups
    └── YYYYMMDD_HHMMSS/
```

## 🔄 **Maintenance**

### **Regular Tasks**
```bash
# Update containers
cd /opt/homelab && docker-compose pull && docker-compose up -d

# Backup configurations
./complete-homelab-setup.sh  # Choose option 15

# Check system health
./complete-homelab-setup.sh  # Choose option 12

# View recent logs
./complete-homelab-setup.sh  # Choose option 14
```

### **Performance Monitoring**
- Monitor disk usage for log retention
- Check Elasticsearch cluster health
- Review firewall rule efficiency
- Analyze attack patterns and trends

## 🎯 **Use Cases**

### **Home Lab Security**
- Network traffic monitoring
- Intrusion detection and analysis
- Security event correlation
- Threat intelligence gathering

### **SOC Training**
- Real-world log analysis practice
- SIEM-like functionality
- Incident response training
- Security visualization skills

### **Network Analysis**
- Traffic pattern analysis
- Bandwidth utilization monitoring
- Application performance tracking
- Network troubleshooting

## 🚀 **Advanced Features**

### **Custom Dashboards**
- Import Grafana dashboard templates
- Create custom Kibana visualizations  
- Build attack correlation rules
- Set up automated reporting

### **Integration Options**
- MISP threat intelligence
- OSINT data feeds
- Custom log sources
- API integrations

### **Scaling Options**
- Multi-node Elasticsearch cluster
- Load balancing with HAProxy
- Distributed log processing
- Cloud deployment options

## 🤝 **Contributing**

This is a complete, production-ready home lab deployment script. Feel free to:
- Customize for your environment
- Add additional services
- Improve security configurations
- Share your modifications

## 📜 **License**

Open source - use and modify as needed for your home lab setup.

---

**🎉 Deploy your complete security monitoring infrastructure in minutes!**

**Run as root • Test safely • Monitor everything • Visualize threats**