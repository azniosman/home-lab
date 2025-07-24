# pfSense + ELK Stack Security Monitoring Lab

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)
[![ELK Stack](https://img.shields.io/badge/ELK-8.11.0-orange.svg)](https://www.elastic.co/)
[![pfSense](https://img.shields.io/badge/pfSense-2.7+-red.svg)](https://www.pfsense.org/)

A comprehensive security monitoring solution combining pfSense firewall with Elasticsearch, Logstash, and Kibana (ELK Stack) for real-time threat detection and visualization.

## 🚀 Features

- **Real-time Attack Map**: Global threat visualization with geographic correlation
- **Advanced Security Monitoring**: Brute force, port scan, and DDoS detection
- **Machine Learning**: Anomaly detection for unusual traffic patterns
- **Automated Alerting**: Slack/email notifications for critical events
- **Scalable Architecture**: Optimized for high-volume log processing

## 📁 Project Structure

- `docs/` - Comprehensive documentation and guides
- `configs/` - Configuration files for all components
- `scripts/` - Installation and maintenance automation
- `vm-configs/` - Virtual machine definitions
- `docker-compose/` - Container deployment option

## 📋 Prerequisites

- **Hardware**: Minimum 8GB RAM, 4 CPU cores, 50GB storage
- **Operating System**: Ubuntu 20.04+ or CentOS 8+
- **Docker**: Version 20.10+ with Docker Compose
- **pfSense**: Version 2.7+ with remote logging enabled
- **Network**: Static IP addresses for all components

## 🎯 Quick Start

### Option 1: Docker Deployment (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd home-lab/pfsense-elk-security

# Start the ELK stack
docker-compose -f docker-compose/docker-compose.yml up -d

# Verify services are running
docker-compose -f docker-compose/docker-compose.yml ps
```

### Option 2: Manual Installation
1. Follow the [Installation Guide](docs/installation-guide.md)
2. Configure pfSense logging using configs in `configs/pfsense/`
3. Deploy ELK Stack with `scripts/install/install-elk.sh`
4. Import Kibana dashboards from `configs/kibana/dashboards/`
5. Set up monitoring with scripts in `scripts/maintenance/`

### Access Points
- **Kibana Dashboard**: http://localhost:5601
- **Elasticsearch API**: http://localhost:9200
- **Logstash**: Listening on UDP 514 for syslog

## 🔧 Architecture

Internet → pfSense VM → Logstash → Elasticsearch → Kibana
↓
Security Analysis & Attack Map

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

### Minimum Requirements
- **RAM**: 8GB (4GB for Elasticsearch, 2GB for Logstash, 1GB for Kibana)
- **CPU**: 4 cores minimum, 8 cores recommended
- **Storage**: 50GB minimum, SSD recommended for optimal performance
- **Network**: 1Gbps for high-volume log processing

### Scaling Recommendations
- **Log Volume**: <10GB/day - Single node sufficient
- **Log Volume**: 10-50GB/day - Consider Elasticsearch cluster
- **Log Volume**: >50GB/day - Multi-node cluster with dedicated roles

### Performance Tuning
```yaml
# Elasticsearch heap size (50% of available RAM, max 32GB)
ES_JAVA_OPTS: "-Xms4g -Xmx4g"

# Logstash processing threads
pipeline.workers: 4
pipeline.batch.size: 1000
```

## 📚 Documentation

- [Installation Guide](docs/installation-guide.md)
- [Architecture Overview](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

MIT License - see LICENSE file for details
