# Installation Guide

This guide provides step-by-step instructions for deploying the pfSense + ELK Stack security monitoring solution.

## Prerequisites

### Hardware Requirements
- **Minimum**: 8GB RAM, 4 CPU cores, 50GB storage
- **Recommended**: 16GB RAM, 8 CPU cores, 100GB SSD storage
- **Network**: Static IP addresses for all components

### Software Requirements
- Ubuntu 20.04+ or CentOS 8+
- Docker 20.10+ with Docker Compose
- pfSense 2.7+ firewall
- Internet connectivity for Docker image downloads

## Installation Methods

### Method 1: Docker Deployment (Recommended)

#### Step 1: Clone Repository
```bash
git clone <repository-url>
cd home-lab/pfsense-elk-security
```

#### Step 2: Configure Environment
```bash
# Create environment file
cp .env.example .env

# Edit environment variables
nano .env
```

Required environment variables:
```bash
ELASTIC_PASSWORD=your_secure_password_here
ELK_SERVER_IP=192.168.1.100
PFSENSE_IP=192.168.1.1
ELASTIC_VERSION=8.11.0
```

#### Step 3: Deploy ELK Stack
```bash
# Start all services
docker-compose -f docker-compose/docker-compose.yml up -d

# Verify deployment
docker-compose -f docker-compose/docker-compose.yml ps
```

#### Step 4: Verify Services
```bash
# Check Elasticsearch
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check Kibana (wait 2-3 minutes for startup)
curl -X GET "localhost:5601/api/status"

# Check Logstash
docker logs logstash
```

### Method 2: Manual Installation

#### Step 1: Install Elasticsearch
```bash
# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Install Elasticsearch
sudo apt update
sudo apt install elasticsearch

# Configure Elasticsearch
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Elasticsearch configuration:
```yaml
cluster.name: pfsense-security
node.name: elasticsearch-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
```

#### Step 2: Install Logstash
```bash
# Install Logstash
sudo apt install logstash

# Copy configuration
sudo cp configs/logstash/conf.d/pfsense.conf /etc/logstash/conf.d/

# Configure Logstash
sudo nano /etc/logstash/logstash.yml
```

#### Step 3: Install Kibana
```bash
# Install Kibana
sudo apt install kibana

# Configure Kibana
sudo nano /etc/kibana/kibana.yml
```

Kibana configuration:
```yaml
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
```

#### Step 4: Start Services
```bash
# Enable and start services
sudo systemctl enable elasticsearch logstash kibana
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl start kibana

# Check service status
sudo systemctl status elasticsearch logstash kibana
```

## pfSense Configuration

### Step 1: Enable Remote Logging
1. Navigate to **System → Advanced → Logging**
2. Go to **Remote Logging** tab
3. Configure the following:
   - **Remote Syslog Server**: `<ELK_SERVER_IP>:514`
   - **Remote Log Contents**: Select **Everything**
   - **Source Address**: Select your LAN interface

### Step 2: Configure Firewall Rules
1. Navigate to **Firewall → Rules → LAN**
2. Create rule to allow traffic to ELK server:
   - **Action**: Pass
   - **Protocol**: UDP
   - **Source**: LAN net
   - **Destination**: ELK Server IP
   - **Destination Port**: 514

### Step 3: Enable Detailed Logging
1. Navigate to **Status → System Logs → Settings**
2. Enable:
   - **Log packets matched by the default block rule**
   - **Log packets matched by the default pass rule**
   - **Log packets blocked by interface rules**

## Post-Installation Setup

### Step 1: Import Kibana Dashboards
```bash
# Import index templates
curl -X PUT "localhost:9200/_index_template/pfsense-firewall" \
  -H "Content-Type: application/json" \
  -d @configs/elasticsearch/index-templates/pfsense-firewall.json

# Import Kibana objects (dashboards, visualizations)
curl -X POST "localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -F file=@configs/kibana/dashboards/pfsense-security-dashboards.ndjson
```

### Step 2: Configure Alerting
```bash
# Set up Watcher alerts
curl -X PUT "localhost:9200/_watcher/watch/brute-force-detection" \
  -H "Content-Type: application/json" \
  -d @scripts/alerts/watchers/brute-force-detection.json
```

### Step 3: Set up Health Monitoring
```bash
# Make health check script executable
chmod +x scripts/maintenance/elk-health.sh

# Add to crontab for regular health checks
echo "*/5 * * * * /path/to/scripts/maintenance/elk-health.sh" | crontab -
```

## Verification

### Test Log Flow
1. Generate test traffic on pfSense
2. Check Logstash logs: `docker logs logstash`
3. Verify data in Elasticsearch:
   ```bash
   curl -X GET "localhost:9200/pfsense-firewall-*/_search?pretty&size=1"
   ```
4. Access Kibana dashboard: http://localhost:5601

### Access Points
- **Kibana Dashboard**: http://localhost:5601
- **Elasticsearch API**: http://localhost:9200
- **Elasticsearch Health**: http://localhost:9200/_cluster/health

## Security Hardening

### Step 1: Enable Authentication
```bash
# Generate passwords for built-in users
docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
```

### Step 2: Configure TLS
```bash
# Generate certificates
docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil ca
docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
```

### Step 3: Firewall Configuration
- Restrict access to ports 9200, 5601, and 514 to authorized networks only
- Use VPN or private networks for administrative access

## Next Steps

1. Configure additional dashboards and visualizations
2. Set up automated alerting for security events
3. Implement log retention policies
4. Configure backups for Elasticsearch indices
5. Set up monitoring and alerting for the ELK stack itself

For troubleshooting common issues, see the [Troubleshooting Guide](troubleshooting.md).