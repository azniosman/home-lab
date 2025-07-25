#!/bin/bash

#######################################################################
# Complete Home Lab Setup Script
# 
# Deploys: openSUSE MicroOS + pfSense + ELK Stack + Attack Map Dashboard
# Author: Home Lab Automation
# Run as: root
#######################################################################

set -e

# Configuration
SCRIPT_NAME="$(basename "$0")"
if [[ $(id -u) -eq 0 ]]; then
    LOG_FILE="/var/log/homelab-setup.log"
    COMPOSE_DIR="/opt/homelab"
else
    LOG_FILE="$HOME/homelab-setup.log"
    COMPOSE_DIR="$HOME/homelab"
fi

PACKAGES_INSTALLED=()
FAILED_OPERATIONS=()
SERVICES_DEPLOYED=()

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

#######################################################################
# Core Functions
#######################################################################

print_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    case "$level" in
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "INFO")  echo -e "${BLUE}[INFO]${NC} $message" ;;
        "SUCCESS") echo -e "${GREEN}[SUCCESS]${NC} $message" ;;
        "DEPLOY") echo -e "${PURPLE}[DEPLOY]${NC} $message" ;;
        "NETWORK") echo -e "${CYAN}[NETWORK]${NC} $message" ;;
        *) echo "[$level] $message" ;;
    esac
}

check_root() {
    if [[ $(id -u) -ne 0 ]]; then
        if [[ "${TEST_MODE:-}" == "true" ]]; then
            print_message "WARN" "Not running as root, but TEST_MODE enabled"
            return 0
        fi
        print_message "ERROR" "This script must be run as root"
        print_message "INFO" "Run with: sudo $0"
        print_message "INFO" "For testing: TEST_MODE=true $0"
        exit 1
    fi
    print_message "SUCCESS" "Running as root"
}

check_system() {
    if [[ -f /etc/os-release ]] && grep -q "MicroOS" /etc/os-release; then
        local version=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
        print_message "SUCCESS" "Detected openSUSE MicroOS version: $version"
        return 0
    elif [[ "${FORCE_RUN:-}" == "true" ]]; then
        print_message "WARN" "Not MicroOS but FORCE_RUN is set - continuing"
        return 0
    else
        print_message "ERROR" "This script is designed for openSUSE MicroOS"
        print_message "INFO" "To run anyway: FORCE_RUN=true $0"
        exit 1
    fi
}

detect_variant() {
    if command -v pkcon >/dev/null 2>&1; then
        VARIANT="desktop"
        print_message "INFO" "Detected Desktop variant (pkcon available)"
    elif command -v transactional-update >/dev/null 2>&1; then
        VARIANT="server"
        print_message "INFO" "Detected Server variant (transactional-update)"
    else
        VARIANT="server"
        print_message "WARN" "Cannot detect variant, assuming server"
    fi
}

#######################################################################
# Package Management
#######################################################################

install_package() {
    local package="$1"
    local description="${2:-$package}"
    
    print_message "INFO" "Installing $description..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        PACKAGES_INSTALLED+=("$package")
        print_message "SUCCESS" "TEST: Would install $description"
        return 0
    fi
    
    if [[ "$VARIANT" == "desktop" ]]; then
        if pkcon install -y "$package" >/dev/null 2>&1; then
            PACKAGES_INSTALLED+=("$package")
            print_message "SUCCESS" "Installed $description"
            return 0
        fi
    else
        if transactional-update pkg install -y "$package" >/dev/null 2>&1; then
            PACKAGES_INSTALLED+=("$package")
            print_message "SUCCESS" "Installed $description (reboot needed)"
            return 0
        fi
    fi
    
    FAILED_OPERATIONS+=("Install $description")
    print_message "ERROR" "Failed to install $description"
    return 1
}

#######################################################################
# Base System Setup
#######################################################################

install_base_system() {
    print_message "INFO" "Installing base system packages..."
    
    local packages=(
        "curl"
        "wget" 
        "git"
        "vim"
        "nano"
        "htop"
        "btop"
        "zip"
        "unzip"
        "rsync"
        "tree"
        "jq"
        "yq"
        "net-tools"
        "bind-utils"
        "tcpdump"
        "nmap"
        "iperf3"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

install_container_runtime() {
    print_message "INFO" "Installing container runtime and orchestration..."
    
    local packages=(
        "docker"
        "docker-compose"
        "podman"
        "buildah"
        "skopeo"
        "kubernetes1.28-client"
        "helm"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
    
    # Configure Docker
    if [[ "${TEST_MODE:-}" != "true" ]] && command -v docker >/dev/null 2>&1; then
        systemctl enable --now docker >/dev/null 2>&1 || true
        usermod -aG docker root >/dev/null 2>&1 || true
        print_message "SUCCESS" "Docker service configured"
    fi
}

install_monitoring_tools() {
    print_message "INFO" "Installing monitoring and logging tools..."
    
    local packages=(
        "prometheus"
        "grafana"
        "node_exporter"
        "logrotate"
        "rsyslog"
        "filebeat"
        "metricbeat"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

install_security_tools() {
    print_message "INFO" "Installing security and network tools..."
    
    local packages=(
        "openssh-server"
        "firewalld"
        "fail2ban"
        "clamav"
        "rkhunter"
        "chkrootkit"
        "nftables"
        "iptables"
        "wireshark"
        "tshark"
    )
    
    for pkg in "${packages[@]}"; do
        install_package "$pkg" || true
    done
}

#######################################################################
# Network Configuration
#######################################################################

setup_advanced_firewall() {
    print_message "NETWORK" "Configuring advanced firewall rules..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would setup advanced firewall"
        return 0
    fi
    
    # Enable firewalld
    systemctl enable --now firewalld >/dev/null 2>&1 || true
    
    # Base services
    firewall-cmd --permanent --add-service=ssh >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=http >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
    
    # ELK Stack ports
    firewall-cmd --permanent --add-port=5601/tcp >/dev/null 2>&1 || true  # Kibana
    firewall-cmd --permanent --add-port=9200/tcp >/dev/null 2>&1 || true  # Elasticsearch
    firewall-cmd --permanent --add-port=9300/tcp >/dev/null 2>&1 || true  # Elasticsearch cluster
    firewall-cmd --permanent --add-port=5044/tcp >/dev/null 2>&1 || true  # Logstash Beats
    firewall-cmd --permanent --add-port=9600/tcp >/dev/null 2>&1 || true  # Logstash monitoring
    
    # Attack Map Dashboard
    firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true  # Grafana
    firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true  # Attack Map
    
    # pfSense management (if running on same host)
    firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true  # pfSense web GUI
    
    # Docker/Container ports range
    firewall-cmd --permanent --add-port=8000-8999/tcp >/dev/null 2>&1 || true
    
    # Monitoring ports
    firewall-cmd --permanent --add-port=9090/tcp >/dev/null 2>&1 || true  # Prometheus
    firewall-cmd --permanent --add-port=9100/tcp >/dev/null 2>&1 || true  # Node Exporter
    
    firewall-cmd --reload >/dev/null 2>&1 || true
    print_message "SUCCESS" "Advanced firewall configured"
}

configure_network_optimization() {
    print_message "NETWORK" "Applying network optimizations..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would optimize network"
        return 0
    fi
    
    # Network optimizations for high-throughput logging
    cat >> /etc/sysctl.conf << 'EOF'
# Network optimizations for ELK Stack and high-throughput logging
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1

# Memory optimizations for large datasets
vm.swappiness = 1
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
vm.max_map_count = 262144

# File system optimizations
fs.file-max = 2097152
fs.nr_open = 1048576
EOF
    
    sysctl -p >/dev/null 2>&1 || true
    print_message "SUCCESS" "Network and system optimizations applied"
}

#######################################################################
# ELK Stack Deployment
#######################################################################

deploy_elk_stack() {
    print_message "DEPLOY" "Deploying ELK Stack (Elasticsearch, Logstash, Kibana)..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        SERVICES_DEPLOYED+=("ELK Stack")
        print_message "SUCCESS" "TEST: Would deploy ELK Stack"
        return 0
    fi
    
    mkdir -p "$COMPOSE_DIR/elk"
    
    # Create ELK Stack docker-compose.yml
    cat > "$COMPOSE_DIR/elk/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: elasticsearch
    environment:
      - node.name=elasticsearch
      - cluster.name=homelab-elk
      - discovery.type=single-node
      - bootstrap.memory_lock=true
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - xpack.security.enabled=false
      - xpack.security.http.ssl.enabled=false
      - xpack.security.transport.ssl.enabled=false
    ulimits:
      memlock:
        soft: -1
        hard: -1
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data
      - ./elasticsearch/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro
    ports:
      - "9200:9200"
      - "9300:9300"
    networks:
      - elk-network
    restart: unless-stopped

  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    container_name: logstash
    volumes:
      - ./logstash/config/logstash.yml:/usr/share/logstash/config/logstash.yml:ro
      - ./logstash/pipeline:/usr/share/logstash/pipeline:ro
    ports:
      - "5044:5044"
      - "5000:5000/tcp"
      - "5000:5000/udp"
      - "9600:9600"
    environment:
      - "LS_JAVA_OPTS=-Xmx1g -Xms1g"
    networks:
      - elk-network
    depends_on:
      - elasticsearch
    restart: unless-stopped

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: kibana
    volumes:
      - ./kibana/config/kibana.yml:/usr/share/kibana/config/kibana.yml:ro
    ports:
      - "5601:5601"
    networks:
      - elk-network
    depends_on:
      - elasticsearch
    restart: unless-stopped

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.0
    container_name: filebeat
    user: root
    volumes:
      - ./filebeat/config/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - filebeat_data:/usr/share/filebeat/data
    networks:
      - elk-network
    depends_on:
      - logstash
    restart: unless-stopped

volumes:
  elasticsearch_data:
  filebeat_data:

networks:
  elk-network:
    driver: bridge
EOF

    # Create Elasticsearch config
    mkdir -p "$COMPOSE_DIR/elk/elasticsearch/config"
    cat > "$COMPOSE_DIR/elk/elasticsearch/config/elasticsearch.yml" << 'EOF'
cluster.name: homelab-elk
node.name: elasticsearch
network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.monitoring.collection.enabled: true
EOF

    # Create Logstash config
    mkdir -p "$COMPOSE_DIR/elk/logstash/config" "$COMPOSE_DIR/elk/logstash/pipeline"
    cat > "$COMPOSE_DIR/elk/logstash/config/logstash.yml" << 'EOF'
http.host: "0.0.0.0"
xpack.monitoring.elasticsearch.hosts: ["http://elasticsearch:9200"]
EOF

    # Create Logstash pipeline for pfSense logs
    cat > "$COMPOSE_DIR/elk/logstash/pipeline/pfsense.conf" << 'EOF'
input {
  udp {
    port => 5000
    type => "pfsense"
  }
  beats {
    port => 5044
  }
}

filter {
  if [type] == "pfsense" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{WORD:program}: %{GREEDYDATA:message}" }
    }
    
    if [program] == "filterlog" {
      grok {
        match => { "message" => "%{INT:rule_number},%{INT:sub_rule_number},%{WORD:anchor},%{INT:tracker},%{WORD:interface},%{WORD:reason},%{WORD:action},%{WORD:direction},%{INT:ip_version},%{GREEDYDATA:details}" }
      }
      
      if [ip_version] == "4" {
        grok {
          match => { "details" => "%{IPV4:src_ip},%{IPV4:dst_ip},%{INT:src_port},%{INT:dst_port},%{WORD:protocol}" }
        }
      }
      
      mutate {
        add_field => { "log_type" => "firewall" }
      }
    }
    
    date {
      match => [ "timestamp", "MMM dd HH:mm:ss" ]
    }
  }
  
  # GeoIP lookup for external IPs
  if [src_ip] and [src_ip] !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ {
    geoip {
      source => "src_ip"
      target => "src_geoip"
    }
  }
  
  if [dst_ip] and [dst_ip] !~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ {
    geoip {
      source => "dst_ip"
      target => "dst_geoip"
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "homelab-logs-%{+YYYY.MM.dd}"
  }
}
EOF

    # Create Kibana config
    mkdir -p "$COMPOSE_DIR/elk/kibana/config"
    cat > "$COMPOSE_DIR/elk/kibana/config/kibana.yml" << 'EOF'
server.host: 0.0.0.0
server.port: 5601
elasticsearch.hosts: ["http://elasticsearch:9200"]
logging.appenders.file.fileName: /var/log/kibana.log
EOF

    # Create Filebeat config
    mkdir -p "$COMPOSE_DIR/elk/filebeat/config"
    cat > "$COMPOSE_DIR/elk/filebeat/config/filebeat.yml" << 'EOF'
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/messages
    - /var/log/secure
  fields:
    log_type: system
    
- type: container
  enabled: true
  paths:
    - '/var/lib/docker/containers/*/*.log'
  fields:
    log_type: docker

output.logstash:
  hosts: ["logstash:5044"]

processors:
- add_host_metadata:
    when.not.contains.tags: forwarded
- add_docker_metadata: ~
EOF

    cd "$COMPOSE_DIR/elk"
    docker-compose up -d >/dev/null 2>&1 || true
    
    SERVICES_DEPLOYED+=("ELK Stack")
    print_message "SUCCESS" "ELK Stack deployed"
    print_message "INFO" "Kibana available at: http://localhost:5601"
    print_message "INFO" "Elasticsearch available at: http://localhost:9200"
}

#######################################################################
# Attack Map Dashboard
#######################################################################

deploy_attack_map() {
    print_message "DEPLOY" "Deploying Attack Map Dashboard..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        SERVICES_DEPLOYED+=("Attack Map Dashboard")
        print_message "SUCCESS" "TEST: Would deploy Attack Map Dashboard"
        return 0
    fi
    
    mkdir -p "$COMPOSE_DIR/attack-map"
    
    # Create Attack Map docker-compose.yml
    cat > "$COMPOSE_DIR/attack-map/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: attack-map-redis
    restart: unless-stopped
    networks:
      - attack-map-network

  attack-map-server:
    image: node:18-alpine
    container_name: attack-map-server
    working_dir: /app
    volumes:
      - ./server:/app
    ports:
      - "8080:8080"
    environment:
      - NODE_ENV=production
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - redis
    networks:
      - attack-map-network
    restart: unless-stopped
    command: sh -c "npm install && npm start"

  log-processor:
    image: python:3.11-alpine
    container_name: attack-map-processor
    working_dir: /app
    volumes:
      - ./processor:/app
    environment:
      - ELASTICSEARCH_HOST=elasticsearch
      - ELASTICSEARCH_PORT=9200
      - REDIS_HOST=redis
      - REDIS_PORT=6379
    depends_on:
      - redis
    networks:
      - attack-map-network
      - elk_elk-network
    restart: unless-stopped
    command: sh -c "pip install -r requirements.txt && python processor.py"

networks:
  attack-map-network:
    driver: bridge
  elk_elk-network:
    external: true
EOF

    # Create attack map server
    mkdir -p "$COMPOSE_DIR/attack-map/server"
    cat > "$COMPOSE_DIR/attack-map/server/package.json" << 'EOF'
{
  "name": "attack-map-server",
  "version": "1.0.0",
  "description": "Real-time attack map server",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.2",
    "redis": "^4.6.7",
    "geoip-lite": "^1.4.7"
  }
}
EOF

    cat > "$COMPOSE_DIR/attack-map/server/server.js" << 'EOF'
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const redis = require('redis');
const geoip = require('geoip-lite');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Redis client
const client = redis.createClient({
  host: process.env.REDIS_HOST || 'redis',
  port: process.env.REDIS_PORT || 6379
});

client.connect();

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Main route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.io connection handling
io.on('connection', (socket) => {
  console.log('Client connected');
  
  // Send initial data
  sendRecentAttacks(socket);
  
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// Function to send recent attacks
async function sendRecentAttacks(socket) {
  try {
    const attacks = await client.lRange('recent_attacks', 0, 99);
    const parsedAttacks = attacks.map(attack => JSON.parse(attack));
    socket.emit('attacks', parsedAttacks);
  } catch (error) {
    console.error('Error fetching attacks:', error);
  }
}

// Listen for new attacks from Redis
async function listenForAttacks() {
  const subscriber = client.duplicate();
  await subscriber.connect();
  
  subscriber.subscribe('new_attack', (message) => {
    const attack = JSON.parse(message);
    io.emit('new_attack', attack);
  });
}

listenForAttacks();

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`Attack Map Server running on port ${PORT}`);
});
EOF

    # Create web interface
    mkdir -p "$COMPOSE_DIR/attack-map/server/public"
    cat > "$COMPOSE_DIR/attack-map/server/public/index.html" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home Lab Attack Map</title>
    <script src="https://cdn.socket.io/4.7.2/socket.io.min.js"></script>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        body { margin: 0; font-family: Arial, sans-serif; background: #000; color: #0f0; }
        #header { padding: 20px; text-align: center; background: #111; }
        #map { height: 80vh; }
        #stats { position: absolute; top: 100px; right: 20px; background: rgba(0,0,0,0.8); padding: 15px; border-radius: 5px; z-index: 1000; }
        .attack-pulse { animation: pulse 2s ease-out; }
        @keyframes pulse { 0% { transform: scale(1); opacity: 1; } 100% { transform: scale(3); opacity: 0; } }
        .stat-item { margin: 5px 0; }
    </style>
</head>
<body>
    <div id="header">
        <h1>🛡️ Home Lab Security Monitor</h1>
        <p>Real-time Attack Visualization</p>
    </div>
    
    <div id="stats">
        <div class="stat-item">Total Attacks: <span id="total-attacks">0</span></div>
        <div class="stat-item">Last Hour: <span id="hourly-attacks">0</span></div>
        <div class="stat-item">Top Country: <span id="top-country">-</span></div>
        <div class="stat-item">Active: <span id="status">🟢 Online</span></div>
    </div>
    
    <div id="map"></div>

    <script>
        // Initialize map
        const map = L.map('map').setView([20, 0], 2);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(map);

        // Socket connection
        const socket = io();
        
        let totalAttacks = 0;
        let hourlyAttacks = 0;
        let countryStats = {};
        
        // Handle new attacks
        socket.on('new_attack', (attack) => {
            if (attack.src_lat && attack.src_lon) {
                // Add attack marker
                const marker = L.circleMarker([attack.src_lat, attack.src_lon], {
                    color: '#ff0000',
                    fillColor: '#ff0000',
                    fillOpacity: 0.8,
                    radius: 5,
                    className: 'attack-pulse'
                }).addTo(map);
                
                // Show popup
                marker.bindPopup(`
                    <b>Attack Detected!</b><br>
                    Source: ${attack.src_ip}<br>
                    Country: ${attack.src_country || 'Unknown'}<br>
                    Target: ${attack.dst_ip}:${attack.dst_port}<br>
                    Protocol: ${attack.protocol}<br>
                    Time: ${new Date(attack.timestamp).toLocaleString()}
                `).openPopup();
                
                // Remove marker after 10 seconds
                setTimeout(() => {
                    map.removeLayer(marker);
                }, 10000);
                
                // Update stats
                updateStats(attack);
            }
        });
        
        // Handle initial attacks data
        socket.on('attacks', (attacks) => {
            attacks.forEach(attack => {
                if (attack.src_lat && attack.src_lon) {
                    updateStats(attack);
                }
            });
        });
        
        function updateStats(attack) {
            totalAttacks++;
            hourlyAttacks++;
            
            // Count by country
            const country = attack.src_country || 'Unknown';
            countryStats[country] = (countryStats[country] || 0) + 1;
            
            // Update display
            document.getElementById('total-attacks').textContent = totalAttacks;
            document.getElementById('hourly-attacks').textContent = hourlyAttacks;
            
            // Find top country
            const topCountry = Object.keys(countryStats).reduce((a, b) => 
                countryStats[a] > countryStats[b] ? a : b
            );
            document.getElementById('top-country').textContent = topCountry;
        }
        
        // Reset hourly stats every hour
        setInterval(() => {
            hourlyAttacks = 0;
            document.getElementById('hourly-attacks').textContent = '0';
        }, 3600000);
    </script>
</body>
</html>
EOF

    # Create log processor
    mkdir -p "$COMPOSE_DIR/attack-map/processor"
    cat > "$COMPOSE_DIR/attack-map/processor/requirements.txt" << 'EOF'
elasticsearch==8.11.0
redis==5.0.1
geoip2==4.7.0
requests==2.31.0
python-dateutil==2.8.2
EOF

    cat > "$COMPOSE_DIR/attack-map/processor/processor.py" << 'EOF'
#!/usr/bin/env python3
import json
import time
import redis
import requests
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
ES_HOST = os.getenv('ELASTICSEARCH_HOST', 'elasticsearch')
ES_PORT = int(os.getenv('ELASTICSEARCH_PORT', 9200))
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# Initialize connections
es = Elasticsearch([f'http://{ES_HOST}:{ES_PORT}'])
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def get_geolocation(ip):
    """Get geolocation for IP address using ipapi.co"""
    try:
        response = requests.get(f'http://ipapi.co/{ip}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'lat': data.get('latitude'),
                'lon': data.get('longitude'),
                'country': data.get('country_name'),
                'city': data.get('city')
            }
    except Exception as e:
        logger.error(f"Error getting geolocation for {ip}: {e}")
    return None

def process_firewall_logs():
    """Process firewall logs from Elasticsearch"""
    try:
        # Query for recent firewall blocks/denies
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"log_type": "firewall"}},
                        {"term": {"action": "block"}},
                        {"range": {"@timestamp": {"gte": "now-1m"}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        result = es.search(index="homelab-logs-*", body=query)
        
        for hit in result['hits']['hits']:
            log = hit['_source']
            
            # Extract attack data
            attack = {
                'timestamp': log.get('@timestamp'),
                'src_ip': log.get('src_ip'),
                'dst_ip': log.get('dst_ip'),
                'src_port': log.get('src_port'),
                'dst_port': log.get('dst_port'),
                'protocol': log.get('protocol'),
                'action': log.get('action'),
                'interface': log.get('interface')
            }
            
            # Skip if already processed
            attack_id = f"{attack['src_ip']}:{attack['timestamp']}"
            if r.exists(f"processed:{attack_id}"):
                continue
                
            # Get geolocation
            if attack['src_ip']:
                geo = get_geolocation(attack['src_ip'])
                if geo:
                    attack.update({
                        'src_lat': geo['lat'],
                        'src_lon': geo['lon'],
                        'src_country': geo['country'],
                        'src_city': geo['city']
                    })
            
            # Store in Redis
            r.lpush('recent_attacks', json.dumps(attack))
            r.ltrim('recent_attacks', 0, 999)  # Keep last 1000 attacks
            r.publish('new_attack', json.dumps(attack))
            r.setex(f"processed:{attack_id}", 3600, "1")  # Mark as processed for 1 hour
            
            logger.info(f"Processed attack from {attack['src_ip']} to {attack['dst_ip']}")
            
    except Exception as e:
        logger.error(f"Error processing firewall logs: {e}")

def main():
    logger.info("Starting attack map log processor...")
    
    while True:
        try:
            process_firewall_logs()
            time.sleep(30)  # Process every 30 seconds
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            break
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
EOF

    cd "$COMPOSE_DIR/attack-map"
    docker-compose up -d >/dev/null 2>&1 || true
    
    SERVICES_DEPLOYED+=("Attack Map Dashboard")
    print_message "SUCCESS" "Attack Map Dashboard deployed"
    print_message "INFO" "Attack Map available at: http://localhost:8080"
}

#######################################################################
# pfSense Integration
#######################################################################

setup_pfsense_integration() {
    print_message "DEPLOY" "Setting up pfSense integration..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        SERVICES_DEPLOYED+=("pfSense Integration")
        print_message "SUCCESS" "TEST: Would setup pfSense integration"
        return 0
    fi
    
    mkdir -p "$COMPOSE_DIR/pfsense"
    
    # Create pfSense configuration helper
    cat > "$COMPOSE_DIR/pfsense/pfsense-config.md" << 'EOF'
# pfSense Configuration for ELK Integration

## 1. Enable Remote Logging in pfSense

1. Login to pfSense web interface
2. Go to **Status > System Logs > Settings**
3. Check "Enable Remote Logging"
4. Set Remote Log Servers to: `<your-elk-server-ip>:5000`
5. Set Remote Syslog Contents to: "Everything"
6. Click Save

## 2. Configure Firewall Logging

1. Go to **Firewall > Rules**
2. Edit each rule you want to monitor
3. Check "Log packets that are handled by this rule"
4. Set description for better identification
5. Save and Apply Changes

## 3. Enable Additional Logging

1. Go to **System > Advanced > Miscellaneous**
2. Check "Log firewall default blocks"
3. Check "Log packets blocked by 'Block Bogon Networks' rules"
4. Check "Log packets blocked by 'Block Private Networks' rules"
5. Save

## 4. Setup Log Rotation

1. Go to **Status > System Logs > Settings**
2. Set "Log file size" to appropriate value (e.g., 512 KB)
3. Set "Log entries to show" to 50
4. Enable "Reverse Display"

## 5. Test Configuration

After setup, you should see logs in:
- Kibana: http://your-server:5601
- Attack Map: http://your-server:8080

## Sample pfSense Rules for Testing

Create these firewall rules to generate test data:
1. Block all from specific countries (GeoIP)
2. Block common attack ports (22, 23, 3389 from WAN)
3. Rate limiting rules
4. IDS/IPS integration

## Troubleshooting

If logs don't appear:
1. Check pfSense System Logs for errors
2. Verify network connectivity to ELK server
3. Check Logstash logs: `docker logs logstash`
4. Verify Elasticsearch indices: `curl localhost:9200/_cat/indices`
EOF

    # Create pfSense backup script
    cat > "$COMPOSE_DIR/pfsense/backup-pfsense.sh" << 'EOF'
#!/bin/bash

# pfSense Configuration Backup Script
# Run this periodically to backup pfSense configurations

PFSENSE_IP="${PFSENSE_IP:-192.168.1.1}"
BACKUP_DIR="/opt/homelab/backups/pfsense"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Note: This requires manual download from pfSense web interface
# Go to Diagnostics > Backup & Restore > Download configuration as XML

echo "Manual pfSense backup required:"
echo "1. Login to pfSense at https://$PFSENSE_IP"
echo "2. Go to Diagnostics > Backup & Restore"
echo "3. Click 'Download configuration as XML'"
echo "4. Save to: $BACKUP_DIR/pfsense-config-$DATE.xml"
echo ""
echo "For automated backups, consider using pfSense API or SSH access"
EOF

    chmod +x "$COMPOSE_DIR/pfsense/backup-pfsense.sh"
    
    SERVICES_DEPLOYED+=("pfSense Integration")
    print_message "SUCCESS" "pfSense integration setup completed"
    print_message "INFO" "Configuration guide: $COMPOSE_DIR/pfsense/pfsense-config.md"
}

#######################################################################
# Monitoring and Alerting
#######################################################################

deploy_monitoring() {
    print_message "DEPLOY" "Deploying monitoring stack (Prometheus + Grafana)..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        SERVICES_DEPLOYED+=("Monitoring Stack")
        print_message "SUCCESS" "TEST: Would deploy monitoring stack"
        return 0
    fi
    
    mkdir -p "$COMPOSE_DIR/monitoring"
    
    # Create monitoring docker-compose.yml
    cat > "$COMPOSE_DIR/monitoring/docker-compose.yml" << 'EOF'
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=30d'
      - '--web.enable-lifecycle'
    networks:
      - monitoring-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_INSTALL_PLUGINS=grafana-worldmap-panel,grafana-piechart-panel
    networks:
      - monitoring-network
    depends_on:
      - prometheus
    restart: unless-stopped

  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.rootfs=/rootfs'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'
    networks:
      - monitoring-network
    restart: unless-stopped

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:latest
    container_name: cadvisor
    ports:
      - "8081:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:rw
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro
    networks:
      - monitoring-network
    restart: unless-stopped

volumes:
  prometheus_data:
  grafana_data:

networks:
  monitoring-network:
    driver: bridge
EOF

    # Create Prometheus config
    mkdir -p "$COMPOSE_DIR/monitoring/prometheus"
    cat > "$COMPOSE_DIR/monitoring/prometheus/prometheus.yml" << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']

  - job_name: 'elasticsearch'
    static_configs:
      - targets: ['elasticsearch:9200']
    metrics_path: '/_prometheus/metrics'

  - job_name: 'logstash'
    static_configs:
      - targets: ['logstash:9600']
    metrics_path: '/metrics'
EOF

    # Create Grafana provisioning
    mkdir -p "$COMPOSE_DIR/monitoring/grafana/provisioning/datasources"
    cat > "$COMPOSE_DIR/monitoring/grafana/provisioning/datasources/prometheus.yml" << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF

    mkdir -p "$COMPOSE_DIR/monitoring/grafana/provisioning/dashboards"
    cat > "$COMPOSE_DIR/monitoring/grafana/provisioning/dashboards/default.yml" << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 10
    options:
      path: /var/lib/grafana/dashboards
EOF

    cd "$COMPOSE_DIR/monitoring"
    docker-compose up -d >/dev/null 2>&1 || true
    
    SERVICES_DEPLOYED+=("Monitoring Stack")
    print_message "SUCCESS" "Monitoring stack deployed"
    print_message "INFO" "Grafana available at: http://localhost:3000 (admin/admin123)"
    print_message "INFO" "Prometheus available at: http://localhost:9090"
}

#######################################################################
# Menu System
#######################################################################

show_banner() {
    clear
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🏠 Complete Home Lab Deployment Suite              ║
║                                                                  ║
║     openSUSE MicroOS + pfSense + ELK Stack + Attack Map        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
    echo "Running as: $(whoami) | Variant: ${VARIANT:-unknown}"
    echo "Log: $LOG_FILE"
    echo "Deployment Directory: $COMPOSE_DIR"
    echo "=================================================================="
    echo
}

show_menu() {
    show_banner
    echo "📦 SYSTEM SETUP:"
    echo "  1) Install Base System Packages"
    echo "  2) Install Container Runtime (Docker/Podman)"
    echo "  3) Install Monitoring Tools"
    echo "  4) Install Security Tools"
    echo
    echo "🌐 NETWORK CONFIGURATION:"
    echo "  5) Setup Advanced Firewall"
    echo "  6) Configure Network Optimization"
    echo
    echo "🔍 ELK STACK DEPLOYMENT:"
    echo "  7) Deploy ELK Stack (Elasticsearch/Logstash/Kibana)"
    echo "  8) Setup pfSense Integration"
    echo
    echo "🗺️  ATTACK MAP & MONITORING:"
    echo "  9) Deploy Attack Map Dashboard"
    echo "  10) Deploy Monitoring Stack (Prometheus/Grafana)"
    echo
    echo "🚀 COMPLETE DEPLOYMENT:"
    echo "  11) Deploy Everything (Full Home Lab Setup)"
    echo
    echo "📊 MANAGEMENT:"
    echo "  12) Show System Status"
    echo "  13) Show Service URLs"
    echo "  14) View Logs"
    echo "  15) Backup Configurations"
    echo "  16) Exit"
    echo
    read -p "Choose option [1-16]: " choice
}

show_system_status() {
    clear
    print_message "INFO" "System Status Overview"
    echo "========================================"
    
    # System info
    echo "🖥️  System Information:"
    echo "   OS: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || uname -s)"
    echo "   Kernel: $(uname -r)"
    echo "   Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo
    
    # Package status
    echo "📦 Packages Installed: ${#PACKAGES_INSTALLED[@]}"
    echo "❌ Failed Operations: ${#FAILED_OPERATIONS[@]}"
    echo "🚀 Services Deployed: ${#SERVICES_DEPLOYED[@]}"
    echo
    
    # Service status
    echo "🔧 Service Status:"
    local services=("docker" "firewalld" "sshd")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "   ✅ $service: Active"
        else
            echo "   ❌ $service: Inactive"
        fi
    done
    echo
    
    # Docker containers (if available)
    if command -v docker >/dev/null 2>&1 && [[ "${TEST_MODE:-}" != "true" ]]; then
        echo "🐳 Docker Containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "   No containers running"
        echo
    fi
    
    # Disk usage
    echo "💾 Disk Usage:"
    df -h / 2>/dev/null | tail -1 | awk '{printf "   /: %s used of %s (%s)\n", $3, $2, $5}'
    echo
    
    read -p "Press Enter to continue..."
}

show_service_urls() {
    clear
    print_message "INFO" "Service Access URLs"
    echo "========================================="
    echo
    echo "🔍 ELK Stack:"
    echo "   Kibana:        http://localhost:5601"
    echo "   Elasticsearch: http://localhost:9200"
    echo "   Logstash:      http://localhost:9600"
    echo
    echo "🗺️  Attack Map:"
    echo "   Dashboard:     http://localhost:8080"
    echo
    echo "📊 Monitoring:"
    echo "   Grafana:       http://localhost:3000 (admin/admin123)"
    echo "   Prometheus:    http://localhost:9090"
    echo "   Node Exporter: http://localhost:9100"
    echo
    echo "🛡️  pfSense:"
    echo "   Web Interface: https://192.168.1.1 (configure manually)"
    echo "   Backup Script: $COMPOSE_DIR/pfsense/backup-pfsense.sh"
    echo
    echo "📁 Configuration Files:"
    echo "   ELK Stack:     $COMPOSE_DIR/elk/"
    echo "   Attack Map:    $COMPOSE_DIR/attack-map/"
    echo "   Monitoring:    $COMPOSE_DIR/monitoring/"
    echo "   pfSense:       $COMPOSE_DIR/pfsense/"
    echo
    read -p "Press Enter to continue..."
}

backup_configurations() {
    print_message "INFO" "Creating configuration backup..."
    
    if [[ "${TEST_MODE:-}" == "true" ]]; then
        print_message "SUCCESS" "TEST: Would create backup"
        read -p "Press Enter to continue..."
        return 0
    fi
    
    local backup_dir="/opt/homelab/backups/$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Backup compose files and configs
    if [[ -d "$COMPOSE_DIR" ]]; then
        cp -r "$COMPOSE_DIR" "$backup_dir/"
        print_message "SUCCESS" "Configurations backed up to: $backup_dir"
    else
        print_message "WARN" "No configurations found to backup"
    fi
    
    # Create system info snapshot
    cat > "$backup_dir/system-info.txt" << EOF
Backup Date: $(date)
System: $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
Kernel: $(uname -r)
Packages Installed: ${PACKAGES_INSTALLED[@]}
Services Deployed: ${SERVICES_DEPLOYED[@]}
Failed Operations: ${FAILED_OPERATIONS[@]}
EOF
    
    print_message "INFO" "Backup completed: $backup_dir"
    read -p "Press Enter to continue..."
}

full_deployment() {
    print_message "DEPLOY" "Starting complete home lab deployment..."
    echo
    print_message "INFO" "This will install and configure:"
    echo "   • Base system packages and container runtime" 
    echo "   • Advanced firewall and network optimization"
    echo "   • Complete ELK Stack for log analysis"
    echo "   • Attack Map Dashboard for threat visualization"
    echo "   • Monitoring stack with Grafana and Prometheus"
    echo "   • pfSense integration setup"
    echo
    read -p "Continue with full deployment? [y/N]: " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        return 0
    fi
    
    # Execute full deployment
    install_base_system
    install_container_runtime
    install_monitoring_tools
    install_security_tools
    setup_advanced_firewall
    configure_network_optimization
    deploy_elk_stack
    setup_pfsense_integration
    deploy_attack_map
    deploy_monitoring
    
    # Summary
    echo
    print_message "SUCCESS" "🎉 Complete Home Lab Deployment Finished!"
    print_message "INFO" "Packages installed: ${#PACKAGES_INSTALLED[@]}"
    print_message "INFO" "Services deployed: ${#SERVICES_DEPLOYED[@]}"
    
    if [[ ${#FAILED_OPERATIONS[@]} -gt 0 ]]; then
        print_message "WARN" "Some operations failed: ${#FAILED_OPERATIONS[@]}"
    fi
    
    echo
    print_message "INFO" "🌐 Access your services:"
    echo "   • Kibana (Log Analysis): http://localhost:5601"
    echo "   • Attack Map: http://localhost:8080"
    echo "   • Grafana (Monitoring): http://localhost:3000"
    echo "   • Prometheus: http://localhost:9090"
    echo
    print_message "INFO" "📖 Next steps:"
    echo "   1. Configure pfSense logging (see: $COMPOSE_DIR/pfsense/pfsense-config.md)"
    echo "   2. Import Grafana dashboards for better visualization"
    echo "   3. Set up automated backups"
    echo "   4. Configure alerting rules"
    
    if [[ "$VARIANT" == "server" ]] && [[ ${#PACKAGES_INSTALLED[@]} -gt 0 ]]; then
        echo
        print_message "INFO" "Server variant detected - reboot recommended"
        read -p "Reboot now to complete package installation? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_message "INFO" "Rebooting system..."
            reboot
        fi
    fi
    
    read -p "Press Enter to continue..."
}

show_log() {
    clear
    echo "=== Home Lab Setup Log ==="
    echo
    if [[ -f "$LOG_FILE" ]]; then
        tail -50 "$LOG_FILE"
    else
        echo "No log file found"
    fi
    echo
    read -p "Press Enter to continue..."
}

#######################################################################
# Main Function
#######################################################################

main() {
    # Set up environment from arguments
    for arg in "$@"; do
        case "$arg" in
            TEST_MODE=true)
                export TEST_MODE=true
                ;;
            FORCE_RUN=true) 
                export FORCE_RUN=true
                ;;
        esac
    done
    
    # Initialize
    echo "Starting Complete Home Lab Setup..." > "$LOG_FILE"
    
    # Basic checks
    check_root
    check_system
    detect_variant
    
    # Create deployment directory
    mkdir -p "$COMPOSE_DIR"
    
    # Menu loop
    while true; do
        show_menu
        
        case $choice in
            1) install_base_system; read -p "Press Enter to continue..." ;;
            2) install_container_runtime; read -p "Press Enter to continue..." ;;
            3) install_monitoring_tools; read -p "Press Enter to continue..." ;;
            4) install_security_tools; read -p "Press Enter to continue..." ;;
            5) setup_advanced_firewall; read -p "Press Enter to continue..." ;;
            6) configure_network_optimization; read -p "Press Enter to continue..." ;;
            7) deploy_elk_stack; read -p "Press Enter to continue..." ;;
            8) setup_pfsense_integration; read -p "Press Enter to continue..." ;;
            9) deploy_attack_map; read -p "Press Enter to continue..." ;;
            10) deploy_monitoring; read -p "Press Enter to continue..." ;;
            11) full_deployment ;;
            12) show_system_status ;;
            13) show_service_urls ;;
            14) show_log ;;
            15) backup_configurations ;;
            16) 
                print_message "SUCCESS" "🏠 Home Lab Setup Complete!"
                print_message "INFO" "Thank you for using the Complete Home Lab Deployment Suite!"
                exit 0
                ;;
            *)
                print_message "ERROR" "Invalid option"
                sleep 1
                ;;
        esac
    done
}

# Check for help
if [[ "${1:-}" == "--help" ]] || [[ "${1:-}" == "-h" ]]; then
    cat << EOF
Usage: $SCRIPT_NAME [options]

Complete Home Lab Deployment Suite
Deploys: openSUSE MicroOS + pfSense + ELK Stack + Attack Map Dashboard

Options:
  --help, -h    Show this help
  
Environment Variables:
  FORCE_RUN=true    Run on non-MicroOS systems (for testing)
  TEST_MODE=true    Simulate operations without changes

Examples:
  $SCRIPT_NAME                          # Interactive deployment (as root)
  sudo $SCRIPT_NAME                     # Run with sudo
  FORCE_RUN=true $SCRIPT_NAME           # Force run on any system
  TEST_MODE=true FORCE_RUN=true $SCRIPT_NAME  # Complete test mode

Services Deployed:
  • ELK Stack (Elasticsearch, Logstash, Kibana)
  • Attack Map Dashboard with real-time visualization
  • Monitoring Stack (Prometheus, Grafana, Node Exporter)
  • pfSense integration and configuration
  • Advanced firewall and network optimization
  • Complete logging and security infrastructure

Note: This script is designed to run as root for full system access.
EOF
    exit 0
fi

# Run main function
main "$@"