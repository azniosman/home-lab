# UniFi Cloud Gateway Ultra Security Configuration Guide

This comprehensive guide covers the implementation of advanced security features on the UniFi Cloud Gateway Ultra (UCG-Ultra) for the secure home lab environment, integrating with the existing openSUSE MicroOS host and pfSense VM architecture.

## Overview

The UCG-Ultra serves as the primary network security gateway, positioned between the QNAP QHora-301W and the internal home lab infrastructure. It provides multiple layers of security including:

- **Stateful Firewall**: Advanced packet filtering and connection tracking
- **Application-Aware Firewall**: Deep packet inspection with application identification
- **Intrusion Prevention System (IPS/IDS)**: Real-time threat detection and blocking
- **Content Filtering**: Web content blocking and security scanning
- **Ad Blocking**: Network-level advertisement and tracker blocking
- **VLAN Security**: Traffic segmentation and inter-VLAN controls
- **VPN Gateway**: Secure remote access with multiple VPN protocols

## Network Architecture Integration

### Updated Network Topology

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
│ UCG-Ultra Security  │  ← Advanced Security Gateway
│   Gateway           │    - Stateful firewall
│                     │    - IPS/IDS
│                     │    - Content filtering
│                     │    - VLAN management
└─────────────────────┘
    │ (VLAN Trunk)
    ▼
┌─────────────────────┐
│ openSUSE MicroOS    │  ← Virtualization Host
│  Physical Host      │    - Bridge interface (br0)
│     (br0)           │    - KVM/QEMU virtualization
└─────────────────────┘
    │
    ▼
┌─────────────────────┐
│    pfSense VM       │  ← Internal Firewall
│ (Virtual Firewall)  │    - Inter-VLAN routing
│                     │    - Internal security policies
└─────────────────────┘
    │
    ├── VLAN 10 (Management)
    ├── VLAN 20 (LAN)
    ├── VLAN 30 (DMZ)
    └── VLAN 40 (Guest)
```

## Initial UCG-Ultra Setup

### Prerequisites

1. **Hardware Requirements**:
   - UCG-Ultra device with latest firmware
   - Network connection to QNAP QHora-301W
   - Management access to UniFi Network Application

2. **Network Planning**:
   ```
   WAN Side: Connected to QHora-301W
   LAN Side: VLAN trunk to openSUSE MicroOS host
   Management: Dedicated management VLAN (VLAN 10)
   ```

### Initial Configuration

1. **Factory Reset and Adoption**:
   ```bash
   # Reset UCG-Ultra to factory defaults
   # Hold reset button for 10 seconds
   # LED will flash white, then solid white
   
   # Adopt device in UniFi Network Application
   # Navigate to: Devices → UCG-Ultra → Adopt
   ```

2. **Basic Network Configuration**:
   ```json
   {
     "wan_config": {
       "connection_type": "static",
       "ip_address": "192.168.1.100",
       "subnet_mask": "255.255.255.0",
       "gateway": "192.168.1.1",
       "dns_servers": ["1.1.1.1", "8.8.8.8"]
     },
     "lan_config": {
       "ip_address": "192.168.10.1",
       "subnet_mask": "255.255.255.240",
       "dhcp_enabled": false
     }
   }
   ```

## Advanced Firewall Configuration

### Stateful Firewall Rules

1. **Access UniFi Network Application**:
   - Navigate to: Security → Traffic & Firewall Rules
   - Create comprehensive firewall policies

2. **Internet Security Rules**:
   ```json
   {
     "internet_security_rules": [
       {
         "name": "Block Malicious IPs",
         "type": "internet_in",
         "action": "drop",
         "source": "threat_intelligence",
         "destination": "any",
         "enabled": true,
         "logging": true
       },
       {
         "name": "Block Tor Exit Nodes",
         "type": "internet_in", 
         "action": "drop",
         "source": "tor_exit_nodes",
         "destination": "any",
         "enabled": true,
         "logging": true
       },
       {
         "name": "Rate Limit Inbound Connections",
         "type": "internet_in",
         "action": "accept",
         "rate_limit": {
           "enabled": true,
           "rate": 1000,
           "burst": 2000,
           "per": "minute"
         }
       }
     ]
   }
   ```

3. **LAN Security Rules**:
   ```json
   {
     "lan_security_rules": [
       {
         "name": "Management VLAN Isolation",
         "type": "lan_in",
         "action": "drop",
         "source": "!VLAN_10_Management",
         "destination": "VLAN_10_Management",
         "enabled": true,
         "logging": true
       },
       {
         "name": "Guest Network Isolation", 
         "type": "lan_in",
         "action": "drop",
         "source": "VLAN_40_Guest",
         "destination": "!VLAN_40_Guest,!internet",
         "enabled": true,
         "logging": true
       },
       {
         "name": "DMZ Access Control",
         "type": "lan_in",
         "action": "accept",
         "source": "VLAN_20_LAN",
         "destination": "VLAN_30_DMZ",
         "destination_port": "80,443,8080,8443",
         "protocol": "tcp"
       }
     ]
   }
   ```

### Application-Aware Firewall

1. **Deep Packet Inspection (DPI) Configuration**:
   ```json
   {
     "dpi_config": {
       "enabled": true,
       "application_identification": true,
       "protocol_detection": true,
       "categories": {
         "social_media": {
           "action": "monitor",
           "allowed_vlans": ["VLAN_20_LAN"],
           "blocked_vlans": ["VLAN_40_Guest"],
           "time_restrictions": {
             "enabled": true,
             "schedule": "business_hours"
           }
         },
         "streaming": {
           "action": "rate_limit",
           "bandwidth_limit": "50Mbps",
           "allowed_vlans": ["VLAN_20_LAN", "VLAN_40_Guest"]
         },
         "gaming": {
           "action": "prioritize",
           "qos_priority": "high",
           "allowed_vlans": ["VLAN_20_LAN"]
         },
         "file_sharing": {
           "action": "block",
           "blocked_vlans": ["VLAN_40_Guest"],
           "allowed_vlans": ["VLAN_20_LAN"]
         }
       }
     }
   }
   ```

2. **Application Control Rules**:
   ```json
   {
     "application_rules": [
       {
         "name": "Block Cryptocurrency Mining",
         "applications": ["cryptocurrency", "mining_pools"],
         "action": "drop",
         "vlans": ["all"],
         "logging": true
       },
       {
         "name": "Control Remote Access Tools",
         "applications": ["teamviewer", "anydesk", "remote_desktop"],
         "action": "require_auth",
         "vlans": ["VLAN_20_LAN"],
         "time_restrictions": "business_hours"
       },
       {
         "name": "Monitor Cloud Storage",
         "applications": ["dropbox", "google_drive", "onedrive"],
         "action": "monitor",
         "vlans": ["VLAN_20_LAN"],
         "data_loss_prevention": true
       }
     ]
   }
   ```

## Intrusion Prevention System (IPS/IDS)

### IPS Configuration

1. **Enable Threat Detection**:
   ```json
   {
     "ips_config": {
       "enabled": true,
       "mode": "detection_prevention",
       "sensitivity": "balanced",
       "categories": {
         "malware": {
           "enabled": true,
           "action": "drop_and_alert",
           "signature_updates": "automatic"
         },
         "vulnerability_exploits": {
           "enabled": true, 
           "action": "drop_and_alert",
           "custom_signatures": true
         },
         "botnet_communication": {
           "enabled": true,
           "action": "drop_and_quarantine",
           "c2_blocking": true
         },
         "data_exfiltration": {
           "enabled": true,
           "action": "alert_and_rate_limit",
           "dlp_integration": true
         }
       }
     }
   }
   ```

2. **Custom IPS Rules**:
   ```json
   {
     "custom_ips_rules": [
       {
         "name": "Detect SSH Brute Force",
         "signature": "alert tcp any any -> $HOME_NET 22 (msg:\"SSH Brute Force Attempt\"; flow:to_server; content:\"SSH-\"; detection_filter:track by_src,count 5,seconds 60; sid:1000001;)",
         "action": "alert_and_rate_limit",
         "enabled": true
       },
       {
         "name": "Detect DNS Tunneling",
         "signature": "alert udp $HOME_NET any -> any 53 (msg:\"Possible DNS Tunneling\"; content:\"|01 00 00 01|\"; byte_test:2,>,50,12; sid:1000002;)",
         "action": "alert",
         "enabled": true
       },
       {
         "name": "Block Known IoT Malware",
         "signature": "drop tcp any any -> $HOME_NET any (msg:\"IoT Malware Communication\"; content:\"Mirai\"; nocase; sid:1000003;)",
         "action": "drop",
         "enabled": true
       }
     ]
   }
   ```

### IDS Integration with ELK Stack

1. **Configure Syslog Export**:
   ```json
   {
     "syslog_config": {
       "enabled": true,
       "remote_servers": [
         {
           "host": "192.168.10.3",
           "port": 514,
           "protocol": "udp",
           "facility": "local0",
           "severity": "info"
         }
       ],
       "log_categories": [
         "ips_alerts",
         "firewall_blocks", 
         "application_control",
         "threat_intelligence",
         "authentication_events"
       ]
     }
   }
   ```

## VLAN Security and Traffic Segmentation

### VLAN Security Policies

1. **Configure VLAN Isolation**:
   ```json
   {
     "vlan_security": {
       "inter_vlan_routing": false,
       "vlans": {
         "10": {
           "name": "Management",
           "subnet": "192.168.10.0/28",
           "isolation": "strict",
           "allowed_communication": ["internet"],
           "security_level": "high",
           "monitoring": "comprehensive"
         },
         "20": {
           "name": "LAN", 
           "subnet": "192.168.20.0/24",
           "isolation": "selective",
           "allowed_communication": ["internet", "dmz_services"],
           "security_level": "medium",
           "content_filtering": true
         },
         "30": {
           "name": "DMZ",
           "subnet": "192.168.30.0/28", 
           "isolation": "strict",
           "allowed_communication": ["internet_limited"],
           "security_level": "high",
           "ids_monitoring": "aggressive"
         },
         "40": {
           "name": "Guest",
           "subnet": "192.168.40.0/26",
           "isolation": "complete",
           "allowed_communication": ["internet_filtered"],
           "security_level": "low",
           "bandwidth_limit": "50Mbps"
         }
       }
     }
   }
   ```

2. **Micro-Segmentation Rules**:
   ```json
   {
     "micro_segmentation": [
       {
         "name": "IoT Device Isolation",
         "source_criteria": {
           "device_type": "iot",
           "vlan": "40"
         },
         "destination_criteria": {
           "type": "internet_only",
           "allowed_ports": ["80", "443", "53", "123"]
         },
         "security_policy": "strict_egress"
       },
       {
         "name": "Server-to-Server Communication",
         "source_criteria": {
           "vlan": "30",
           "device_role": "server"
         },
         "destination_criteria": {
           "vlan": "30",
           "device_role": "server"
         },
         "security_policy": "authenticated_communication"
       }
     ]
   }
   ```

## Content Filtering and Ad Blocking

### Web Content Filtering

1. **Configure Content Categories**:
   ```json
   {
     "content_filtering": {
       "enabled": true,
       "mode": "dns_and_http_inspection",
       "categories": {
         "adult_content": {
           "action": "block",
           "vlans": ["VLAN_40_Guest"],
           "bypass_allowed": false
         },
         "gambling": {
           "action": "block", 
           "vlans": ["VLAN_40_Guest"],
           "time_restrictions": "always"
         },
         "social_media": {
           "action": "time_restrict",
           "vlans": ["VLAN_20_LAN"],
           "allowed_hours": "18:00-22:00",
           "weekends_only": false
         },
         "malware_sites": {
           "action": "block",
           "vlans": ["all"],
           "threat_intelligence": true
         },
         "phishing": {
           "action": "block_and_alert",
           "vlans": ["all"],
           "user_notification": true
         }
       }
     }
   }
   ```

2. **Custom Blocklists**:
   ```json
   {
     "custom_blocklists": [
       {
         "name": "Corporate Security Blocklist",
         "type": "domain",
         "sources": [
           "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
           "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"
         ],
         "update_frequency": "daily",
         "vlans": ["all"]
       },
       {
         "name": "Ad Blocking",
         "type": "domain",
         "sources": [
           "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adservers.txt"
         ],
         "update_frequency": "weekly",
         "vlans": ["VLAN_20_LAN", "VLAN_40_Guest"]
       }
     ]
   }
   ```

### DNS Security

1. **Secure DNS Configuration**:
   ```json
   {
     "dns_security": {
       "dns_over_https": {
         "enabled": true,
         "providers": ["cloudflare", "quad9"],
         "fallback": "quad8"
       },
       "dns_filtering": {
         "malware_blocking": true,
         "phishing_protection": true,
         "adult_content_blocking": {
           "enabled": true,
           "vlans": ["VLAN_40_Guest"]
         }
       },
       "dns_monitoring": {
         "query_logging": true,
         "suspicious_domain_detection": true,
         "dga_detection": true,
         "dns_tunneling_detection": true
       }
     }
   }
   ```

## VPN Security Configuration

### Site-to-Site VPN

1. **Configure S2S VPN for Management**:
   ```json
   {
     "site_to_site_vpn": {
       "enabled": true,
       "protocol": "ipsec",
       "remote_gateways": [
         {
           "name": "Remote_Office",
           "peer_ip": "203.0.113.100",
           "preshared_key": "managed_externally",
           "local_subnet": "192.168.10.0/28",
           "remote_subnet": "10.0.0.0/24",
           "encryption": "aes-256-gcm",
           "authentication": "sha256",
           "dh_group": "19"
         }
       ]
     }
   }
   ```

### Remote Access VPN

1. **Configure OpenVPN Server**:
   ```json
   {
     "remote_access_vpn": {
       "enabled": true,
       "protocol": "openvpn",
       "server_config": {
         "port": "1194",
         "protocol": "udp",
         "encryption": "aes-256-gcm",
         "authentication": "sha256",
         "compression": "lz4-v2"
       },
       "client_config": {
         "max_clients": 10,
         "client_subnet": "10.8.0.0/24",
         "dns_servers": ["192.168.10.1"],
         "routes": ["192.168.10.0/28"]
       },
       "authentication": {
         "method": "certificate_and_user",
         "certificate_authority": "internal_ca",
         "user_authentication": "local_users",
         "mfa_required": true
       }
     }
   }
   ```

2. **VPN Security Policies**:
   ```json
   {
     "vpn_security_policies": [
       {
         "name": "Admin VPN Access",
         "user_groups": ["administrators"],
         "allowed_vlans": ["VLAN_10_Management"],
         "time_restrictions": "none",
         "source_ip_restrictions": "none",
         "mfa_required": true
       },
       {
         "name": "Standard User VPN",
         "user_groups": ["standard_users"],
         "allowed_vlans": ["VLAN_20_LAN"],
         "time_restrictions": "business_hours", 
         "bandwidth_limit": "10Mbps",
         "mfa_required": true
       }
     ]
   }
   ```

## Monitoring and Logging Integration

### Security Event Logging

1. **Configure Comprehensive Logging**:
   ```json
   {
     "logging_config": {
       "local_storage": {
         "enabled": true,
         "retention_days": 30,
         "max_size_gb": 10
       },
       "remote_syslog": {
         "enabled": true,
         "servers": [
           {
             "host": "192.168.10.3",
             "port": 514,
             "protocol": "udp",
             "format": "rfc3164"
           }
         ]
       },
       "log_categories": {
         "firewall_events": "all",
         "ips_events": "all", 
         "vpn_events": "all",
         "authentication_events": "all",
         "application_control": "blocked_only",
         "content_filtering": "blocked_only",
         "system_events": "errors_warnings"
       }
     }
   }
   ```

### ELK Stack Integration

1. **Logstash Configuration for UCG-Ultra**:
   ```ruby
   # Add to pfsense-elk-security/configs/logstash/conf.d/ucg-ultra.conf
   input {
     udp {
       port => 5140
       type => "ucg-ultra"
     }
   }
   
   filter {
     if [type] == "ucg-ultra" {
       grok {
         match => { 
           "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:device} %{DATA:facility}: %{GREEDYDATA:message_body}" 
         }
       }
       
       # Parse UCG-Ultra specific events
       if [facility] == "firewall" {
         grok {
           match => {
             "message_body" => "%{WORD:action} %{WORD:protocol} %{IPV4:src_ip}:%{INT:src_port} -> %{IPV4:dest_ip}:%{INT:dest_port} %{GREEDYDATA:details}"
           }
         }
         mutate { add_tag => ["firewall", "ucg-ultra"] }
       }
       
       if [facility] == "ips" {
         grok {
           match => {
             "message_body" => "IPS Alert: %{DATA:signature_name} Priority: %{INT:priority} %{IPV4:src_ip} -> %{IPV4:dest_ip}"
           }
         }
         mutate { add_tag => ["ips", "security_alert", "ucg-ultra"] }
       }
       
       # GeoIP enrichment
       geoip {
         source => "src_ip"
         target => "src_geo"
       }
       
       # Threat intelligence enrichment
       if [src_ip] {
         ruby {
           code => "
             require 'net/http'
             require 'json'
             
             begin
               uri = URI('https://api.abuseipdb.com/api/v2/check')
               params = { ip: event.get('src_ip'), maxAgeInDays: 90 }
               uri.query = URI.encode_www_form(params)
               
               req = Net::HTTP::Get.new(uri)
               req['Key'] = 'YOUR_ABUSEIPDB_API_KEY'
               req['Accept'] = 'application/json'
               
               res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) { |http| http.request(req) }
               
               if res.code == '200'
                 data = JSON.parse(res.body)
                 if data['data']['abuseConfidencePercentage'] > 25
                   event.set('threat_intelligence', {
                     'is_malicious' => true,
                     'confidence' => data['data']['abuseConfidencePercentage'],
                     'country' => data['data']['countryCode']
                   })
                 end
               end
             rescue => e
               # Handle API errors gracefully
             end
           "
         }
       }
     }
   }
   
   output {
     if [type] == "ucg-ultra" {
       elasticsearch {
         hosts => ["192.168.10.3:9200"]
         index => "ucg-ultra-%{+YYYY.MM.dd}"
       }
     }
   }
   ```

## Security Automation and Response

### Automated Threat Response

1. **Create Threat Response Scripts**:
   ```bash
   # UCG-Ultra threat response automation
   sudo tee /usr/local/bin/ucg-ultra-threat-response.sh << 'EOF'
   #!/bin/bash
   
   # UCG-Ultra Automated Threat Response
   THREAT_TYPE="$1"
   SOURCE_IP="$2"
   SEVERITY="$3"
   
   UCG_CONTROLLER="192.168.10.1"
   API_KEY="your_unifi_api_key"
   
   case "$THREAT_TYPE" in
       "ips_alert")
           if [[ "$SEVERITY" == "high" ]]; then
               # Block IP address via UniFi API
               curl -X POST "https://$UCG_CONTROLLER:443/proxy/network/api/s/default/rest/firewallrule" \
                    -H "Authorization: Bearer $API_KEY" \
                    -H "Content-Type: application/json" \
                    -d "{
                         \"name\": \"Auto-Block-$SOURCE_IP\",
                         \"action\": \"drop\",
                         \"ruleset\": \"WAN_IN\",
                         \"rule_index\": 1,
                         \"src_address\": \"$SOURCE_IP\",
                         \"enabled\": true
                       }" \
                    -k
               
               logger "SECURITY: Auto-blocked malicious IP $SOURCE_IP via UCG-Ultra"
           fi
           ;;
       "brute_force")
           # Implement rate limiting
           curl -X POST "https://$UCG_CONTROLLER:443/proxy/network/api/s/default/rest/firewallrule" \
                -H "Authorization: Bearer $API_KEY" \
                -H "Content-Type: application/json" \
                -d "{
                     \"name\": \"Rate-Limit-$SOURCE_IP\",
                     \"action\": \"accept\", 
                     \"ruleset\": \"WAN_IN\",
                     \"src_address\": \"$SOURCE_IP\",
                     \"rate_limit\": {\"enabled\": true, \"rate\": 10, \"burst\": 20},
                     \"enabled\": true
                   }" \
                -k
           ;;
   esac
   EOF
   
   chmod +x /usr/local/bin/ucg-ultra-threat-response.sh
   ```

### Security Dashboard Creation

1. **Kibana Dashboard for UCG-Ultra**:
   ```json
   {
     "dashboard_config": {
       "title": "UCG-Ultra Security Dashboard",
       "visualizations": [
         {
           "title": "Firewall Events by Action",
           "type": "pie_chart",
           "query": "type:ucg-ultra AND tags:firewall",
           "aggregation": "terms",
           "field": "action"
         },
         {
           "title": "IPS Alerts Timeline",
           "type": "line_chart",
           "query": "type:ucg-ultra AND tags:ips",
           "time_field": "@timestamp",
           "aggregation": "date_histogram"
         },
         {
           "title": "Top Blocked Countries",
           "type": "bar_chart",
           "query": "type:ucg-ultra AND action:drop",
           "aggregation": "terms",
           "field": "src_geo.country_name"
         },
         {
           "title": "Application Control Events",
           "type": "data_table",
           "query": "type:ucg-ultra AND tags:application_control",
           "columns": ["timestamp", "src_ip", "application", "action"]
         }
       ]
     }
   }
   ```

## Performance Optimization

### UCG-Ultra Performance Tuning

1. **Optimize Security Features**:
   ```json
   {
     "performance_optimization": {
       "dpi_settings": {
         "max_flows": 100000,
         "flow_timeout": 300,
         "packet_capture_buffer": "128MB"
       },
       "ips_settings": {
         "rule_optimization": true,
         "fast_pattern_matcher": true,
         "flow_based_detection": true
       },
       "firewall_settings": {
         "connection_tracking_table_size": 65536,
         "nat_table_size": 16384,
         "state_timeout": 86400
       }
     }
   }
   ```

## Maintenance and Updates

### Security Update Management

1. **Configure Automatic Updates**:
   ```json
   {
     "update_config": {
       "automatic_updates": {
         "enabled": true,
         "schedule": "02:00",
         "update_types": ["security", "threat_intelligence"],
         "maintenance_window": "02:00-04:00"
       },
       "signature_updates": {
         "ips_signatures": "daily",
         "threat_intelligence": "hourly",
         "application_signatures": "weekly"
       }
     }
   }
   ```

### Regular Security Health Checks

1. **UCG-Ultra Security Health Script**:
   ```bash
   sudo tee /usr/local/bin/ucg-ultra-health-check.sh << 'EOF'
   #!/bin/bash
   
   echo "=== UCG-Ultra Security Health Check ==="
   
   # Check UCG-Ultra connectivity
   if ping -c 1 192.168.10.1 >/dev/null 2>&1; then
       echo "✓ UCG-Ultra connectivity: OK"
   else
       echo "✗ UCG-Ultra connectivity: FAILED"
   fi
   
   # Check firewall rule count
   RULE_COUNT=$(curl -s -k "https://192.168.10.1:443/api/firewall/rules" | jq '.data | length')
   echo "ℹ Active firewall rules: $RULE_COUNT"
   
   # Check IPS status
   IPS_STATUS=$(curl -s -k "https://192.168.10.1:443/api/ids/status" | jq -r '.data.enabled')
   echo "ℹ IPS Status: $IPS_STATUS"
   
   # Check VPN connections
   VPN_ACTIVE=$(curl -s -k "https://192.168.10.1:443/api/vpn/sessions" | jq '.data | length')
   echo "ℹ Active VPN sessions: $VPN_ACTIVE"
   
   echo "=== Health Check Complete ==="
   EOF
   
   chmod +x /usr/local/bin/ucg-ultra-health-check.sh
   ```

This comprehensive UCG-Ultra security configuration provides enterprise-grade security features integrated with your existing home lab infrastructure, creating multiple layers of defense while maintaining high performance and centralized monitoring through the ELK Stack.