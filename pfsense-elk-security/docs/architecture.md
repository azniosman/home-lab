# Architecture Overview

This document provides a comprehensive overview of the pfSense + ELK Stack security monitoring architecture, data flow, and component interactions.

## System Architecture

### High-Level Architecture Diagram
```
Internet Traffic
       ↓
┌─────────────────┐
│    pfSense      │ ← Firewall + Router
│   Firewall      │
└─────────────────┘
       ↓ (Syslog UDP:514)
┌─────────────────┐
│    Logstash     │ ← Log Processing Engine
│  (Data Pipeline)│
└─────────────────┘
       ↓ (HTTP:9200)
┌─────────────────┐
│  Elasticsearch  │ ← Search & Analytics Engine
│  (Data Storage) │
└─────────────────┘
       ↓ (HTTP:9200)
┌─────────────────┐
│     Kibana      │ ← Visualization & Dashboards
│ (Frontend UI)   │
└─────────────────┘
       ↓ (HTTP:5601)
┌─────────────────┐
│  Security Team  │ ← End Users
│   Dashboard     │
└─────────────────┘
```

## Component Details

### 1. pfSense Firewall

**Role**: Network gateway and log source
**Key Functions**:
- Packet filtering and routing
- Traffic logging and analysis
- Syslog message generation
- Geographic IP blocking

**Configuration**:
```
Logging Target: Logstash Server (UDP:514)
Log Format: BSD Syslog (RFC 3164)
Log Content: Firewall rules, blocked connections, passed traffic
Update Frequency: Real-time
```

**Sample Log Format**:
```
<134>Nov 24 10:15:30 pfsense filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.1.100,203.0.113.50,49152,22,0
```

### 2. Logstash

**Role**: Log processing and enrichment pipeline
**Key Functions**:
- Syslog message parsing
- Data transformation and normalization
- GeoIP enrichment
- Field extraction and mapping

**Processing Pipeline**:
```
Input → Filter → Output
  ↓       ↓        ↓
Syslog  Parse   Elasticsearch
UDP:514 Enrich  HTTP:9200
```

**Data Enrichment**:
- **GeoIP Lookup**: Converts IP addresses to geographic locations
- **Field Extraction**: Parses structured data from log messages
- **Timestamp Normalization**: Standardizes time formats
- **Data Validation**: Ensures data quality and consistency

### 3. Elasticsearch

**Role**: Distributed search and analytics engine
**Key Functions**:
- Real-time data indexing
- Full-text search capabilities
- Aggregation and analytics
- Data persistence and retrieval

**Index Strategy**:
```
pfsense-firewall-YYYY.MM.DD    # Firewall logs
pfsense-suricata-YYYY.MM.DD    # IDS/IPS logs
pfsense-system-YYYY.MM.DD      # System logs
```

**Performance Optimization**:
- Time-based indices for efficient querying
- Custom mapping for IP addresses and geographic data
- Optimized sharding for high-volume logging
- Automated index lifecycle management

### 4. Kibana

**Role**: Data visualization and user interface
**Key Functions**:
- Interactive dashboards
- Real-time monitoring
- Alert management
- Report generation

**Dashboard Categories**:
- **Security Overview**: High-level security metrics
- **Attack Map**: Geographic threat visualization
- **Threat Intelligence**: Attack pattern analysis
- **Network Traffic**: Bandwidth and connection analysis

## Data Flow Architecture

### 1. Log Generation Phase
```
Network Event → pfSense Processing → Syslog Generation
```
- Network packets trigger firewall rules
- pfSense evaluates rules and generates decisions
- Log entries created for blocked/allowed traffic
- Syslog messages formatted and transmitted

### 2. Log Processing Phase
```
Syslog Receipt → Parsing → Enrichment → Validation
```
- Logstash receives UDP syslog messages
- Grok patterns extract structured data
- GeoIP databases add location information
- Data validated and normalized

### 3. Storage Phase
```
Processed Data → Index Creation → Document Storage
```
- Elasticsearch receives JSON documents
- Time-based indices automatically created
- Documents stored with optimized mappings
- Search indices built for fast retrieval

### 4. Visualization Phase
```
Query Execution → Data Aggregation → Dashboard Rendering
```
- Kibana executes Elasticsearch queries
- Real-time aggregations computed
- Visualizations updated dynamically
- Interactive dashboards served to users

## Security Architecture

### Network Segmentation
```
┌─────────────────┐
│   Internet      │
└─────────────────┘
         │
┌─────────────────┐
│   DMZ Zone      │ ← pfSense Firewall
│ (192.168.1.0/24)│
└─────────────────┘
         │
┌─────────────────┐
│  Internal LAN   │ ← ELK Stack
│(192.168.10.0/24)│
└─────────────────┘
```

### Access Control
- **Network Level**: Firewall rules restrict ELK access
- **Application Level**: Kibana authentication and RBAC
- **Data Level**: Elasticsearch security features
- **Transport Level**: TLS encryption for all communications

### Monitoring Points
1. **Perimeter Security**: External attack detection
2. **Internal Traffic**: Lateral movement detection
3. **Administrative Access**: Privileged account monitoring
4. **Data Exfiltration**: Unusual outbound traffic patterns

## Scalability Architecture

### Horizontal Scaling Options

#### Single Node (Current)
```
Resources: 8GB RAM, 4 CPU cores
Capacity: ~10GB logs/day
Use Case: Small to medium networks
```

#### Multi-Node Cluster
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ Elasticsearch   │  │ Elasticsearch   │  │ Elasticsearch   │
│    Master       │  │     Data        │  │     Data        │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                     │                     │
┌─────────────────────────────────────────────────────────────┐
│                    Logstash Cluster                        │
└─────────────────────────────────────────────────────────────┘
         │
┌─────────────────┐
│     Kibana      │
└─────────────────┘
```

**Capacity**: 50GB+ logs/day
**Use Case**: Enterprise networks

### Vertical Scaling Guidelines
- **Memory**: 50% of system RAM to Elasticsearch heap
- **CPU**: 1 core per 2GB of Elasticsearch heap
- **Storage**: SSD recommended, 3x log volume for retention
- **Network**: 1Gbps minimum for high-volume logging

## Monitoring and Health

### System Health Metrics
```
Component     │ Key Metrics                    │ Thresholds
──────────────┼────────────────────────────────┼─────────────
Elasticsearch │ Cluster Health, Index Size    │ Red = Alert
Logstash      │ Events/sec, Queue Depth       │ >1000 queue
Kibana        │ Response Time, Error Rate      │ >5s response
pfSense       │ Log Rate, Memory Usage         │ >80% memory
```

### Alerting Strategy
- **Infrastructure Alerts**: Service availability and performance
- **Security Alerts**: Attack detection and anomalies
- **Capacity Alerts**: Storage and processing limits
- **Data Quality Alerts**: Log parsing errors and gaps

## Integration Points

### External Systems
- **SIEM Integration**: Forward alerts to enterprise SIEM
- **Ticketing Systems**: Automatic incident creation
- **Notification Services**: Slack, email, SMS alerting
- **Backup Systems**: Automated index backup and recovery

### API Endpoints
```
Elasticsearch: http://elk-server:9200
Kibana:       http://elk-server:5601
Logstash:     udp://elk-server:514 (syslog)
```

## Performance Considerations

### Optimization Strategies
1. **Index Templates**: Pre-configure mappings and settings
2. **Shard Sizing**: Optimal shard size for search performance
3. **Refresh Intervals**: Balance real-time vs. performance
4. **Retention Policies**: Automated old data cleanup

### Capacity Planning
```
Log Volume    │ Elasticsearch │ Logstash     │ Total RAM
──────────────┼───────────────┼──────────────┼────────────
1GB/day       │ 4GB heap      │ 1GB heap     │ 8GB system
10GB/day      │ 8GB heap      │ 2GB heap     │ 16GB system
50GB/day      │ 16GB heap     │ 4GB heap     │ 32GB system
```

This architecture provides a robust, scalable foundation for network security monitoring with room for future expansion and enhancement.