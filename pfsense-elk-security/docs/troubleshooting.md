# Troubleshooting Guide

This guide covers common issues, diagnostic procedures, and solutions for the pfSense + ELK Stack security monitoring system.

## Quick Diagnostic Commands

### System Health Check
```bash
# Check all Docker containers
docker-compose -f docker-compose/docker-compose.yml ps

# Check Elasticsearch cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check Logstash pipeline status
curl -X GET "localhost:9600/_node/stats/pipelines?pretty"

# Check Kibana status
curl -X GET "localhost:5601/api/status"
```

### Log Analysis Commands
```bash
# View Elasticsearch logs
docker logs elasticsearch

# View Logstash logs
docker logs logstash

# View Kibana logs
docker logs kibana

# Check log processing rate
curl -X GET "localhost:9200/_cat/indices/pfsense-*?v"
```

## Common Issues and Solutions

### 1. Elasticsearch Issues

#### Issue: Elasticsearch won't start
**Symptoms**:
- Container exits immediately
- "max virtual memory areas vm.max_map_count [65530] is too low" error

**Solution**:
```bash
# Increase virtual memory
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Or temporarily
sudo sysctl -w vm.max_map_count=262144

# Restart Elasticsearch
docker-compose restart elasticsearch
```

#### Issue: Elasticsearch cluster status is RED
**Symptoms**:
- Cluster health API returns "red" status
- Some indices are inaccessible

**Diagnostic Commands**:
```bash
# Check cluster health details
curl -X GET "localhost:9200/_cluster/health?level=indices&pretty"

# Check unassigned shards
curl -X GET "localhost:9200/_cat/shards?h=index,shard,prirep,state,unassigned.reason"

# Check node status
curl -X GET "localhost:9200/_cat/nodes?v"
```

**Solutions**:
```bash
# Delete problematic indices (CAUTION: Data loss)
curl -X DELETE "localhost:9200/problematic-index-name"

# Retry allocation for unassigned shards
curl -X POST "localhost:9200/_cluster/reroute?retry_failed=true"
```

#### Issue: Elasticsearch out of disk space
**Symptoms**:
- "disk usage exceeded flood-stage watermark" error
- New indices cannot be created

**Solution**:
```bash
# Check disk usage
df -h

# Clean old indices
curl -X DELETE "localhost:9200/pfsense-*-$(date -d '30 days ago' '+%Y.%m.%d')"

# Update disk watermark settings (temporary)
curl -X PUT "localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "transient": {
      "cluster.routing.allocation.disk.watermark.low": "90%",
      "cluster.routing.allocation.disk.watermark.high": "95%",
      "cluster.routing.allocation.disk.watermark.flood_stage": "97%"
    }
  }'
```

### 2. Logstash Issues

#### Issue: Logstash not receiving logs
**Symptoms**:
- Logstash shows no incoming events
- pfSense logs not appearing in Elasticsearch

**Diagnostic Commands**:
```bash
# Check if UDP port 514 is listening
sudo netstat -ulnp | grep 514

# Test UDP connectivity from pfSense
# On pfSense: echo "test message" | nc -u <ELK_SERVER_IP> 514

# Check Logstash pipeline stats
curl -X GET "localhost:9600/_node/stats/pipelines?pretty"
```

**Solutions**:
1. **Firewall Issues**:
   ```bash
   # Check firewall rules
   sudo ufw status
   
   # Allow UDP 514 if needed
   sudo ufw allow 514/udp
   ```

2. **Configuration Issues**:
   ```bash
   # Test Logstash configuration
   docker exec logstash /usr/share/logstash/bin/logstash --config.test_and_exit
   
   # Check configuration syntax
   docker exec logstash /usr/share/logstash/bin/logstash --config.reload.automatic
   ```

#### Issue: Logstash parsing errors
**Symptoms**:
- "_grokparsefailure" tags in Elasticsearch
- Raw unparsed messages in indices

**Diagnostic Commands**:
```bash
# Search for parsing failures
curl -X GET "localhost:9200/pfsense-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": { "match": { "tags": "_grokparsefailure" } },
    "size": 5
  }'
```

**Solutions**:
```bash
# Debug with sample log entry
echo "Nov 24 10:15:30 pfsense filterlog: sample_log_entry" | \
  docker exec -i logstash /usr/share/logstash/bin/logstash -f /dev/stdin

# Update grok patterns in configs/logstash/conf.d/pfsense.conf
# Test new patterns with Kibana Dev Tools
```

### 3. Kibana Issues

#### Issue: Kibana loading slowly or timing out
**Symptoms**:
- Long page load times
- "Request timeout" errors
- Browser shows loading spinner indefinitely

**Diagnostic Commands**:
```bash
# Check Kibana response time
time curl -X GET "localhost:5601/api/status"

# Monitor Kibana logs for errors
docker logs -f kibana

# Check Elasticsearch query performance
curl -X GET "localhost:9200/_nodes/stats/indices/search"
```

**Solutions**:
1. **Memory Issues**:
   ```bash
   # Increase Kibana memory in docker-compose.yml
   environment:
     - NODE_OPTIONS="--max-old-space-size=4096"
   ```

2. **Large Dataset Issues**:
   ```bash
   # Reduce default time range in Kibana settings
   # Use filters to limit data scope
   # Create optimized index patterns
   ```

#### Issue: Kibana index patterns not working
**Symptoms**:
- "No matching indices found" error
- Unable to create index patterns

**Solutions**:
```bash
# Check if indices exist
curl -X GET "localhost:9200/_cat/indices/pfsense-*?v"

# Create index pattern via API
curl -X POST "localhost:5601/api/saved_objects/index-pattern/pfsense-*" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "title": "pfsense-*",
      "timeFieldName": "@timestamp"
    }
  }'
```

### 4. pfSense Configuration Issues

#### Issue: pfSense not sending logs
**Symptoms**:
- No log entries in Logstash/Elasticsearch
- pfSense system logs show no remote logging activity

**Diagnostic Steps**:
1. **Check pfSense Syslog Configuration**:
   - Navigate to System → Advanced → Logging
   - Verify Remote Syslog Server is set to `<ELK_SERVER_IP>:514`
   - Ensure "Remote Log Contents" includes desired log types

2. **Test Network Connectivity**:
   ```bash
   # From pfSense diagnostics page, ping ELK server
   ping <ELK_SERVER_IP>
   
   # Test UDP port connectivity
   telnet <ELK_SERVER_IP> 514
   ```

3. **Check Firewall Rules**:
   - Ensure LAN rules allow traffic to ELK server on UDP 514
   - Verify no blocking rules prevent syslog traffic

**Solutions**:
```bash
# Restart syslog service on pfSense
# Services → System Services → Syslog-ng → Restart

# Temporarily increase logging verbosity
# System → Advanced → Logging → Log Message Format = "RFC 5424"
```

### 5. Network and Connectivity Issues

#### Issue: Services can't communicate
**Symptoms**:
- Connection refused errors
- Timeout errors between components

**Network Diagnostic Commands**:
```bash
# Check Docker network
docker network ls
docker network inspect pfsense-elk-security_elk

# Test inter-container connectivity
docker exec logstash ping elasticsearch
docker exec kibana ping elasticsearch

# Check port bindings
docker port elasticsearch
docker port logstash
docker port kibana
```

**Solutions**:
```bash
# Recreate Docker network
docker-compose down
docker network prune
docker-compose up -d

# Check firewall settings
sudo ufw status
sudo iptables -L
```

### 6. Performance Issues

#### Issue: High memory usage
**Symptoms**:
- Out of memory errors
- System becomes unresponsive
- Docker containers being killed

**Monitoring Commands**:
```bash
# Monitor container resource usage
docker stats

# Check system memory
free -h

# Monitor Elasticsearch heap usage
curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"
```

**Solutions**:
```bash
# Adjust Elasticsearch heap size in docker-compose.yml
environment:
  - "ES_JAVA_OPTS=-Xms2g -Xmx2g"  # Reduce if needed

# Adjust Logstash heap size
environment:
  - "LS_JAVA_OPTS=-Xms512m -Xmx512m"

# Clean up old indices
curl -X DELETE "localhost:9200/pfsense-*-$(date -d '7 days ago' '+%Y.%m.%d')"
```

#### Issue: High CPU usage
**Symptoms**:
- System load consistently high
- Slow query response times

**Solutions**:
```bash
# Reduce Logstash workers in pipeline.yml
pipeline.workers: 2  # Reduce from default

# Optimize Elasticsearch queries
# Use time-based filters in Kibana dashboards
# Reduce dashboard refresh intervals
```

## Maintenance Procedures

### Regular Health Checks
```bash
#!/bin/bash
# Daily health check script

echo "=== ELK Stack Health Check $(date) ==="

# Check container status
echo "Container Status:"
docker-compose ps

# Check Elasticsearch cluster health
echo "Elasticsearch Health:"
curl -s "localhost:9200/_cluster/health" | jq

# Check recent log ingestion
echo "Recent Log Count:"
curl -s "localhost:9200/pfsense-*/_count" | jq

# Check disk usage
echo "Disk Usage:"
df -h /var/lib/docker

echo "=== Health Check Complete ==="
```

### Log Rotation and Cleanup
```bash
#!/bin/bash
# Weekly cleanup script

# Delete indices older than 30 days
CUTOFF_DATE=$(date -d '30 days ago' '+%Y.%m.%d')
curl -X DELETE "localhost:9200/pfsense-*-${CUTOFF_DATE}"

# Force merge old indices to reduce storage
curl -X POST "localhost:9200/pfsense-*/_forcemerge?max_num_segments=1"

# Clean Docker logs
docker system prune -f
```

### Backup Procedures
```bash
#!/bin/bash
# Backup Elasticsearch indices

# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup_repo" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/backup"
    }
  }'

# Create snapshot of all indices
curl -X PUT "localhost:9200/_snapshot/backup_repo/$(date +%Y%m%d_%H%M%S)" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": "pfsense-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'
```

## Emergency Procedures

### Complete System Recovery
```bash
# 1. Stop all services
docker-compose down

# 2. Clean Docker volumes (WARNING: Data loss)
docker volume prune -f

# 3. Restart with fresh configuration
docker-compose up -d

# 4. Restore from backup if available
# (Restore procedures depend on backup method used)
```

### Data Recovery
```bash
# Recover from snapshot
curl -X POST "localhost:9200/_snapshot/backup_repo/snapshot_name/_restore" \
  -H "Content-Type: application/json" \
  -d '{
    "indices": "pfsense-firewall-*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'
```

## Getting Help

### Log Collection for Support
```bash
#!/bin/bash
# Collect diagnostic information

mkdir -p elk-diagnostics
cd elk-diagnostics

# Container information
docker-compose ps > container-status.txt
docker stats --no-stream > container-stats.txt

# Service logs
docker logs elasticsearch > elasticsearch.log 2>&1
docker logs logstash > logstash.log 2>&1
docker logs kibana > kibana.log 2>&1

# Elasticsearch cluster info
curl -s "localhost:9200/_cluster/health?pretty" > cluster-health.json
curl -s "localhost:9200/_cat/indices?v" > indices-info.txt

# System information
uname -a > system-info.txt
free -h > memory-info.txt
df -h > disk-info.txt

echo "Diagnostic files collected in elk-diagnostics/"
```

### Useful Resources
- **Elasticsearch Documentation**: https://elastic.co/guide/en/elasticsearch/reference/current/
- **Logstash Documentation**: https://elastic.co/guide/en/logstash/current/
- **Kibana Documentation**: https://elastic.co/guide/en/kibana/current/
- **pfSense Documentation**: https://docs.pfsense.org/

Remember to check version-specific documentation for your ELK Stack version (8.11.0 as of this guide).