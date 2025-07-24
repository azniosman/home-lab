#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== ELK Stack Health Check ==="
echo "Date: $(date)"
echo

# Elasticsearch cluster health
echo "Elasticsearch Cluster Health:"
CLUSTER_HEALTH=$(curl -s -u elastic:${ELASTIC_PASSWORD} "192.168.10.20:9200/_cluster/health" | jq -r '.status')
case $CLUSTER_HEALTH in
  "green") echo -e "${GREEN}✓ Cluster Status: $CLUSTER_HEALTH${NC}" ;;
  "yellow") echo -e "${YELLOW}⚠ Cluster Status: $CLUSTER_HEALTH${NC}" ;;
  "red") echo -e "${RED}✗ Cluster Status: $CLUSTER_HEALTH${NC}" ;;
  *) echo -e "${RED}✗ Cluster Status: Unknown${NC}" ;;
esac

# Service status checks
systemctl is-active elasticsearch && echo -e "${GREEN}✓ Elasticsearch: Running${NC}" || echo -e "${RED}✗ Elasticsearch: Stopped${NC}"
systemctl is-active logstash && echo -e "${GREEN}✓ Logstash: Running${NC}" || echo -e "${RED}✗ Logstash: Stopped${NC}"
systemctl is-active kibana && echo -e "${GREEN}✓ Kibana: Running${NC}" || echo -e "${RED}✗ Kibana: Stopped${NC}"

echo -e "\n=== Health Check Complete ==="
