#!/bin/bash

set -e

echo "🚀 Installing ELK Stack for pfSense Security Monitoring"

# Update system
sudo apt update && sudo apt upgrade -y

# Install Java
sudo apt install openjdk-11-jdk -y

# Add Elastic repository
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

sudo apt update

# Install ELK components
sudo apt install elasticsearch logstash kibana -y

# Copy configuration files
sudo cp ../configs/elasticsearch/elasticsearch.yml /etc/elasticsearch/
sudo cp ../configs/logstash/conf.d/pfsense.conf /etc/logstash/conf.d/
sudo cp ../configs/kibana/kibana.yml /etc/kibana/

# Set JVM heap sizes
echo -e "-Xms2g\n-Xmx2g" | sudo tee /etc/elasticsearch/jvm.options.d/heap.options
echo -e "-Xms1g\n-Xmx1g" | sudo tee /etc/logstash/jvm.options.d/heap.options

# Start services
sudo systemctl enable --now elasticsearch
sudo systemctl enable --now logstash  
sudo systemctl enable --now kibana

echo "✅ ELK Stack installation complete!"
echo "🌐 Kibana will be available at: http://192.168.10.20:5601"
