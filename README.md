# pfSense + ELK Stack Security Monitoring Lab

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

## 🎯 Quick Start

1. Follow the [Installation Guide](docs/installation-guide.md)
2. Configure pfSense logging using configs in `configs/pfsense/`
3. Deploy ELK Stack with `scripts/install/install-elk.sh`
4. Import Kibana dashboards from `configs/kibana/dashboards/`
5. Set up monitoring with scripts in `scripts/maintenance/`

## 🔧 Architecture

Internet → pfSense VM → Logstash → Elasticsearch → Kibana
↓
Security Analysis & Attack Map

## 📊 Dashboards

- **Attack Map**: Real-time global threat visualization
- **Security Overview**: Summary of security events and trends
- **Threat Intelligence**: Analysis of attack patterns and sources

## 🚨 Alerting

- Brute force attack detection
- Port scanning identification
- DDoS attack monitoring
- Geographic anomaly detection
- Multi-stage attack correlation

## 📚 Documentation

- [Installation Guide](docs/installation-guide.md)
- [Architecture Overview](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)

## 🤝 Contributing

Feel free to submit issues and enhancement requests!

## 📄 License

MIT License - see LICENSE file for details
