# Security Hardening Guide

This comprehensive guide covers security hardening procedures for all components of the secure home lab environment, including the openSUSE MicroOS host, pfSense VM, network infrastructure, and ELK Stack monitoring.

## Overview

Security hardening is implemented at multiple layers:
- **Physical Security**: Hardware and facility protection
- **Host Security**: openSUSE MicroOS system hardening
- **Network Security**: VLAN isolation and firewall policies
- **Virtual Machine Security**: pfSense and guest VM protection
- **Application Security**: ELK Stack and service hardening
- **Access Control**: Authentication and authorization
- **Monitoring**: Security event detection and response

## Host System Security (openSUSE MicroOS)

### System Access Control

#### SSH Hardening

1. **Configure SSH Key-Based Authentication**:
   ```bash
   # Generate strong SSH key pair (on client)
   ssh-keygen -t ed25519 -a 100 -C "homelab-admin@$(hostname)"
   
   # Copy public key to server
   ssh-copy-id -i ~/.ssh/id_ed25519.pub admin@192.168.10.2
   ```

2. **Harden SSH Configuration**:
   ```bash
   sudo tee /etc/ssh/sshd_config.d/99-security-hardening.conf << EOF
   # Security Hardening Configuration
   
   # Authentication
   PermitRootLogin no
   PasswordAuthentication no
   PubkeyAuthentication yes
   AuthorizedKeysFile .ssh/authorized_keys
   PermitEmptyPasswords no
   UsePAM yes
   
   # Protocol and Connection Settings
   Protocol 2
   Port 22
   AddressFamily inet
   ListenAddress 192.168.10.2
   
   # Security Limits
   MaxAuthTries 3
   MaxSessions 5
   MaxStartups 10:30:60
   LoginGraceTime 30
   
   # Keep-alive Settings
   ClientAliveInterval 300
   ClientAliveCountMax 2
   TCPKeepAlive no
   
   # User Restrictions
   AllowUsers admin
   DenyUsers root
   AllowGroups wheel
   
   # Disable Dangerous Features
   AllowAgentForwarding no
   AllowTcpForwarding no
   X11Forwarding no
   PermitTTY yes
   PermitUserEnvironment no
   
   # Cryptographic Settings
   Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
   MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512
   KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
   
   # Banner and Logging
   Banner /etc/ssh/banner
   LogLevel VERBOSE
   SyslogFacility AUTH
   EOF
   
   # Create warning banner
   sudo tee /etc/ssh/banner << EOF
   ******************************************************************
   *                    AUTHORIZED ACCESS ONLY                     *
   *                                                              *
   * This system is for authorized users only. All activities    *
   * are monitored and logged. Unauthorized access is prohibited *
   * and will be prosecuted to the full extent of the law.       *
   ******************************************************************
   EOF
   
   # Restart SSH service
   sudo systemctl restart sshd
   ```

#### User Account Security

1. **Configure Strong Password Policies**:
   ```bash
   # Install password quality checking
   sudo transactional-update pkg install cracklib-dict-full
   
   # Configure password quality
   sudo tee -a /etc/security/pwquality.conf << EOF
   # Password Quality Requirements
   minlen = 14
   minclass = 3
   maxrepeat = 3
   maxclasschars = 4
   lcredit = -1
   ucredit = -1
   dcredit = -1
   ocredit = -1
   difok = 8
   gecoscheck = 1
   dictcheck = 1
   usercheck = 1
   enforcing = 1
   EOF
   
   # Reboot to apply transactional update
   sudo systemctl reboot
   ```

2. **Configure Account Lockout Policies**:
   ```bash
   # Configure PAM for account lockout
   sudo tee /etc/security/faillock.conf << EOF
   # Account Lockout Configuration
   dir = /var/run/faillock
   audit
   silent
   no_log_info
   local_users_only
   deny = 5
   fail_interval = 900
   unlock_time = 600
   even_deny_root
   root_unlock_time = 300
   EOF
   ```

### Firewall Configuration

1. **Configure Advanced Firewall Rules**:
   ```bash
   # Enable and configure firewalld
   sudo systemctl enable firewalld
   sudo systemctl start firewalld
   
   # Remove default zones and create custom zones
   sudo firewall-cmd --permanent --delete-zone=public
   sudo firewall-cmd --permanent --delete-zone=work
   sudo firewall-cmd --permanent --delete-zone=home
   
   # Create management zone
   sudo firewall-cmd --permanent --new-zone=mgmt
   sudo firewall-cmd --permanent --zone=mgmt --set-description="Management VLAN"
   sudo firewall-cmd --permanent --zone=mgmt --add-interface=br0.10
   sudo firewall-cmd --permanent --zone=mgmt --add-service=ssh
   sudo firewall-cmd --permanent --zone=mgmt --add-service=libvirt
   sudo firewall-cmd --permanent --zone=mgmt --add-port=9200/tcp  # Elasticsearch
   sudo firewall-cmd --permanent --zone=mgmt --add-port=5601/tcp  # Kibana
   sudo firewall-cmd --permanent --zone=mgmt --add-port=514/udp   # Syslog
   
   # Create isolated zone for other VLANs
   sudo firewall-cmd --permanent --new-zone=isolated
   sudo firewall-cmd --permanent --zone=isolated --set-target=DROP
   sudo firewall-cmd --permanent --zone=isolated --add-interface=br0.20
   sudo firewall-cmd --permanent --zone=isolated --add-interface=br0.30
   sudo firewall-cmd --permanent --zone=isolated --add-interface=br0.40
   
   # Apply configuration
   sudo firewall-cmd --reload
   
   # Verify configuration
   sudo firewall-cmd --list-all-zones
   ```

2. **Configure Connection Rate Limiting**:
   ```bash
   # Create rich rules for rate limiting
   sudo firewall-cmd --permanent --zone=mgmt --add-rich-rule='rule service name="ssh" accept limit value="5/m"'
   sudo firewall-cmd --permanent --zone=mgmt --add-rich-rule='rule port port="9200" protocol="tcp" accept limit value="100/m"'
   
   # Apply rules
   sudo firewall-cmd --reload
   ```

### System Hardening

1. **Configure Kernel Security Parameters**:
   ```bash
   sudo tee /etc/sysctl.d/99-security-hardening.conf << EOF
   # Network Security
   net.ipv4.ip_forward = 1
   net.ipv4.conf.all.send_redirects = 0
   net.ipv4.conf.default.send_redirects = 0
   net.ipv4.conf.all.accept_redirects = 0
   net.ipv4.conf.default.accept_redirects = 0
   net.ipv4.conf.all.accept_source_route = 0
   net.ipv4.conf.default.accept_source_route = 0
   net.ipv4.conf.all.log_martians = 1
   net.ipv4.conf.default.log_martians = 1
   net.ipv4.icmp_echo_ignore_broadcasts = 1
   net.ipv4.icmp_ignore_bogus_error_responses = 1
   net.ipv4.tcp_syncookies = 1
   net.ipv4.tcp_max_syn_backlog = 2048
   net.ipv4.tcp_synack_retries = 3
   net.ipv4.tcp_syn_retries = 5
   
   # IPv6 Security
   net.ipv6.conf.all.accept_redirects = 0
   net.ipv6.conf.default.accept_redirects = 0
   net.ipv6.conf.all.accept_source_route = 0
   net.ipv6.conf.default.accept_source_route = 0
   
   # Memory Protection
   kernel.dmesg_restrict = 1
   kernel.kptr_restrict = 2
   kernel.yama.ptrace_scope = 1
   
   # File System Security
   fs.suid_dumpable = 0
   fs.protected_hardlinks = 1
   fs.protected_symlinks = 1
   
   # Process Security
   kernel.core_uses_pid = 1
   kernel.ctrl-alt-del = 0
   EOF
   
   # Apply settings
   sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf
   ```

2. **Configure AppArmor**:
   ```bash
   # Enable AppArmor
   sudo systemctl enable apparmor
   sudo systemctl start apparmor
   
   # Check AppArmor status
   sudo aa-status
   
   # Set profiles to enforce mode
   sudo aa-enforce /etc/apparmor.d/*
   
   # Install additional profiles
   sudo transactional-update pkg install apparmor-profiles apparmor-utils
   sudo systemctl reboot
   ```

### Logging and Auditing

1. **Configure System Auditing**:
   ```bash
   # Install and enable auditd
   sudo transactional-update pkg install audit
   sudo systemctl reboot
   
   # Configure audit rules
   sudo tee /etc/audit/rules.d/99-security-hardening.rules << EOF
   # Delete all existing rules
   -D
   
   # Buffer size
   -b 8192
   
   # Failure mode (0=silent, 1=printk, 2=panic)
   -f 1
   
   # Monitor administrative actions
   -w /etc/passwd -p wa -k identity
   -w /etc/group -p wa -k identity
   -w /etc/shadow -p wa -k identity
   -w /etc/sudoers -p wa -k identity
   -w /etc/sudoers.d/ -p wa -k identity
   
   # Monitor SSH configuration
   -w /etc/ssh/sshd_config -p wa -k ssh
   -w /etc/ssh/sshd_config.d/ -p wa -k ssh
   
   # Monitor network configuration
   -w /etc/systemd/network/ -p wa -k network
   -w /etc/firewalld/ -p wa -k firewall
   
   # Monitor system calls
   -a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
   -a always,exit -F arch=b64 -S clock_settime -k time-change
   -a always,exit -F arch=b64 -S stime -k time-change
   
   # Monitor file access
   -a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k file_access
   -a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k file_access
   
   # Make rules immutable
   -e 2
   EOF
   
   # Enable and start auditd
   sudo systemctl enable auditd
   sudo systemctl start auditd
   ```

2. **Configure Centralized Logging**:
   ```bash
   # Configure rsyslog for centralized logging
   sudo tee /etc/rsyslog.d/99-security-logging.conf << EOF
   # Security event logging
   auth,authpriv.*                 /var/log/auth.log
   kern.*                          /var/log/kern.log
   daemon.*                        /var/log/daemon.log
   
   # Forward security logs to ELK Stack
   auth,authpriv.*                 @@192.168.10.3:514
   kern.*                          @@192.168.10.3:514
   daemon.*                        @@192.168.10.3:514
   local0.*                        @@192.168.10.3:514
   EOF
   
   # Restart rsyslog
   sudo systemctl restart rsyslog
   ```

## pfSense Security Hardening

### Web Interface Security

1. **Access pfSense Web Interface**:
   - Navigate to: https://192.168.10.1
   - Login with administrative credentials

2. **Configure HTTPS and Certificates**:
   ```
   Navigate to: System → Advanced → Admin Access
   
   Settings:
   - Protocol: HTTPS
   - SSL/TLS Certificate: Generate or import proper certificate
   - Enable "Redirect HTTP to HTTPS"
   - Disable "Web GUI redirect"
   - Set "Session timeout" to 60 minutes
   - Enable "Require HTTPS for pfSense login page"
   ```

3. **Configure Administrative Access**:
   ```
   Navigate to: System → User Manager
   
   Actions:
   - Change default admin password to strong password
   - Create additional administrative users if needed
   - Configure user privileges appropriately
   - Enable two-factor authentication if available
   ```

### Network Security Configuration

1. **Configure Firewall Rules**:
   ```
   Navigate to: Firewall → Rules
   
   Management VLAN (em0):
   - Allow HTTPS to pfSense (port 443)
   - Allow SSH if needed (restricted sources)
   - Allow DNS (port 53)
   - Allow NTP (port 123)
   - Deny all other inbound traffic
   
   LAN VLAN (em1):
   - Allow internet access (HTTP/HTTPS)
   - Allow DNS
   - Allow access to DMZ services (specific ports)
   - Deny access to Management VLAN
   - Deny access to other internal VLANs
   
   DMZ VLAN (em2):
   - Allow limited outbound internet (HTTP/HTTPS/DNS)
   - Deny access to all internal VLANs
   - Allow inbound traffic only on service ports
   
   Guest VLAN (em3):
   - Allow internet access only
   - Deny all internal network access
   - Rate limit bandwidth
   ```

2. **Configure Traffic Shaping**:
   ```
   Navigate to: Firewall → Traffic Shaper
   
   Settings:
   - Limit guest network bandwidth
   - Prioritize management traffic
   - Implement QoS policies
   ```

### Advanced Security Features

1. **Configure Intrusion Detection/Prevention**:
   ```
   Navigate to: System → Package Manager
   Install: Suricata or Snort
   
   Configuration:
   - Enable on WAN and LAN interfaces
   - Subscribe to threat intelligence feeds
   - Configure alerting rules
   - Enable automatic rule updates
   ```

2. **Configure pfBlockerNG**:
   ```
   Install: pfBlockerNG
   
   Configuration:
   - Enable DNS blocking for malware domains
   - Configure geographic blocking
   - Enable IP reputation blocking
   - Configure custom block lists
   ```

### Logging and Monitoring

1. **Configure System Logging**:
   ```
   Navigate to: Status → System Logs → Settings
   
   Settings:
   - Enable "Log packets matched by the default block rule"
   - Enable "Log packets matched by the default pass rule"
   - Enable "Log packets blocked by interface rules"
   - Set log rotation appropriately
   ```

2. **Configure Remote Logging**:
   ```
   Navigate to: Status → System Logs → Settings → Remote Logging
   
   Settings:
   - Remote Syslog Server: 192.168.10.3:514
   - Remote Log Contents: Everything
   - Source Address: 192.168.10.1
   ```

## Network Infrastructure Security

### VLAN Security

1. **VLAN Isolation Verification**:
   ```bash
   # Test VLAN isolation
   /home-lab/network/vlans/test-vlan-connectivity.sh --security
   ```

2. **Implement VLAN ACLs**:
   ```bash
   # Configure additional VLAN filtering rules
   sudo bridge vlan add dev br0 vid 10 pvid untagged
   sudo bridge vlan add dev br0 vid 20 
   sudo bridge vlan add dev br0 vid 30 
   sudo bridge vlan add dev br0 vid 40
   ```

### Network Monitoring

1. **Deploy Network Monitoring Tools**:
   ```bash
   # Install network monitoring tools
   sudo transactional-update pkg install \
     tcpdump \
     wireshark-cli \
     nmap \
     netstat-nat \
     ss \
     iftop \
     nethogs
   
   sudo systemctl reboot
   ```

2. **Configure Network Intrusion Detection**:
   ```bash
   # Install Suricata for host-based IDS
   sudo transactional-update pkg install suricata
   sudo systemctl reboot
   
   # Configure Suricata
   sudo tee /etc/suricata/suricata.yaml << EOF
   # Suricata Configuration
   default-log-dir: /var/log/suricata/
   stats:
     enabled: yes
     interval: 8
   
   outputs:
     - syslog:
         enabled: yes
         facility: local0
         level: Info
   
   af-packet:
     - interface: br0
       cluster-id: 99
   
   default-rule-path: /etc/suricata/rules
   rule-files:
     - suricata.rules
   EOF
   
   # Enable and start Suricata
   sudo systemctl enable suricata
   sudo systemctl start suricata
   ```

## ELK Stack Security

### Elasticsearch Security

1. **Enable Security Features**:
   ```yaml
   # Edit docker-compose.yml
   environment:
     - xpack.security.enabled=true
     - xpack.security.enrollment.enabled=true
     - xpack.security.http.ssl.enabled=true
     - xpack.security.transport.ssl.enabled=true
   ```

2. **Configure Authentication**:
   ```bash
   # Generate passwords for built-in users
   docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-setup-passwords interactive
   
   # Create custom certificates
   docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil ca
   docker exec elasticsearch /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12
   ```

### Kibana Security

1. **Configure Kibana Authentication**:
   ```yaml
   # Add to docker-compose.yml
   environment:
     - ELASTICSEARCH_USERNAME=kibana_system
     - ELASTICSEARCH_PASSWORD=${KIBANA_PASSWORD}
     - xpack.security.enabled=true
     - xpack.encryptedSavedObjects.encryptionKey=${ENCRYPTION_KEY}
   ```

2. **Configure Role-Based Access Control**:
   ```bash
   # Create security roles via Kibana interface
   # Navigate to: Stack Management → Security → Roles
   
   # Create roles:
   # - security_analyst: Read access to security indices
   # - network_admin: Full access to network dashboards
   # - view_only: Read-only access to dashboards
   ```

### Logstash Security

1. **Secure Logstash Configuration**:
   ```yaml
   # Update logstash configuration
   input {
     syslog {
       port => 514
       type => "syslog"
       use_labels => true
     }
   }
   
   filter {
     if [type] == "syslog" {
       grok {
         match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}: %{GREEDYDATA:msg}" }
       }
       
       # Security event classification
       if [program] =~ /sshd|auth|security/ {
         mutate { add_tag => ["security"] }
       }
       
       # Anonymize sensitive data
       mutate {
         gsub => [
           "message", "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP_ANONYMIZED]"
         ]
       }
     }
   }
   ```

## Access Control and Authentication

### Multi-Factor Authentication

1. **Configure MFA for Critical Services**:
   ```bash
   # Install Google Authenticator
   sudo transactional-update pkg install google-authenticator-libpam
   sudo systemctl reboot
   
   # Configure MFA for SSH
   sudo tee -a /etc/pam.d/sshd << EOF
   # Google Authenticator
   auth required pam_google_authenticator.so
   EOF
   
   # Update SSH configuration
   echo "ChallengeResponseAuthentication yes" | sudo tee -a /etc/ssh/sshd_config.d/99-security-hardening.conf
   echo "AuthenticationMethods publickey,keyboard-interactive" | sudo tee -a /etc/ssh/sshd_config.d/99-security-hardening.conf
   
   # Restart SSH
   sudo systemctl restart sshd
   ```

### Certificate Management

1. **Deploy Internal Certificate Authority**:
   ```bash
   # Create internal CA
   openssl genrsa -out ca-key.pem 4096
   openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem \
     -subj "/C=US/ST=Lab/L=HomeLab/O=Internal/CN=HomeLab-CA"
   
   # Generate server certificates
   openssl genrsa -out server-key.pem 4096
   openssl req -subj "/C=US/ST=Lab/L=HomeLab/O=Internal/CN=*.homelab.local" \
     -sha256 -new -key server-key.pem -out server.csr
   
   # Sign server certificate
   openssl x509 -req -days 365 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem \
     -out server-cert.pem -CAcreateserial
   ```

## Automated Security Monitoring

### Security Event Detection

1. **Create Security Alerting Rules**:
   ```bash
   # Create Watcher alerts for security events
   curl -X PUT "localhost:9200/_watcher/watch/security-alerts" \
     -H "Content-Type: application/json" \
     -d '{
       "trigger": {
         "schedule": {
           "interval": "5m"
         }
       },
       "input": {
         "search": {
           "request": {
             "search_type": "query_then_fetch",
             "indices": ["security-*"],
             "body": {
               "query": {
                 "bool": {
                   "must": [
                     {"range": {"@timestamp": {"gte": "now-5m"}}},
                     {"terms": {"tags": ["security", "failed_login", "intrusion"]}}
                   ]
                 }
               }
             }
           }
         }
       },
       "condition": {
         "compare": {
           "ctx.payload.hits.total": {
             "gt": 5
           }
         }
       },
       "actions": {
         "send_email": {
           "email": {
             "to": ["admin@homelab.local"],
             "subject": "Security Alert: Multiple security events detected",
             "body": "{{ctx.payload.hits.total}} security events detected in the last 5 minutes."
           }
         }
       }
     }'
   ```

### Automated Response

1. **Create Incident Response Scripts**:
   ```bash
   # Create security incident response script
   sudo tee /usr/local/bin/security-incident-response.sh << 'EOF'
   #!/bin/bash
   
   # Security incident response script
   INCIDENT_TYPE="$1"
   SEVERITY="$2"
   
   case "$INCIDENT_TYPE" in
       "failed_login")
           # Block IP if multiple failed logins
           IP=$(echo "$3" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")
           if [[ -n "$IP" ]]; then
               firewall-cmd --add-rich-rule="rule family='ipv4' source address='$IP' reject"
               logger "SECURITY: Blocked IP $IP due to failed login attempts"
           fi
           ;;
       "intrusion_attempt")
           # Alert and log intrusion attempt
           logger "SECURITY: Intrusion attempt detected - $3"
           echo "$(date): Intrusion attempt - $3" >> /var/log/security-incidents.log
           ;;
       *)
           logger "SECURITY: Unknown incident type - $INCIDENT_TYPE"
           ;;
   esac
   EOF
   
   chmod +x /usr/local/bin/security-incident-response.sh
   ```

## Backup and Recovery Security

### Secure Backup Strategy

1. **Configure Encrypted Backups**:
   ```bash
   # Create backup encryption script
   sudo tee /usr/local/bin/secure-backup.sh << 'EOF'
   #!/bin/bash
   
   BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
   BACKUP_DIR="/backup"
   ENCRYPTION_KEY="/etc/backup-key.gpg"
   
   # Create encrypted backup
   tar -czf - /etc /var/lib/libvirt /home | \
     gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
         --output "$BACKUP_DIR/system-backup-$BACKUP_DATE.tar.gz.gpg"
   
   # Log backup completion
   logger "BACKUP: Encrypted system backup completed - $BACKUP_DATE"
   EOF
   
   chmod +x /usr/local/bin/secure-backup.sh
   ```

2. **Configure Automated Backup Schedule**:
   ```bash
   # Add to crontab
   sudo crontab -e
   
   # Add backup schedule
   0 2 * * * /usr/local/bin/secure-backup.sh
   ```

## Security Testing and Validation

### Penetration Testing

1. **Internal Security Assessment**:
   ```bash
   # Install security testing tools
   sudo transactional-update pkg install nmap nikto openvas
   sudo systemctl reboot
   
   # Run network security scan
   nmap -sS -O -A 192.168.10.0/28
   nmap -sS -O -A 192.168.20.0/24
   nmap -sS -O -A 192.168.30.0/28
   nmap -sS -O -A 192.168.40.0/26
   ```

2. **Vulnerability Assessment**:
   ```bash
   # Run vulnerability scans
   openvas-nasl -t localhost
   nikto -h https://192.168.10.1
   ```

### Security Compliance

1. **Security Checklist**:
   ```bash
   # Create security compliance checker
   sudo tee /usr/local/bin/security-compliance-check.sh << 'EOF'
   #!/bin/bash
   
   echo "=== Security Compliance Check ==="
   
   # Check SSH configuration
   echo "SSH Security:"
   grep -q "PermitRootLogin no" /etc/ssh/sshd_config && echo "✓ Root login disabled" || echo "✗ Root login enabled"
   grep -q "PasswordAuthentication no" /etc/ssh/sshd_config && echo "✓ Password auth disabled" || echo "✗ Password auth enabled"
   
   # Check firewall status
   echo "Firewall Status:"
   systemctl is-active firewalld && echo "✓ Firewall active" || echo "✗ Firewall inactive"
   
   # Check audit status
   echo "Audit Status:"
   systemctl is-active auditd && echo "✓ Audit active" || echo "✗ Audit inactive"
   
   # Check AppArmor status
   echo "AppArmor Status:"
   systemctl is-active apparmor && echo "✓ AppArmor active" || echo "✗ AppArmor inactive"
   
   # Check for security updates
   echo "Security Updates:"
   zypper lu --category security | grep -q "No updates found" && echo "✓ No security updates pending" || echo "⚠ Security updates available"
   EOF
   
   chmod +x /usr/local/bin/security-compliance-check.sh
   ```

## Maintenance and Updates

### Security Update Management

1. **Configure Automatic Security Updates**:
   ```bash
   # Configure transactional-update for security patches
   sudo tee /etc/systemd/system/transactional-update-security.service << EOF
   [Unit]
   Description=Transactional Update Security Patches
   After=network.target
   
   [Service]
   Type=oneshot
   ExecStart=/usr/sbin/transactional-update --continue --drop-if-no-change dup --category security
   
   [Install]
   WantedBy=multi-user.target
   EOF
   
   # Create timer for weekly security updates
   sudo tee /etc/systemd/system/transactional-update-security.timer << EOF
   [Unit]
   Description=Weekly Security Updates
   Requires=transactional-update-security.service
   
   [Timer]
   OnCalendar=Sun 02:00
   Persistent=true
   RandomizedDelaySec=1h
   
   [Install]
   WantedBy=timers.target
   EOF
   
   # Enable security update timer
   sudo systemctl enable transactional-update-security.timer
   sudo systemctl start transactional-update-security.timer
   ```

### Security Monitoring Maintenance

1. **Regular Security Health Checks**:
   ```bash
   # Schedule weekly security health checks
   echo "0 1 * * 0 /usr/local/bin/security-compliance-check.sh | mail -s 'Weekly Security Report' admin@homelab.local" | sudo crontab -
   ```

This comprehensive security hardening guide provides multi-layered protection for your home lab environment. Regular review and updates of these security measures are essential to maintain a strong security posture.