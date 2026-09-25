# SecureChat Production Deployment Guide

**Version:** 1.0  
**Last Updated:** September 25, 2026  
**Target Audience:** System Administrators, DevOps Engineers

## Overview

This guide covers deploying SecureChat in a production environment with proper security hardening, monitoring, and operational procedures.

⚠️ **IMPORTANT:** Complete a professional security audit before production deployment.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Server Deployment](#server-deployment)
3. [TLS/SSL Configuration](#tlsssl-configuration)
4. [Security Hardening](#security-hardening)
5. [Monitoring & Logging](#monitoring--logging)
6. [Backup & Recovery](#backup--recovery)
7. [Performance Tuning](#performance-tuning)
8. [Operational Procedures](#operational-procedures)
9. [Incident Response](#incident-response)

---

## Prerequisites

### Hardware Requirements

**Minimum (< 100 users):**
- CPU: 2 cores @ 2.0 GHz
- RAM: 2 GB
- Disk: 20 GB SSD
- Network: 10 Mbps

**Recommended (1000 users):**
- CPU: 4 cores @ 2.5 GHz
- RAM: 8 GB
- Disk: 100 GB SSD
- Network: 100 Mbps

**Enterprise (10,000+ users):**
- CPU: 8+ cores @ 3.0 GHz
- RAM: 16+ GB
- Disk: 500 GB SSD (RAID 10)
- Network: 1 Gbps
- Load balancer required

### Software Requirements

**Operating System:**
- Ubuntu 22.04 LTS (recommended)
- Debian 11+
- CentOS 8+
- RHEL 8+

**Python:**
- Version: 3.9 or higher
- Virtual environment recommended

**Database:**
- SQLite 3.35+ (development/small deployments)
- PostgreSQL 13+ (production recommended)

**TLS Certificate:**
- Valid SSL/TLS certificate from trusted CA
- Or Let's Encrypt (free, automated)

### Network Requirements

**Ports:**
- 443/tcp (HTTPS/WSS) - Client connections
- 80/tcp (HTTP) - Let's Encrypt validation only
- 22/tcp (SSH) - Administration (restrict to admin IPs)

**Firewall:**
- Allow inbound: 443, 80 (optional)
- Allow outbound: DNS (53), NTP (123), updates
- Block all other inbound traffic

**DNS:**
- A record: securechat.example.com → server IP
- AAAA record: (if IPv6)

---

## Server Deployment

### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3.9 python3-pip python3-venv \
    nginx certbot python3-certbot-nginx \
    postgresql postgresql-contrib \
    supervisor git build-essential

# Create service user (no login shell)
sudo useradd -r -s /bin/false securechat

# Create directories
sudo mkdir -p /opt/securechat
sudo mkdir -p /var/log/securechat
sudo mkdir -p /var/lib/securechat

# Set permissions
sudo chown -R securechat:securechat /opt/securechat
sudo chown -R securechat:securechat /var/log/securechat
sudo chown -R securechat:securechat /var/lib/securechat
```

### 2. Install SecureChat

```bash
# Clone repository
cd /opt/securechat
sudo -u securechat git clone https://github.com/yourusername/securechat.git .

# Create virtual environment
sudo -u securechat python3 -m venv venv

# Install dependencies
sudo -u securechat venv/bin/pip install -e .
sudo -u securechat venv/bin/pip install gunicorn psycopg2-binary
```

### 3. Database Setup (PostgreSQL)

```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE securechat;
CREATE USER securechat WITH PASSWORD 'CHANGE_THIS_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE securechat TO securechat;
\q

# Configure connection
cat > /opt/securechat/config/database.conf << EOF
DATABASE_URL=postgresql://securechat:CHANGE_THIS_PASSWORD@localhost/securechat
EOF

# Secure permissions
chmod 600 /opt/securechat/config/database.conf
chown securechat:securechat /opt/securechat/config/database.conf
```

### 4. Application Configuration

```bash
# Create configuration file
sudo -u securechat cat > /opt/securechat/config/production.env << EOF
# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8000
SERVER_URL=wss://securechat.example.com

# Database
DATABASE_URL=postgresql://securechat:PASSWORD@localhost/securechat

# Security
SESSION_TIMEOUT=1800
MAX_MESSAGE_SIZE=1048576
MAX_CONNECTIONS_PER_IP=10

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/securechat/server.log

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_MESSAGES_PER_MINUTE=60
RATE_LIMIT_CONNECTIONS_PER_HOUR=100
EOF

# Secure configuration
chmod 600 /opt/securechat/config/production.env
```

### 5. Systemd Service

```bash
# Create service file
sudo cat > /etc/systemd/system/securechat.service << EOF
[Unit]
Description=SecureChat Server
After=network.target postgresql.service

[Service]
Type=simple
User=securechat
Group=securechat
WorkingDirectory=/opt/securechat
EnvironmentFile=/opt/securechat/config/production.env

ExecStart=/opt/securechat/venv/bin/python -m src.server.main

Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/securechat /var/lib/securechat

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable securechat
sudo systemctl start securechat

# Check status
sudo systemctl status securechat
```

---

## TLS/SSL Configuration

### Option 1: Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d securechat.example.com

# Auto-renewal (certbot installs this automatically)
sudo systemctl status certbot.timer
```

### Option 2: Custom Certificate

```bash
# Copy certificate files
sudo cp your-cert.pem /etc/ssl/certs/securechat.crt
sudo cp your-key.pem /etc/ssl/private/securechat.key
sudo cp ca-chain.pem /etc/ssl/certs/securechat-ca.crt

# Set permissions
sudo chmod 644 /etc/ssl/certs/securechat.crt
sudo chmod 600 /etc/ssl/private/securechat.key
sudo chown root:root /etc/ssl/private/securechat.key
```

### Nginx Reverse Proxy

```bash
# Create nginx configuration
sudo cat > /etc/nginx/sites-available/securechat << 'EOF'
# Rate limiting
limit_req_zone $binary_remote_addr zone=securechat_req:10m rate=60r/m;
limit_conn_zone $binary_remote_addr zone=securechat_conn:10m;

# Upstream WebSocket server
upstream securechat_backend {
    server 127.0.0.1:8000;
    keepalive 64;
}

# HTTP -> HTTPS redirect
server {
    listen 80;
    listen [::]:80;
    server_name securechat.example.com;
    
    # Let's Encrypt validation
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    
    # Redirect to HTTPS
    location / {
        return 301 https://$server_name$request_uri;
    }
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name securechat.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/securechat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/securechat.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;
    
    # Rate limiting
    limit_req zone=securechat_req burst=20 nodelay;
    limit_conn securechat_conn 10;
    
    # WebSocket proxy
    location / {
        proxy_pass http://securechat_backend;
        proxy_http_version 1.1;
        
        # WebSocket headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 7d;
        proxy_send_timeout 7d;
        proxy_read_timeout 7d;
        
        # Buffer settings
        proxy_buffering off;
        proxy_request_buffering off;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/securechat /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default  # Remove default site

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

---

## Security Hardening

### 1. Firewall Configuration (UFW)

```bash
# Install and enable UFW
sudo apt install ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (change 22 if using non-standard port)
sudo ufw allow 22/tcp

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

### 2. Fail2Ban

```bash
# Install fail2ban
sudo apt install fail2ban

# Configure for SecureChat
sudo cat > /etc/fail2ban/jail.d/securechat.conf << EOF
[securechat]
enabled = true
port = 443
filter = securechat
logpath = /var/log/securechat/server.log
maxretry = 5
bantime = 3600
findtime = 600
EOF

# Create filter
sudo cat > /etc/fail2ban/filter.d/securechat.conf << EOF
[Definition]
failregex = Failed authentication.*<HOST>
            Connection refused.*<HOST>
            Rate limit exceeded.*<HOST>
ignoreregex =
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

### 3. System Hardening

```bash
# Disable root login
sudo passwd -l root

# Configure automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# Install security tools
sudo apt install -y rkhunter chkrootkit lynis

# Run security audit
sudo lynis audit system
```

### 4. PostgreSQL Hardening

```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/13/main/postgresql.conf

# Set:
# listen_addresses = 'localhost'
# ssl = on
# password_encryption = scram-sha-256

# Edit pg_hba.conf
sudo nano /etc/postgresql/13/main/pg_hba.conf

# Change:
# local   all             all                                     scram-sha-256
# host    all             all             127.0.0.1/32            scram-sha-256

# Restart PostgreSQL
sudo systemctl restart postgresql
```

---

## Monitoring & Logging

### 1. Log Configuration

```bash
# Configure log rotation
sudo cat > /etc/logrotate.d/securechat << EOF
/var/log/securechat/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 securechat securechat
    sharedscripts
    postrotate
        systemctl reload securechat > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 2. Prometheus Metrics

```bash
# Install prometheus node exporter
sudo apt install prometheus-node-exporter

# Configure SecureChat metrics endpoint
# Add to server configuration:
# METRICS_ENABLED=true
# METRICS_PORT=9090
```

### 3. Monitoring Dashboard

**Grafana Installation:**
```bash
# Install Grafana
sudo apt-get install -y software-properties-common
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo apt update
sudo apt install grafana

# Start Grafana
sudo systemctl start grafana-server
sudo systemctl enable grafana-server
```

**Key Metrics to Monitor:**
- Active WebSocket connections
- Messages per second
- Database query latency
- CPU and memory usage
- Disk I/O
- Network throughput
- Failed authentication attempts

### 4. Alerting

```bash
# Install alerting tools
sudo apt install mailutils

# Configure alerts (example)
sudo cat > /usr/local/bin/securechat-alert << 'EOF'
#!/bin/bash
if [ $(systemctl is-active securechat) != "active" ]; then
    echo "SecureChat service is down!" | mail -s "ALERT: SecureChat Down" admin@example.com
fi
EOF

chmod +x /usr/local/bin/securechat-alert

# Add to crontab
echo "*/5 * * * * /usr/local/bin/securechat-alert" | sudo crontab -
```

---

## Backup & Recovery

### 1. Database Backup

```bash
# Create backup script
sudo cat > /usr/local/bin/securechat-backup << 'EOF'
#!/bin/bash
BACKUP_DIR="/var/backups/securechat"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup PostgreSQL
sudo -u postgres pg_dump securechat | gzip > $BACKUP_DIR/securechat_$DATE.sql.gz

# Backup configuration
tar czf $BACKUP_DIR/config_$DATE.tar.gz /opt/securechat/config/

# Keep only last 30 days
find $BACKUP_DIR -type f -mtime +30 -delete

# Upload to S3 (optional)
# aws s3 cp $BACKUP_DIR/securechat_$DATE.sql.gz s3://your-bucket/backups/
EOF

chmod +x /usr/local/bin/securechat-backup

# Schedule daily backups at 2 AM
echo "0 2 * * * /usr/local/bin/securechat-backup" | sudo crontab -
```

### 2. Restore Procedure

```bash
# Stop service
sudo systemctl stop securechat

# Restore database
gunzip < /var/backups/securechat/securechat_YYYYMMDD.sql.gz | sudo -u postgres psql securechat

# Restore configuration
tar xzf /var/backups/securechat/config_YYYYMMDD.tar.gz -C /

# Start service
sudo systemctl start securechat
```

---

## Performance Tuning

### 1. PostgreSQL Optimization

```bash
# Edit postgresql.conf
sudo nano /etc/postgresql/13/main/postgresql.conf

# Recommended settings (adjust based on RAM):
shared_buffers = 2GB                    # 25% of RAM
effective_cache_size = 6GB              # 75% of RAM
maintenance_work_mem = 512MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1                  # For SSD
effective_io_concurrency = 200          # For SSD
work_mem = 16MB
min_wal_size = 1GB
max_wal_size = 4GB
max_worker_processes = 4
max_parallel_workers_per_gather = 2
max_parallel_workers = 4

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### 2. Nginx Optimization

```bash
# Edit /etc/nginx/nginx.conf
sudo nano /etc/nginx/nginx.conf

# Add/modify:
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    keepalive_requests 100;
    
    # Buffer sizes
    client_body_buffer_size 128k;
    client_max_body_size 1m;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    output_buffers 1 32k;
    postpone_output 1460;
}
```

### 3. System Limits

```bash
# Increase file descriptor limits
sudo cat >> /etc/security/limits.conf << EOF
securechat soft nofile 65535
securechat hard nofile 65535
EOF

# Increase system limits
sudo cat >> /etc/sysctl.conf << EOF
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
EOF

sudo sysctl -p
```

---

## Operational Procedures

### 1. Health Checks

```bash
# Check service status
sudo systemctl status securechat

# Check logs
sudo journalctl -u securechat -f

# Check connections
sudo netstat -an | grep :8000

# Check database
sudo -u postgres psql securechat -c "SELECT COUNT(*) FROM users;"
```

### 2. Updates

```bash
# Update procedure
cd /opt/securechat

# Backup first
/usr/local/bin/securechat-backup

# Pull updates
sudo -u securechat git pull

# Update dependencies
sudo -u securechat venv/bin/pip install -e .

# Run migrations (if any)
sudo -u securechat venv/bin/python manage.py migrate

# Restart service
sudo systemctl restart securechat

# Verify
sudo systemctl status securechat
```

### 3. Scaling

**Vertical Scaling:**
- Upgrade server resources
- Tune PostgreSQL
- Increase worker processes

**Horizontal Scaling:**
- Deploy multiple servers
- Use load balancer (HAProxy, AWS ELB)
- Share PostgreSQL database
- Use Redis for session storage

---

## Incident Response

### 1. Service Down

```bash
# Check status
sudo systemctl status securechat

# Check logs
sudo tail -100 /var/log/securechat/server.log

# Restart service
sudo systemctl restart securechat

# If database issue:
sudo systemctl status postgresql
sudo journalctl -u postgresql -f
```

### 2. High CPU/Memory

```bash
# Check resource usage
top
htop

# Check connections
sudo netstat -an | grep :8000 | wc -l

# Check database
sudo -u postgres psql securechat -c "SELECT * FROM pg_stat_activity;"

# Restart if necessary
sudo systemctl restart securechat
```

### 3. Security Breach

**Immediate Actions:**
1. Isolate affected systems
2. Change all credentials
3. Review logs for unauthorized access
4. Notify users
5. Engage security team

**Post-Incident:**
1. Root cause analysis
2. Patch vulnerabilities
3. Update security measures
4. Document lessons learned

---

## Production Checklist

### Pre-Launch
- [ ] Security audit completed
- [ ] TLS certificate installed
- [ ] Firewall configured
- [ ] Backups automated and tested
- [ ] Monitoring configured
- [ ] Alerting configured
- [ ] Load testing completed
- [ ] Disaster recovery plan documented
- [ ] Incident response plan documented

### Post-Launch
- [ ] Monitor logs daily
- [ ] Review metrics weekly
- [ ] Test backups monthly
- [ ] Apply security updates promptly
- [ ] Review access logs monthly
- [ ] Conduct security audit annually

---

## Troubleshooting

### Common Issues

**Issue: WebSocket connections fail**
```bash
# Check nginx configuration
sudo nginx -t

# Check if port is listening
sudo netstat -tlnp | grep :443

# Check certificates
sudo certbot certificates
```

**Issue: Database connection errors**
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connections
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Restart database
sudo systemctl restart postgresql
```

**Issue: High memory usage**
```bash
# Check processes
ps aux --sort=-%mem | head

# Clear cache if needed
sync && echo 3 | sudo tee /proc/sys/vm/drop_caches
```

---

## Compliance & Legal

### GDPR Compliance
- Implement user data export
- Implement user data deletion
- Document data processing
- Implement consent mechanisms

### Data Retention
- Messages: Delete after delivery + 30 days
- User accounts: Keep while active
- Logs: Retain for 90 days
- Backups: Retain for 30 days

### Legal Requirements
- Terms of Service
- Privacy Policy
- Data Processing Agreement
- Warrant canary (optional)

---

## Support & Maintenance

### Regular Maintenance

**Daily:**
- Check service status
- Review error logs
- Monitor resource usage

**Weekly:**
- Review security logs
- Check backup integrity
- Update dashboard

**Monthly:**
- Apply security updates
- Review access controls
- Test disaster recovery

**Quarterly:**
- Security audit
- Performance review
- Capacity planning

---

## Additional Resources

- **Documentation:** `/opt/securechat/docs/`
- **Security Guide:** `docs/SECURITY_GUIDE.md`
- **Audit Checklist:** `docs/SECURITY_AUDIT_CHECKLIST.md`
- **Threat Model:** `docs/THREAT_MODEL.md`

---

**Version:** 1.0  
**Last Updated:** September 25, 2026  
**Maintained By:** SecureChat Operations Team
