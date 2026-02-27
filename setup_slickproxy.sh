#!/bin/bash
set -e

# -----------------------------
# Check if Ubuntu
# -----------------------------
if ! [ -f /etc/os-release ]; then
    echo "This script is only for Ubuntu."
    exit 1
fi

. /etc/os-release
if [ "$ID" != "ubuntu" ]; then
    echo "This script is only for Ubuntu. Detected: $ID"
    exit 1
fi

echo "Detected Ubuntu: $VERSION"

# -----------------------------
# Sysctl tuning
# -----------------------------
echo "Applying sysctl tuning..."
sudo tee /etc/sysctl.d/99-custom-tuning.conf > /dev/null <<EOF
net.core.somaxconn = 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.ip_local_port_range = 1024 65535
EOF

sudo sysctl --system

# -----------------------------
# Install InfluxDB
# -----------------------------
echo "Installing InfluxDB..."
sudo apt update
sudo apt install -y influxdb influxdb-client
sudo systemctl enable influxdb
sudo systemctl start influxdb

# Create database and retention policy
echo "Setting up InfluxDB database..."
influx -execute "CREATE DATABASE go_metrics;"
influx -execute "CREATE RETENTION POLICY \"7days\" ON \"go_metrics\" DURATION 7d REPLICATION 1 DEFAULT;"

# -----------------------------
# Install Grafana
# -----------------------------
echo "Installing Grafana..."
sudo apt install -y software-properties-common wget
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository -y "deb https://packages.grafana.com/oss/deb stable main"
sudo apt update
sudo apt install -y grafana
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl start grafana-server

# -----------------------------
# Install MySQL
# -----------------------------
echo "Installing MySQL..."
sudo apt install -y mysql-server
sudo systemctl start mysql
sudo systemctl enable mysql

echo "Please run 'sudo mysql_secure_installation' manually to secure MySQL."

# -----------------------------
# Setup SlickProxy service
# -----------------------------
echo "Setting up SlickProxy service..."

# Create directory
mkdir -p ~/slickproxy

# Copy binaries (assuming they are in current folder)
cp slickproxy.bin ~/slickproxy/slickproxy
cp config.json ~/slickproxy/
chmod 777 ~/slickproxy/slickproxy

# Create systemd service
sudo tee /etc/systemd/system/slickproxy.service > /dev/null <<EOF
[Unit]
Description=SlickProxy Service
After=network.target

[Service]
ExecStart=/root/slickproxy/slickproxy
WorkingDirectory=/root/slickproxy
Restart=always
RestartSec=3
User=root
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=HOME=/root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable slickproxy.service

# -----------------------------
# Initialize MySQL database and tables
# -----------------------------
echo "Creating SlickProxy database and tables..."
MYSQL_ROOT_PASS="your_password"  # <-- replace this
mysql -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}'; FLUSH PRIVILEGES;"
mysql -uroot -p${MYSQL_ROOT_PASS} <<EOF
CREATE DATABASE IF NOT EXISTS slickproxy;

USE slickproxy;

CREATE TABLE IF NOT EXISTS users(
  user VARCHAR(100) NOT NULL,
  password VARCHAR(35) NOT NULL DEFAULT '',
  proxyIP VARCHAR(45) NOT NULL DEFAULT '',
  proxyIPList LONGTEXT,
  proxyPort LONGTEXT,
  activeConnections INT NOT NULL DEFAULT 0,
  connectionsPerSecond INT NOT NULL DEFAULT 0,
  throughputPerSecond INT NOT NULL DEFAULT 0,
  totalQuota INT NOT NULL DEFAULT 0,
  quotaDuration VARCHAR(10) NOT NULL DEFAULT '',
  timeQuota INT NOT NULL DEFAULT 0,
  ipMode VARCHAR(20) NOT NULL DEFAULT '',
  ipRotation VARCHAR(20) NOT NULL DEFAULT '',
  portToIP LONGTEXT,
  whiteListIP LONGTEXT,
  rotationIntervalSec INT NOT NULL DEFAULT 0,
  bytesPerSecond BIGINT UNSIGNED DEFAULT 0,
  currentActiveConnections BIGINT UNSIGNED DEFAULT 0,
  totalUsedBytes BIGINT UNSIGNED DEFAULT 0,
  PRIMARY KEY (user)
);

CREATE TABLE IF NOT EXISTS blacklist(
  value VARCHAR(255) NOT NULL,
  type VARCHAR(255) NOT NULL,
  PRIMARY KEY(value, type)
);

CREATE TABLE IF NOT EXISTS listenports(
  port INT NOT NULL UNIQUE
);

INSERT INTO listenports (port) VALUES (4567);
EOF

# -----------------------------
# Start SlickProxy
# -----------------------------
echo "Starting SlickProxy..."
sudo systemctl start slickproxy

echo "Setup complete! You may want to run 'sudo mysql_secure_installation' if not done yet."
