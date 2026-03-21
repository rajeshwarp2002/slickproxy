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
net.netfilter.nf_conntrack_max = 10000000
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


#!/bin/bash
echo "Adding iptables rules for ports 8086, 3086, 3000, and 11000..."

PORTS=(8086 3306 3000 11000)

# Add rules to iptables
for PORT in "${PORTS[@]}"; do
    sudo iptables -t mangle -I INPUT -p tcp --dport "$PORT" -j ACCEPT
done

# Persist the rules in /etc/rc.local
echo "Adding iptables rules to /etc/rc.local for persistence..."
if [ ! -f /etc/rc.local ]; then
    sudo tee /etc/rc.local > /dev/null <<'EOF'
#!/bin/bash
iptables -t mangle -I INPUT -p tcp --dport 8086 -j ACCEPT
iptables -t mangle -I INPUT -p tcp --dport 3306 -j ACCEPT
iptables -t mangle -I INPUT -p tcp --dport 3000 -j ACCEPT
iptables -t mangle -I INPUT -p tcp --dport 11000 -j ACCEPT
exit 0
EOF
    sudo chmod +x /etc/rc.local
else
    for PORT in "${PORTS[@]}"; do
        RULE="iptables -t mangle -I INPUT 12 -p tcp --dport $PORT -j ACCEPT"
        if ! grep -q "$RULE" /etc/rc.local; then
            sudo sed -i "/^exit 0/i $RULE" /etc/rc.local
        fi
    done
fi

echo "Done. Ports ${PORTS[*]} added and persisted."

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
#systemctl stop slickproxy
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

# -----------------------------
# iptables rule for port 11000
# -----------------------------

# -----------------------------
# Start SlickProxy
# -----------------------------
echo "Starting SlickProxy..."
sudo systemctl start slickproxy

echo "Setup complete! You may want to run 'sudo mysql_secure_installation' if not done yet."
