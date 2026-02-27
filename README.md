CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o slickproxy main.go
go install mvdan.cc/garble@latest
export PATH=$PATH:/root/go/bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 garble -literals -tiny build -trimpath -ldflags="-s -w -buildid=" -o slickproxy .
echo "net.core.somaxconn = 65535" | sudo tee /etc/sysctl.d/99-custom-tuning.conf
echo "net.ipv4.tcp_tw_reuse = 1"   | sudo tee -a /etc/sysctl.d/99-custom-tuning.conf
echo "net.ipv4.tcp_fin_timeout = 10" | sudo tee -a /etc/sysctl.d/99-custom-tuning.conf
echo "net.ipv4.ip_local_port_range = 1024 65535" | sudo tee -a /etc/sysctl.d/99-custom-tuning.conf
sudo sysctl --system


sudo apt update
sudo apt install influxdb
sudo systemctl enable influxdb
sudo systemctl start influxdb
apt install influxdb-client
apt install influxdb-client
influx

CREATE DATABASE go_metrics;
CREATE RETENTION POLICY "7days" ON "go_metrics" DURATION 7d REPLICATION 1 DEFAULT;


sudo apt update
sudo apt install -y software-properties-common wget
sudo wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
sudo add-apt-repository "deb https://packages.grafana.com/oss/deb stable main"


sudo apt update
sudo apt install grafana -y
sudo systemctl daemon-reload
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server

 cd /etc/systemd/system/
vi slickproxy.service

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

sudo systemctl daemon-reload
sudo systemctl enable mysql
sudo systemctl enable slickproxy.service






