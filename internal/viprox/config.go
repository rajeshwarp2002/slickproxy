package viprox

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type Config struct {
	LogPath                 string `json:"log_path"`
	DebugLogFileName        string `json:"debug_log_file"`
	AccessLogFileName       string `json:"access_log_file"`
	EndpointConfFile        string `json:"endpoint_conf_file"`
	EndpointUrl             string `json:"endpoint_url"`
	AuthMapFile             string `json:"auth_map_file"`
	DBAuthPath              string `json:"db_auth_path"`
	IPAuthPath              string `json:"ip_auth_path"`
	AuthRefreshInterval     int    `json:"auth_refresh_interval"`
	EndpointRefreshInterval int    `json:"endpoint_refresh_interval"`
	RemoteProxyPortRange    string `json:"remote_proxy_port_range"`
	PeerRetryAttempts       int    `json:"peer_retry_attempts"`
	SamePeerRetryAttempts   int    `json:"same_peer_retry_attempts"`
	IdlePeerTimeout         int    `json:"idle_peer_timeout"`
	ConnectTimeout          int    `json:"connect_timeout"`
}

func LoadConfigOrDefault(path string) *Config {
	config, err := LoadConfig(path)
	if err != nil {
		log.Printf("⚠ Using default EndPointConfig due to error: %v", err)
		return &Config{
			LogPath:                 "/var/log/",
			DebugLogFileName:        "socks_to_http.log",
			AccessLogFileName:       "access_socks_to_http.log",
			EndpointConfFile:        "/etc/squid/endpoints.conf",
			AuthMapFile:             "",
			DBAuthPath:              "/dev/shm/squid_db_auth",
			IPAuthPath:              "/dev/shm/squid_ip_auth",
			AuthRefreshInterval:     10,
			EndpointRefreshInterval: 30,
			RemoteProxyPortRange:    "100000-150000",
			PeerRetryAttempts:       0,
		}
	}
	return config
}

func LoadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open EndPointConfig: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode EndPointConfig: %w", err)
	}

	return &config, nil
}
