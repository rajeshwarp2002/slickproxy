package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var Cfg *Config

func ValidatePort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	return p >= 1 && p <= 65535
}

func ParsePorts(portStr string) ([]int, error) {
	var ports []int
	portStr = strings.TrimSpace(portStr)
	if strings.Contains(portStr, "-") {
		parts := strings.SplitN(portStr, "-", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range: %s", portStr)
		}
		startPort, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
		endPort, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
		if errStart != nil || errEnd != nil {
			return nil, fmt.Errorf("invalid port range: %s", portStr)
		}
		if startPort < 1 || endPort > 65535 || startPort > endPort {
			return nil, fmt.Errorf("invalid port range values: %s", portStr)
		}
		for p := startPort; p <= endPort; p++ {
			ports = append(ports, p)
		}
	} else {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

func ValidateSubnet(subnet string) bool {
	_, ipnet, err := net.ParseCIDR(subnet)
	if err != nil {
		return false
	}

	_, bits := ipnet.Mask.Size()

	if ipnet.IP.To4() != nil {

		if bits < 0 || bits > 32 {
			return false
		}
	} else if ipnet.IP.To16() != nil {

		if bits < 0 || bits > 128 {
			return false
		}
	} else {
		return false
	}

	return true
}

func ExecuteCommand(subnet string) error {

	if !ValidateSubnet(subnet) {
		log.Printf("Invalid subnet: %s", subnet)
		return fmt.Errorf("invalid subnet: %s", subnet)
	}

	ip, _, err := net.ParseCIDR(subnet)
	if err != nil {
		log.Printf("Error parsing subnet %s: %v", subnet, err)
		return fmt.Errorf("error parsing subnet %s: %v", subnet, err)
	}

	if ip.To4() != nil {

		cmd := exec.Command("ip", "route", "add", "to", "local", subnet, "dev", "lo")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error executing IPv4 command: %v", err)
		}
		fmt.Println("IPv4 route added successfully")
	} else {

		cmd := exec.Command("ip", "-6", "route", "add", "to", "local", subnet, "dev", "lo")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error executing IPv6 command: %v", err)
		}
		fmt.Println("IPv6 route added successfully")
	}
	return nil
}

func LoadConfig(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	err = json.Unmarshal(bytes, &Cfg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config JSON: %w", err)
	}

	for _, port := range Cfg.Ports {
		if ValidatePort(port) {
			log.Printf("Valid port: %s", port)
		} else {
			log.Printf("Invalid port: %s", port)
		}
	}

	for _, subnet := range Cfg.Subnets {
		if ValidateSubnet(subnet) {
			log.Printf("Valid subnet: %s", subnet)
		} else {
			log.Printf("Invalid subnet: %s", subnet)
		}
	}

	if Cfg.Server.MaxSessions <= 0 {
		Cfg.Server.MaxSessions = 20000000
	}
	if Cfg.Server.DefaultSessionTTL <= 0 {
		Cfg.Server.DefaultSessionTTL = 24 * 3600
	}

	log.Println("Config loaded successfully, loading subnets...")

	for _, subnet := range Cfg.Subnets {
		if err := ExecuteCommand(subnet); err != nil {
			fmt.Printf("Failed to execute command for subnet %s: %v\n", subnet, err)
		}
	}

	if err := validateDBField(Cfg.DB.Connection); err != nil {
		return fmt.Errorf("invalid db.connection field: %w", err)
	}

	for _, entry := range Cfg.Proxies {
		entry.Key = fmt.Sprintf("%s:%d", entry.IP, entry.Port)
		entry.RateLimiter = NewRateLimiter(uint64(entry.BytesPerSecond))
		Cfg.ProxyTable = append(Cfg.ProxyTable, entry)
	}
	Cfg.Server.Retry.MaxRetries = 3

	portSet := make(map[int]struct{})
	for _, portStr := range Cfg.Ports {
		parsedPorts, err := ParsePorts(portStr)
		if err != nil {
			log.Printf("Invalid port or range: %s (%v)", portStr, err)
			continue
		}
		for _, p := range parsedPorts {
			portSet[p] = struct{}{}
		}
	}

	Cfg.Ports = Cfg.Ports[:0]
	for p := range portSet {
		Cfg.Ports = append(Cfg.Ports, strconv.Itoa(p))
	}

	return nil
}

func validateDBField(db string) error {
	host, port, err := net.SplitHostPort(db)
	if err != nil {
		return fmt.Errorf("invalid db connection format, must be <IP>:<port>")
	}

	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address in db connection")
	}

	if _, err := fmt.Sscanf(port, "%d", new(int)); err != nil {
		return fmt.Errorf("invalid port in db connection")
	}

	return nil
}

type UserMetrics struct {
	ActiveConnections int64
	TotalUsers        int64
	ActiveUsers       int64
	Throughput        int64
}

var UserMetricsObj UserMetrics

func GetUserMetrics() *UserMetrics {
	return &UserMetricsObj
}
