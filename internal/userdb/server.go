package userdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"slickproxy/internal/config"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/sys/unix"
)

type DB struct {
	Connection *sql.DB
}

type SystemMetrics struct {
	CPU struct {
		Percent float64 `json:"percent"`
	} `json:"cpu"`
	RAM struct {
		Total       uint64  `json:"total"`
		Available   uint64  `json:"available"`
		Used        uint64  `json:"used"`
		UsedPercent float64 `json:"usedPercent"`
	} `json:"ram"`
}

func (db *DB) GetMetrics(w http.ResponseWriter, r *http.Request) {

	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get CPU metrics: %v", err), http.StatusInternalServerError)
		return
	}

	memStats, err := mem.VirtualMemory()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get RAM metrics: %v", err), http.StatusInternalServerError)
		return
	}

	metrics := SystemMetrics{}
	if len(cpuPercent) > 0 {
		metrics.CPU.Percent = cpuPercent[0]
	}
	metrics.RAM.Total = memStats.Total
	metrics.RAM.Available = memStats.Available
	metrics.RAM.Used = memStats.Used
	metrics.RAM.UsedPercent = memStats.UsedPercent

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(metrics)
}

func validateIPList(ipList string) error {
	if ipList != "" {
		ips := strings.Split(ipList, ",")
		for _, ip := range ips {
			if strings.Contains(ip, "/") {
				ip = strings.Split(ip, "/")[0]
			}
			if net.ParseIP(ip) == nil {
				return errors.New("invalid IP in proxyIPList")
			}
		}
	}
	return nil
}

func validatePortRange(port string) error {
	if port != "" {
		ports := strings.Split(port, "-")
		if len(ports) > 2 {
			return errors.New("invalid port range")
		}

		for _, p := range ports {
			portNum, err := strconv.Atoi(p)
			if err != nil || portNum < 1 || portNum > 65535 {
				return errors.New("port out of range")
			}
		}
	}
	return nil
}

func validateIPMode(mode string) error {
	validModes := map[string]bool{"IPv4": true, "IPv6": true, "IPv4v6": true}
	if !validModes[mode] {
		return errors.New("invalid ipMode value")
	}
	return nil
}

func Authenticate(w http.ResponseWriter, r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "admin" || pass != "aZ8kL2pQwX" {
		w.Header().Set("WWW-Authenticate", "Basic realm=Restricted")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return false
	}
	return true
}

func (db *DB) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user struct {
		User                 string `json:"user" binding:"required"`
		Password             string `json:"password" binding:"required"`
		ProxyIPList          string `json:"proxyIPList"`
		ProxyPort            string `json:"proxyPort"`
		ActiveConnections    int    `json:"activeConnections"`
		ConnectionsPerSecond int    `json:"connectionsPerSecond"`
		ThroughputPerSecond  int    `json:"throughputPerSecond"`
		TotalQuota           int    `json:"totalQuota"`
		QuotaDuration        int64  `json:"quotaDuration"`
		TimeQuota            int64  `json:"timeQuota"`
		IpMode               string `json:"ipMode"`
		IpRotation           string `json:"ipRotation"`
		PortToIP             string `json:"portToIP"`
		WhiteListIP          string `json:"whiteListIP"`
		RotationIntervalSec  int    `json:"rotationIntervalSec"`
		ProxyIP              string `json:"proxyIP"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, fmt.Sprintf("Invalid input: %v", err), http.StatusBadRequest)
		return
	}

	if user.ProxyIP != "" && !isValidIPv4(user.ProxyIP) {
		http.Error(w, "proxyIP must be a valid IPv4 address", http.StatusBadRequest)
		return
	}

	if user.ProxyIPList != "" {

		if err := validateIPList(user.ProxyIPList); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if user.PortToIP != "" {
		mappings := strings.Split(user.PortToIP, ",")
		for _, mapping := range mappings {
			mapping = strings.TrimSpace(mapping)
			parts := strings.Split(mapping, ":")
			if len(parts) != 2 {
				http.Error(w, fmt.Sprintf("Invalid portToIP entry: %s", mapping), http.StatusBadRequest)
				return
			}
			portStr := strings.TrimSpace(parts[0])
			ip := strings.TrimSpace(parts[1])
			portNum, err := strconv.Atoi(portStr)
			if err != nil || portNum < 1 || portNum > 65535 {
				http.Error(w, fmt.Sprintf("Invalid port in portToIP: %s", portStr), http.StatusBadRequest)
				return
			}
			if !isValidIPv4(ip) {
				http.Error(w, fmt.Sprintf("Invalid IPv4 in portToIP: %s", ip), http.StatusBadRequest)
				return
			}
		}
	}

	if user.PortToIP == "" && config.Cfg.General.LB == false {
		if user.ProxyPort == "" {
			http.Error(w, "proxyPort is required if portToIP is not present", http.StatusBadRequest)
			return
		}
		if err := validatePortRange(user.ProxyPort); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if user.IpMode != "" {
		if err := validateIPMode(user.IpMode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	if user.TimeQuota != 0 && user.TimeQuota < time.Now().Unix() {
		currentTime := time.Now().Unix()
		secondsInADay := int64(24 * 60 * 60)
		user.QuotaDuration = user.TimeQuota
		user.TimeQuota = currentTime + int64(user.TimeQuota)*secondsInADay
	}

	query := `INSERT INTO users (user, password, proxyIPList, proxyPort, activeConnections,
        connectionsPerSecond, throughputPerSecond, totalQuota, quotaDuration, timeQuota, ipMode,
        ipRotation, portToIP, whiteListIP, rotationIntervalSec, proxyIP) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := db.Connection.Exec(query, user.User, user.Password, user.ProxyIPList, user.ProxyPort, user.ActiveConnections,
		user.ConnectionsPerSecond, user.ThroughputPerSecond, user.TotalQuota, user.QuotaDuration, user.TimeQuota,
		user.IpMode, user.IpRotation, user.PortToIP, user.WhiteListIP, user.RotationIntervalSec, user.ProxyIP)
	if err != nil {
		log.Printf("Failed to create record: %v", err)
		http.Error(w, fmt.Sprintf("Failed to create record: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Record created successfully"}`))
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
}

func (db *DB) GetUser(w http.ResponseWriter, r *http.Request) {

	username := r.URL.Query().Get("user")
	log.Println("Retrieved password for user:", username)
	query := `SELECT * FROM users WHERE user = ?`
	row := db.Connection.QueryRow(query, username)

	var user struct {
		User                     string
		Password                 string
		ProxyIPList              string
		ProxyPort                string
		ActiveConnections        int
		ConnectionsPerSecond     int
		ThroughputPerSecond      int
		TotalQuota               int
		QuotaDuration            string
		TimeQuota                int
		IpMode                   string
		IpRotation               string
		PortToIP                 string
		WhiteListIP              string
		RotationIntervalSec      int
		ProxyIP                  string
		BytesPerSecond           uint64
		CurrentActiveConnections uint64
		TotalUsedBytes           uint64
		TimeQuotaReadable        string
	}

	err := row.Scan(&user.User, &user.Password, &user.ProxyIPList, &user.ProxyPort, &user.ActiveConnections,
		&user.ConnectionsPerSecond, &user.ThroughputPerSecond, &user.TotalQuota, &user.QuotaDuration, &user.TimeQuota,
		&user.IpMode, &user.IpRotation, &user.PortToIP, &user.WhiteListIP, &user.RotationIntervalSec,
		&user.ProxyIP, &user.BytesPerSecond, &user.CurrentActiveConnections, &user.TotalUsedBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Failed to retrieve user: %v", err), http.StatusInternalServerError)
		}
		return
	}

	if user.TimeQuota != 0 {
		user.TimeQuotaReadable = time.Unix(int64(user.TimeQuota), 0).Format("2006-01-02 15:04:05")
	} else {
		user.TimeQuotaReadable = "Not Set"
	}

	response, err := json.Marshal(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (db *DB) GetUserLive(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")

	log.Println("Retrieved password for user:", username)
	query := `SELECT password FROM users WHERE user = ?`
	row := db.Connection.QueryRow(query, username)
	var password string
	if err := row.Scan(&password); err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("Failed to retrieve password: %v", err), http.StatusInternalServerError)
		return
	}

	log.Println("Retrieved password for user:", username, password)
	user, exists := (*Users)[username+":"+password]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	response, err := json.Marshal(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (db *DB) GetAllUsers(w http.ResponseWriter, r *http.Request) {
	query := `SELECT * FROM users`
	rows, err := db.Connection.Query(query)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to retrieve records: %v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []map[string]interface{}

	for rows.Next() {
		var user struct {
			User                     string
			Password                 string
			ProxyIP                  string
			ProxyIPList              string
			ProxyPort                string
			ActiveConnections        int
			ConnectionsPerSecond     int
			ThroughputPerSecond      int
			TotalQuota               int
			QuotaDuration            string
			TimeQuota                int
			IpMode                   string
			IpRotation               string
			PortToIP                 string
			WhiteListIP              string
			RotationIntervalSec      int
			BytesPerSecond           uint64
			CurrentActiveConnections uint64
			TotalUsedBytes           uint64
			TimeQuotaReadable        string
		}

		if err := rows.Scan(&user.User, &user.Password, &user.ProxyIP, &user.ProxyIPList, &user.ProxyPort, &user.ActiveConnections,
			&user.ConnectionsPerSecond, &user.ThroughputPerSecond, &user.TotalQuota, &user.QuotaDuration, &user.TimeQuota,
			&user.IpMode, &user.IpRotation, &user.PortToIP, &user.WhiteListIP, &user.RotationIntervalSec,
			&user.BytesPerSecond, &user.CurrentActiveConnections, &user.TotalUsedBytes); err != nil {
			http.Error(w, fmt.Sprintf("Failed to parse records: %v", err), http.StatusInternalServerError)
			return
		}

		if user.TimeQuota != 0 {
			user.TimeQuotaReadable = time.Unix(int64(user.TimeQuota), 0).Format("2006-01-02 15:04:05")
		} else {
			user.TimeQuotaReadable = "Not Set"
		}

		users = append(users, map[string]interface{}{
			"user":                     user.User,
			"password":                 user.Password,
			"proxyIPList":              user.ProxyIPList,
			"proxyPort":                user.ProxyPort,
			"activeConnections":        user.ActiveConnections,
			"connectionsPerSecond":     user.ConnectionsPerSecond,
			"throughputPerSecond":      user.ThroughputPerSecond,
			"totalQuota":               user.TotalQuota,
			"quotaDuration":            user.QuotaDuration,
			"timeQuota":                user.TimeQuota,
			"timeQuotaReadable":        user.TimeQuotaReadable,
			"ipMode":                   user.IpMode,
			"ipRotation":               user.IpRotation,
			"portToIP":                 user.PortToIP,
			"whiteListIP":              user.WhiteListIP,
			"rotationIntervalSec":      user.RotationIntervalSec,
			"proxyIP":                  user.ProxyIP,
			"bytesPerSecond":           user.BytesPerSecond,
			"currentActiveConnections": user.CurrentActiveConnections,
			"totalUsedBytes":           user.TotalUsedBytes,
		})
	}

	response, err := json.Marshal(users)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to serialize response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(response)
}

func (db *DB) UpdateUser(w http.ResponseWriter, r *http.Request) {
	var user struct {
		Password             *string `json:"password"`
		ProxyIPList          *string `json:"proxyIPList"`
		ProxyPort            *string `json:"proxyPort"`
		ActiveConnections    *int    `json:"activeConnections"`
		ConnectionsPerSecond *int    `json:"connectionsPerSecond"`
		ThroughputPerSecond  *int    `json:"throughputPerSecond"`
		TotalQuota           *int    `json:"totalQuota"`
		QuotaDuration        *string `json:"quotaDuration"`
		TimeQuota            *int    `json:"timeQuota"`
		IpMode               *string `json:"ipMode"`
		IpRotation           *string `json:"ipRotation"`
		PortToIP             *string `json:"portToIP"`
		WhiteListIP          *string `json:"whiteListIP"`
		RotationIntervalSec  *int    `json:"rotationIntervalSec"`
		ProxyIP              *string `json:"proxyIP"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON input", http.StatusBadRequest)
		return
	}

	username := r.URL.Query().Get("user")
	if username == "" {
		http.Error(w, "Missing 'user' query parameter", http.StatusBadRequest)
		return
	}

	var fields []string
	var args []interface{}

	if user.Password != nil {
		fields = append(fields, "password=?")
		args = append(args, *user.Password)
	}
	if user.ProxyIPList != nil {
		if err := validateIPList(*user.ProxyIPList); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fields = append(fields, "proxyIPList=?")
		args = append(args, *user.ProxyIPList)
	}
	if user.ProxyPort != nil {
		if err := validatePortRange(*user.ProxyPort); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fields = append(fields, "proxyPort=?")
		args = append(args, *user.ProxyPort)
	}
	if user.ActiveConnections != nil {
		fields = append(fields, "activeConnections=?")
		args = append(args, *user.ActiveConnections)
	}
	if user.ConnectionsPerSecond != nil {
		fields = append(fields, "connectionsPerSecond=?")
		args = append(args, *user.ConnectionsPerSecond)
	}
	if user.ThroughputPerSecond != nil {
		fields = append(fields, "throughputPerSecond=?")
		args = append(args, *user.ThroughputPerSecond)
	}
	if user.TotalQuota != nil {
		fields = append(fields, "totalQuota=?")
		args = append(args, *user.TotalQuota)
	}
	if user.QuotaDuration != nil {
		fields = append(fields, "quotaDuration=?")
		args = append(args, *user.QuotaDuration)
	}
	if user.TimeQuota != nil {
		currentTime := time.Now().Unix()
		if *user.TimeQuota < int(currentTime) {
			secondsInADay := int64(24 * 60 * 60)
			timeQuota := int(currentTime) + *user.TimeQuota*int(secondsInADay)
			fields = append(fields, "timeQuota=?")
			args = append(args, timeQuota)
		} else {
			fields = append(fields, "timeQuota=?")
			args = append(args, *user.TimeQuota)
		}
	}
	if user.IpMode != nil {
		if err := validateIPMode(*user.IpMode); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fields = append(fields, "ipMode=?")
		args = append(args, *user.IpMode)
	}
	if user.IpRotation != nil {
		fields = append(fields, "ipRotation=?")
		args = append(args, *user.IpRotation)
	}
	if user.PortToIP != nil {
		fields = append(fields, "portToIP=?")
		args = append(args, *user.PortToIP)
	}
	if user.WhiteListIP != nil {
		fields = append(fields, "whiteListIP=?")
		args = append(args, *user.WhiteListIP)
	}
	if user.RotationIntervalSec != nil {
		fields = append(fields, "rotationIntervalSec=?")
		args = append(args, *user.RotationIntervalSec)
	}
	if user.ProxyIP != nil {
		if *user.ProxyIP != "" && !isValidIPv4(*user.ProxyIP) {
			http.Error(w, "proxyIP must be a valid IPv4 address", http.StatusBadRequest)
			return
		}
		fields = append(fields, "proxyIP=?")
		args = append(args, *user.ProxyIP)
	}

	if len(fields) == 0 {
		http.Error(w, "No fields to update", http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE user=?", strings.Join(fields, ", "))
	args = append(args, username)

	_, err := db.Connection.Exec(query, args...)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update record: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Record updated successfully"}`))

	syscall.Kill(os.Getpid(), syscall.SIGHUP)
}

func (db *DB) DeleteUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("user")

	query := `DELETE FROM users WHERE user = ?`
	_, err := db.Connection.Exec(query, username)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to delete record: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Record deleted successfully"}`))
	syscall.Kill(os.Getpid(), syscall.SIGHUP)
}

func (db *DB) Init() error {
	conn, err := sql.Open("mysql", "root:your_password@tcp(127.0.0.1:3306)/slickproxy")
	if err != nil {
		return fmt.Errorf("could not connect to the database: %v", err)
	}
	db.Connection = conn
	return nil
}

func withAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !Authenticate(w, r) {
			return
		}
		handler(w, r)
	}
}

func StartServer() {

	db := &DB{}
	err := db.Init()
	if err != nil {
		log.Fatalf("Error initializing DB: %v", err)
	}

	var allowedIPs []string
	err = loadConfig(&allowedIPs)
	if err != nil {
		log.Printf("Error reading config file: %v", err)
	}

	if len(allowedIPs) == 0 {
		log.Println("No allowed IPs configured, accepting all IPs.")
	}

	http.HandleFunc("/users", withAuth(db.GetAllUsers))
	http.HandleFunc("/user", withAuth(db.GetUser))
	http.HandleFunc("/userLive", withAuth(db.GetUserLive))
	http.HandleFunc("/create", withAuth(db.CreateUser))
	http.HandleFunc("/update", withAuth(db.UpdateUser))
	http.HandleFunc("/delete", withAuth(db.DeleteUser))
	http.HandleFunc("/metrics", withAuth(db.GetMetrics))

	listener, err := createListener(8080)
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}

	server := &http.Server{
		Handler: nil,
	}

	log.Println("Server started at :8080")
	err = server.Serve(listener)
	if err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func SetSocketOptions(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 1); err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2*1024*1024); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 2*1024*1024); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
		return err
	}

	return nil
}

func createListener(port uint16) (net.Listener, error) {
	var lc net.ListenConfig

	lc.Control = func(network, address string, c syscall.RawConn) error {
		var err error
		err = c.Control(func(fd uintptr) {
			err = SetSocketOptions(fd)
		})
		return err
	}

	listener, err := lc.Listen(context.Background(), "tcp", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, err
	}

	return listener, nil
}

func loadConfig(allowedIPs *[]string) error {

	data, err := ioutil.ReadFile("config.json")
	if err != nil {
		return err
	}

	var config struct {
		Server struct {
			AllowedIPs string `json:"allowed_ips"`
		} `json:"server"`
	}

	err = json.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("Error parsing config.json: %v", err)
	}

	*allowedIPs = strings.Split(config.Server.AllowedIPs, ",")

	var validIPs []string
	for _, ip := range *allowedIPs {
		ip = strings.TrimSpace(ip)
		if isValidIPv4(ip) {
			validIPs = append(validIPs, ip)
		} else if ip != "" {
			log.Printf("Invalid IP address skipped: %s", ip)
		}
	}

	*allowedIPs = validIPs
	return nil
}

func isAllowedIP(clientIP string, allowedIPs []string) bool {

	clientIP = strings.Split(clientIP, ":")[0]

	if len(allowedIPs) == 0 {
		return true
	}

	if net.ParseIP(clientIP) == nil || !isValidIPv4(clientIP) {
		return false
	}

	for _, ip := range allowedIPs {
		if strings.TrimSpace(ip) == clientIP {
			return true
		}
	}
	return false
}

func isValidIPv4(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To4() != nil
}
