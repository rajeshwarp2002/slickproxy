package userdb

import (
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"slickproxy/internal/config"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/cpu"

	_ "github.com/go-sql-driver/mysql"
)

var Ports []int

var Users *map[string]*User
var GlobalBlacklistDomains *map[string]struct{}
var GlobalBlacklistPorts *map[string]struct{}

type DataStore struct {
	Users                  *map[string]*User
	GlobalBlacklistDomains *map[string]struct{}
	GlobalBlacklistPorts   *map[string]struct{}
}

type IPVersion int

var CurrentActiveConnections int64

const (
	IPv4Mode IPVersion = iota
	IPv6Mode
	IPv4V6Mode
)

type User struct {
	User                           string
	Password                       string
	ProxyIPListv4                  []string
	ProxyIPListv6                  []string
	ProxyPort                      uint16
	ProxyPortRange                 [2]uint16
	ActiveConnections              uint32
	ConnectionsPerSecond           uint32
	ThroughputPerSecond            uint32
	TotalQuota                     int64
	QuotaDuration                  string
	TimeQuota                      int64
	IpMode                         IPVersion
	IpRotation                     string
	PortToIP                       map[uint16]string
	WhiteListIP                    []string
	RotationIntervalSec            uint32
	LastIpTime                     int64
	Mu                             sync.Mutex
	LastIp                         net.IP
	CurrentActiveConnections       *int64
	TotalUsedBytes                 *int64
	TotalUsedBytesLastSec          *int64
	RateLimiter                    *config.RateLimiter
	Dirty                          bool
	PersistedUsedBytes             int64
	PersistedActiveConnections     int64
	PersistedTotalUsedBytesLastSec int64
	ProxyIP                        string
}

func StringToIpMode(mode string) (IPVersion, error) {
	switch strings.ToUpper(mode) {
	case "IPV4":
		return IPv4Mode, nil
	case "IPV6":
		return IPv6Mode, nil
	case "IPV4V6":
		return IPv4V6Mode, nil
	default:
		return -1, errors.New("invalid IP mode")
	}
}

func ParseIpString(ipString string) ([]string, []string) {
	ipv4 := []string{}
	ipv6 := []string{}
	if ipString != "" {
		ips := strings.Split(ipString, ",")
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				ipv6 = append(ipv6, ip)
			} else {
				ipv4 = append(ipv4, ip)
			}
		}
	}
	return ipv4, ipv6
}

func ParsePortString(portString string) (uint16, [2]uint16) {
	var port uint16
	var portRange [2]uint16
	parts := strings.Split(portString, "-")
	if len(parts) == 1 {
		parsedPort, err := strconv.Atoi(parts[0])
		if err == nil {
			port = uint16(parsedPort)
		}
	} else {
		start, err := strconv.Atoi(parts[0])
		if err == nil {
			portRange[0] = uint16(start)
		}
		end, err := strconv.Atoi(parts[1])
		if err == nil {
			portRange[1] = uint16(end)
		}
	}
	return port, portRange
}

func ParsePortIPString(portIPString string) map[uint16]string {
	portToIP := make(map[uint16]string)
	parts := strings.Split(portIPString, ",")
	for _, part := range parts {
		pair := strings.Split(part, ":")
		port, err := strconv.Atoi(pair[0])
		if err == nil {
			portToIP[uint16(port)] = pair[1]
		}
	}
	return portToIP
}

func FetchAndUpdateUsers(start bool) error {

	dsn := "root:your_password@tcp(" + config.Cfg.DB.Connection + ")/slickproxy"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("error connecting")
		return fmt.Errorf("error connecting to database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT port FROM listenports")
	if err != nil {
		log.Println("no listen ports configured", err)
		log.Println(err)
	}
	defer rows.Close()

	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			log.Println(err)
		}

		Ports = append(Ports, port)
	}

	if err := rows.Err(); err != nil {
		log.Println(err)
	}

	query := "SELECT * FROM users"
	rows, err = db.Query(query)
	if err != nil {
		return fmt.Errorf("error querying database for users: %v", err)
	}
	defer rows.Close()

	users := make(map[string]*User)
	for rows.Next() {
		ActiveConnections := int64(0)
		TotalUsedBytes := int64(0)
		TotalUsedBytesLastSec := int64(0)

		var user User
		user.CurrentActiveConnections = &ActiveConnections
		user.TotalUsedBytes = &TotalUsedBytes
		user.TotalUsedBytesLastSec = &TotalUsedBytesLastSec

		var ipMode, proxyIPList, proxyPort, portToIP, whitelist, quotaDuration, ipRotation sql.NullString
		var proxyIP sql.NullString
		var activeConn, connPerSec, throughputPerSec, totalQuota, timeQuota, rotationIntervalSec sql.NullInt64
		var persistedTotalUsedBytesLastSec, persistedActiveConnections, persistedUsedBytes sql.NullInt64

		if err := rows.Scan(&user.User, &user.Password, &proxyIP, &proxyIPList,
			&proxyPort, &activeConn, &connPerSec, &throughputPerSec,
			&totalQuota, &quotaDuration, &timeQuota, &ipMode, &ipRotation,
			&portToIP, &whitelist, &rotationIntervalSec,
			&persistedTotalUsedBytesLastSec,
			&persistedActiveConnections, &persistedUsedBytes); err != nil {
			fmt.Printf("Error scanning row for user %s: %v\n", user.User, err)
			return fmt.Errorf("error scanning row for users: %v", err)
		}

		if proxyIP.Valid {
			user.ProxyIP = proxyIP.String
		}
		proxyIPListStr := ""
		if proxyIPList.Valid {
			proxyIPListStr = proxyIPList.String
		}
		proxyPortStr := ""
		if proxyPort.Valid {
			proxyPortStr = proxyPort.String
		}
		if activeConn.Valid {
			user.ActiveConnections = uint32(activeConn.Int64)
		}
		if connPerSec.Valid {
			user.ConnectionsPerSecond = uint32(connPerSec.Int64)
		}
		if throughputPerSec.Valid {
			user.ThroughputPerSecond = uint32(throughputPerSec.Int64)
		}
		if totalQuota.Valid {
			user.TotalQuota = totalQuota.Int64
		}
		if quotaDuration.Valid {
			user.QuotaDuration = quotaDuration.String
		}
		if timeQuota.Valid {
			user.TimeQuota = timeQuota.Int64
		}
		ipModeStr := "IPV4"
		if ipMode.Valid {
			ipModeStr = ipMode.String
		}
		if ipRotation.Valid {
			user.IpRotation = ipRotation.String
		}
		portToIPStr := ""
		if portToIP.Valid {
			portToIPStr = portToIP.String
		}
		whitelistStr := ""
		if whitelist.Valid {
			whitelistStr = whitelist.String
		}
		if rotationIntervalSec.Valid {
			user.RotationIntervalSec = uint32(rotationIntervalSec.Int64)
		}
		if persistedTotalUsedBytesLastSec.Valid {
			user.PersistedTotalUsedBytesLastSec = persistedTotalUsedBytesLastSec.Int64
		}
		if persistedActiveConnections.Valid {
			user.PersistedActiveConnections = persistedActiveConnections.Int64
		}
		if persistedUsedBytes.Valid {
			user.PersistedUsedBytes = persistedUsedBytes.Int64
		}

		key := fmt.Sprintf("%s:%s", user.User, user.Password)

		user.IpMode, _ = StringToIpMode(ipModeStr)
		user.ProxyIPListv4, user.ProxyIPListv6 = ParseIpString(proxyIPListStr)
		user.WhiteListIP, _ = ParseIpString(whitelistStr)
		user.ProxyPort, user.ProxyPortRange = ParsePortString(proxyPortStr)
		user.PortToIP = ParsePortIPString(portToIPStr)
		user.RateLimiter = config.NewRateLimiter(uint64(user.ThroughputPerSecond) / 8)

		if Users != nil {
			existing, err := UserExists(key, Users)
			if err == nil {
				existing.Mu.Lock()
				defer existing.Mu.Unlock()
				user.LastIp = existing.LastIp
				user.LastIpTime = existing.LastIpTime
				user.CurrentActiveConnections = existing.CurrentActiveConnections
				user.TotalUsedBytes = existing.TotalUsedBytes
				user.TotalUsedBytesLastSec = existing.TotalUsedBytesLastSec
				user.RateLimiter = existing.RateLimiter
				user.RateLimiter.BytesPerSecond = uint64(user.ThroughputPerSecond) / 8
			}
		}

		if user.TotalQuota != 0 && (user.PersistedUsedBytes+*user.TotalUsedBytes > user.TotalQuota) {

			fmt.Println("Skipping user ", key, " because they are over quota")
		} else {
			users[key] = &user
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating over rows for users: %v", err)
	}

	globalBlacklistDomains := make(map[string]struct{})
	globalBlacklistPorts := make(map[string]struct{})

	blacklistQuery := `SELECT value, type FROM blacklist`
	blacklistRows, err := db.Query(blacklistQuery)
	if err != nil {
		return fmt.Errorf("error querying global blacklist: %v", err)
	}
	defer blacklistRows.Close()

	for blacklistRows.Next() {
		var value, listType string
		if err := blacklistRows.Scan(&value, &listType); err != nil {
			return fmt.Errorf("error scanning global blacklist row: %v", err)
		}
		if strings.ToLower(listType) == "domain" {
			globalBlacklistDomains[value] = struct{}{}
		} else if strings.ToLower(listType) == "port" {
			globalBlacklistPorts[value] = struct{}{}
		}
	}

	if err := blacklistRows.Err(); err != nil {
		return fmt.Errorf("error iterating over rows for global blacklist: %v", err)
	}

	Users = &users
	GlobalBlacklistDomains = &globalBlacklistDomains
	GlobalBlacklistPorts = &globalBlacklistPorts

	config.UserMetricsObj.TotalUsers = int64(len(users))
	fmt.Println("Users and blacklist data successfully fetched and updated.")
	return nil
}

func IsDomainBlacklisted(domain string, blacklistDomains *map[string]struct{}) error {

	parts := strings.Split(domain, ":")
	domainWithoutPort := parts[0]

	if _, exists := (*blacklistDomains)[domainWithoutPort]; exists {
		return errors.New("domain is blacklisted")
	}
	return nil
}

func IsPortBlacklisted(port string, blacklistPorts *map[string]struct{}) error {

	if _, exists := (*blacklistPorts)[port]; exists {
		return errors.New("port is blacklisted")
	}
	return nil
}

func UserExists(username string, Users *map[string]*User) (*User, error) {

	if user, exists := (*Users)[username]; exists {

		return user, nil
	}

	return nil, errors.New("user not found")
}

func WriteUsersToDB() {
	dsn := "root:your_password@tcp(" + config.Cfg.DB.Connection + ")/slickproxy"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Println("error connecting")
		return
	}
	defer db.Close()

	for {

		time.Sleep(1 * time.Second)
		usersLocal := Users
		if usersLocal == nil {
			continue
		}

		entries := 0

		for _, user := range *usersLocal {
			if user.Dirty {
				user.Dirty = false

				activeConnections := 0
				if user.CurrentActiveConnections != nil {
					activeConnections = int(*user.CurrentActiveConnections)
				}
				totalUsedBytes := int64(0)
				if user.TotalUsedBytes != nil {
					totalUsedBytes = *user.TotalUsedBytes
				}

				query := `
       				UPDATE users
    				SET
					BytesPerSecond =  ?,
					CurrentActiveConnections =  ?,
					TotalUsedBytes = TotalUsedBytes + ?
					WHERE User = ?
					`

				_, err := db.Exec(query, user.RateLimiter.BytesWritten, activeConnections, totalUsedBytes, user.User)
				if err != nil {
					log.Printf("Error updating user %s: %v", user.User, err)
				} else {
					*user.TotalUsedBytes = 0
				}
				entries++

				if entries >= 100 {
					break
				}
			}
		}
	}
}

var CpuOverThreshold bool
var FdThreshold bool
var cpuHighCount int

func CheckCPUUsage() {

	percentages, err := cpu.Percent(0, false)
	if err != nil {
		log.Fatalf("Error fetching CPU usage: %v", err)
		return
	}

	if percentages[0] >= 90 {
		cpuHighCount++
	} else {
		cpuHighCount = 0
	}

	if cpuHighCount >= 60 {
		CpuOverThreshold = true
	} else {
		CpuOverThreshold = false
	}
}

func checkFDUsage() error {
	const maxLimit = 1_000_000
	const threshold = 0.9

	files, err := ioutil.ReadDir("/proc/self/fd")
	if err != nil {
		return fmt.Errorf("failed to read /proc/self/fd: %w", err)
	}

	used := len(files)
	if float64(used) >= threshold*float64(maxLimit) {
		log.Printf("Warning: Open file descriptors (%d) exceed 90%% of the limit (%d)", used, maxLimit)
		FdThreshold = true
	} else {
		FdThreshold = false
	}

	return nil
}

var cutoff = time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC)

func RefreshUsersData() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := FetchAndUpdateUsers(false); err != nil {
				log.Printf("Error refreshing user data: %v", err)
			}
		}
	}
}

func ImportUsersFromFile() error {
	filePath := config.Cfg.General.Viprox_users_file

	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	dsn := "root:your_password@tcp(" + config.Cfg.DB.Connection + ")/slickproxy"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		return fmt.Errorf("error pinging database: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	insertCount := 0
	skipCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			fmt.Printf("Skipping invalid line (expected 'username password'): %s", line)
			skipCount++
			continue
		}

		username := parts[0]
		password := parts[1]

		query := "INSERT INTO users (user, password) VALUES (?, ?)"
		result, err := db.Exec(query, username, password)
		if err != nil {

			if strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(err.Error(), "1062") {

				skipCount++
				continue
			}
			fmt.Printf("Error inserting user %s: %v\n", username, err)
			skipCount++
			continue
		}

		rowsAffected, err := result.RowsAffected()
		if err == nil && rowsAffected > 0 {
			insertCount++
		}
	}

	return nil
}

func StartUserImportScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := ImportUsersFromFile(); err != nil {
			log.Printf("Error in scheduled user import: %v", err)
		}
	}
}

func MonitorCPUUsage() {

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:

			CheckCPUUsage()
			checkFDUsage()

			now := time.Now().UTC()

			if now.After(cutoff) {
				fmt.Println("Expired: current date is after ", cutoff)

			}
		}
	}
}
