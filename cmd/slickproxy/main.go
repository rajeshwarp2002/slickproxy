package main

import (
	"fmt"
	"log"
	"net/http"

	"os"
	"os/signal"
	"slickproxy/internal/config"
	"slickproxy/internal/ipblocker"
	"slickproxy/internal/metrics"
	"slickproxy/internal/stats"
	"slickproxy/internal/tcp"
	"slickproxy/internal/udp"
	userdb "slickproxy/internal/userdb"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func setFDLimit(limit uint64) {
	rLimit := unix.Rlimit{
		Cur: limit,
		Max: limit,
	}
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Fatalf("Failed to set FD limit: %v", err)
	}
	fmt.Printf("FD limit set to %d\n", limit)
}

func init() {
	if err := config.LoadConfig("config.json"); err != nil {
		fmt.Printf("Error loading config: %v", err)
		log.Fatalf("Error loading config: %v", err)
	}
	log.Println("logger loaded")
}

func startPprofServer() {
	if err := http.ListenAndServe("0.0.0.0:6667", nil); err != nil {
		log.Fatalf("Failed to start pprof server: %v", err)
	}
}

func listenForSIGHUP() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP)

	for {
		<-sigs

		err := userdb.FetchAndUpdateUsers(false)
		if err != nil {
			log.Printf("Error reloading users: %v", err)
		} else {
			log.Println("User data reloaded successfully")
		}
	}
}

func main() {
	fmt.Println("Starting SlickProxy...")

	pub, err := metrics.NewMetricsPublisher("http://localhost:8086", "go_metrics", config.GetUserMetrics(), "", "")
	if err != nil {
		log.Printf("Error creating metrics publisher: %v", err)
		return
	}
	go pub.Start()
	setFDLimit(1_000_000)

	var rLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Fatalf("Failed to get FD limit: %v", err)
	}
	fmt.Printf("Soft limit: %d, Hard limit: %d\n", rLimit.Cur, rLimit.Max)

	if err := userdb.ImportUsersFromFile(); err != nil {
		fmt.Printf("Error importing users from file: %v", err)
	}
	fmt.Println("Initial user import complete, starting scheduler...")

	if err := userdb.LoadUsersFromConfig(); err != nil {
		fmt.Printf("Error loading users from config: %v", err)
	}

	err = userdb.FetchAndUpdateUsers(true)
	if err != nil {
		log.Printf("Error reloading users: %v", err)
		// Only abort startup if database connection is configured
		if config.Cfg.DB.Connection != "" {
			log.Fatalf("Aborting startup: database configured but connection failed")
		}
	} else {
		log.Println("User data reloaded successfully")
	}
	stats.StartStatsClient()

	fmt.Println("Starting user import scheduler...")
	go userdb.StartUserImportScheduler()

	go listenForSIGHUP()

	if config.Cfg.General.ProxyFilesPath != "" {
		fmt.Println("Starting proxy file sync scheduler...")
		go userdb.StartProxyFileSync()
	}

	go userdb.StartServer()
	for _, port := range config.Cfg.Ports {
		port, _ := strconv.Atoi(port)
		go tcp.StartTcpServer(uint16(port))
	}
	config.NewCachedTime(time.Millisecond * 10)
	go userdb.WriteUsersToDB()
	go userdb.MonitorCPUUsage()
	go userdb.RefreshUsersData()

	// Start UDP listeners if not in ephemeral port mode (ConnMap mode)
	if !config.Cfg.General.UDPEphemeralPort {
		for _, port := range config.Cfg.Ports {
			port, _ := strconv.Atoi(port)
			go func(p uint16) {
				if err := udp.HandleUDP(p); err != nil {
					log.Printf("Failed to start UDP listener on port %d: %v", p, err)
				}
			}(uint16(port))
		}
	}

	// Initialize IP blocker (can be nil if disabled in config)
	userdb.IPBlocker = ipblocker.NewIPBlocker()
	if userdb.IPBlocker != nil {
		log.Println("IP blocker initialized and started")
	} else {
		log.Println("IP blocker is disabled")
	}

	// Start license check only if not in load balancer mode
	if !config.Cfg.General.LB {
		userdb.StartLicenseCheck()
	}

	select {}
}
