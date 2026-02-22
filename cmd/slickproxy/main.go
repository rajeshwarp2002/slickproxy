package main

import (
	"fmt"
	"log"
	"net/http"

	"os"
	"os/signal"
	"slickproxy/internal/config"
	"slickproxy/internal/metrics"
	"slickproxy/internal/stats"
	"slickproxy/internal/tcp"
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
	log.Println("Starting pprof server on :666")
	if err := http.ListenAndServe("0.0.0.0:666", nil); err != nil {
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
	go userdb.StartServer()

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

	err = userdb.FetchAndUpdateUsers(true)
	if err != nil {
		log.Printf("Error reloading users: %v", err)
	} else {
		log.Println("User data reloaded successfully")
	}
	stats.StartStatsClient()

	fmt.Println("Starting user import scheduler...")
	go userdb.StartUserImportScheduler()

	go listenForSIGHUP()

	for _, port := range config.Cfg.Ports {
		port, _ := strconv.Atoi(port)
		go tcp.StartTcpServer(uint16(port))
	}
	config.NewCachedTime(time.Millisecond * 10)
	go userdb.WriteUsersToDB()
	go userdb.MonitorCPUUsage()
	go userdb.RefreshUsersData()
	select {}
}
