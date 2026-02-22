package stats

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"slickproxy/internal/config"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
)

const (
	username          = "default"
	database          = "default"
	tableName         = "audit_logs"
	batchSize         = 10000
	flushInterval     = 5 * time.Second
	channelBufferSize = 100000
)

type StatsRequest struct {
	Start               int64
	Host                string
	Type                string
	Bytes               int64
	User                string
	Country             string
	Session             string
	Time                int64
	Password            string
	City                string
	State               string
	Code                string
	UpstreamProxyIp     string
	UpstreamProxyPort   int
	Success             bool
	Timestamp           int64
	Attempts            int
	TotalRequestTime    int64
	Error               string
	ClientIP            string
	UpstreamProxyUser   string
	UpstreamProxyPass   string
	UpstreamProxyRemote bool
}

var insertColumns = `(
    Host, Type, Bytes, User, Country, Session, Time, Password,
    City, State, Code, UpstreamProxyIp, UpstreamProxyPort,
    Success, Timestamp, Attempts,
    TotalRequestTime, Error, node_hostname,
    ClientIP, UpstreamProxyUser, UpstreamProxyPass, UpstreamProxyRemote
)`

var (
	systemHostname        atomic.Value
	systemIP              atomic.Value
	totalBytesProcessed   int64
	totalBytesFailedCount int64
)

func initSystemInfo() error {

	updateSystemInfo()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			updateSystemInfo()
		}
	}()

	return nil
}

func updateSystemInfo() {

	hostname, err := os.Hostname()
	if err == nil {
		systemHostname.Store(hostname)
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					systemIP.Store(ip4.String())
					break
				}
			}
		}
	}
}

func initBuffer() {
	bufferOnce.Do(func() {
		buffer = &RequestBuffer{
			buffer: make(chan StatsRequest, channelBufferSize),
		}
	})
}

type RequestBuffer struct {
	buffer chan StatsRequest
}

var (
	buffer     *RequestBuffer
	bufferOnce sync.Once
)

func InitClickHouse() (clickhouse.Conn, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{config.Cfg.Stats.Host + ":" + strconv.Itoa(config.Cfg.Stats.Port)},
		Auth: clickhouse.Auth{
			Username: username,
			Password: config.Cfg.Stats.Password,
			Database: database,
		},
		Debug: false,
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		Compression: &clickhouse.Compression{
			Method: clickhouse.CompressionLZ4,
		},
		DialTimeout:          time.Second * 30,
		MaxOpenConns:         5,
		MaxIdleConns:         5,
		ConnMaxLifetime:      time.Hour,
		ConnOpenStrategy:     clickhouse.ConnOpenInOrder,
		BlockBufferSize:      10,
		MaxCompressionBuffer: 10240,
	})
	if err != nil {
		fmt.Printf("Failed to connect to ClickHouse: %v\n", err)
		return nil, err
	}

	ctx := context.Background()
	if err := conn.Ping(ctx); err != nil {
		fmt.Printf("Failed to ping ClickHouse: %v\n", err)
		return nil, err
	}

	return conn, nil
}
func AddStatsRequest(rv StatsRequest) error {
	if !config.Cfg.Stats.Enabled {
		return nil
	}
	if buffer == nil {
		initBuffer()
	}

	end := time.Now().UnixMilli()
	rv.TotalRequestTime = end - rv.Start

	buffer.buffer <- rv
	return nil
}

func ensureNonEmptyString(s string) string {
	if len(s) == 0 {
		return ""
	}
	return s
}

func convertToInt32(i int) int32 {
	return int32(i)
}

func convertToFloat64(f float64) float64 {
	return f
}

func convertBoolToUint8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

func insertBatchToDatabase(conn clickhouse.Conn, batch []StatsRequest) error {
	ctx := context.Background()
	batchInsert, err := conn.PrepareBatch(ctx, "INSERT INTO "+tableName+" "+insertColumns)
	if err != nil {
		fmt.Printf("Failed to prepare batch: %v\n", err)
		return err
	}

	hostname := systemHostname.Load().(string)

	for _, rv := range batch {

		err := batchInsert.Append(
			ensureNonEmptyString(rv.Host),
			ensureNonEmptyString(rv.Type),
			rv.Bytes,
			ensureNonEmptyString(rv.User),
			ensureNonEmptyString(rv.Country),
			ensureNonEmptyString(rv.Session),
			rv.Time,
			ensureNonEmptyString(rv.Password),
			ensureNonEmptyString(rv.City),
			ensureNonEmptyString(rv.State),
			ensureNonEmptyString(rv.Code),
			ensureNonEmptyString(rv.UpstreamProxyIp),
			convertToInt32(rv.UpstreamProxyPort),
			convertBoolToUint8(rv.Success),
			rv.Timestamp,
			rv.Attempts,
			rv.TotalRequestTime,
			ensureNonEmptyString(rv.Error),
			hostname,
			ensureNonEmptyString(rv.ClientIP),
			ensureNonEmptyString(rv.UpstreamProxyUser),
			ensureNonEmptyString(rv.UpstreamProxyPass),
			convertBoolToUint8(rv.UpstreamProxyRemote),
		)
		atomic.AddInt64(&totalBytesProcessed, rv.Bytes)
		if err != nil {
			atomic.AddInt64(&totalBytesFailedCount, rv.Bytes)
			fmt.Printf("Failed to insert batch: %v\n", err)
			return err
		}
	}

	return batchInsert.Send()
}

func processRequestBuffer(conn clickhouse.Conn) {
	batch := make([]StatsRequest, 0, batchSize)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case rv := <-buffer.buffer:
			batch = append(batch, rv)

			if len(batch) >= batchSize {
				var err error
				for i := 0; i < 2; i++ {
					err = insertBatchToDatabase(conn, batch)
					if err == nil {
						break
					}
					log.Printf("Insert batch failed (try %d): %v", i+1, err)

					conn, err = InitClickHouse()
					if err != nil {
						log.Printf("Reconnection failed: %v", err)
						break
					}
				}
				batch = batch[:0]

			}

		case <-ticker.C:
			if len(batch) > 0 {
				var err error
				for i := 0; i < 2; i++ {
					err = insertBatchToDatabase(conn, batch)
					if err == nil {
						break
					}
					log.Printf("Timer batch insert failed (try %d): %v", i+1, err)

					conn, err = InitClickHouse()
					if err != nil {
						log.Printf("Reconnection failed: %v", err)
						break
					}
				}
				batch = batch[:0]
			}
		}
	}
}

func StartStatsClient() {
	fmt.Println("Starting stats client check...")
	if !config.Cfg.Stats.Enabled {
		return
	}
	fmt.Println("Starting stats client...")

	if err := initSystemInfo(); err != nil {
		fmt.Printf("Failed to initialize system info: %v", err)
		return
	}

	conn, err := InitClickHouse()
	if err != nil {
		fmt.Printf("Failed to initialize ClickHouse connection: %v", err)
		return
	}

	if buffer == nil {
		initBuffer()
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := conn.Ping(context.Background()); err != nil {
				log.Printf("ClickHouse connection unhealthy, attempting to reconnect: %v", err)
				newConn, err := InitClickHouse()
				if err != nil {
					log.Printf("Failed to reconnect to ClickHouse: %v", err)
					continue
				}
				conn = newConn
				log.Printf("Successfully reconnected to ClickHouse")
			}
		}
	}()
	log.Println("Stats client initialized successfully, starting to process buffer")

	go processRequestBuffer(conn)
}

func NewRequest() StatsRequest {
	now := time.Now()
	return StatsRequest{
		Start:     now.UnixMilli(),
		Timestamp: now.Unix(),
	}
}
