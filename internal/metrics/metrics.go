package metrics

import (
	"fmt"
	"sync/atomic"
	"time"

	"slickproxy/internal/config"

	client "github.com/influxdata/influxdb1-client/v2"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
)

type MetricsPublisher struct {
	InfluxClient client.Client
	Database     string
	Counters     *config.UserMetrics
	Host         string
	Service      string

	prevThroughput int64
	lastTime       time.Time
}

func NewMetricsPublisher(influxAddr, db string, counters *config.UserMetrics, host, service string) (*MetricsPublisher, error) {
	c, err := client.NewHTTPClient(client.HTTPConfig{Addr: influxAddr})
	if err != nil {
		return nil, err
	}
	return &MetricsPublisher{
		InfluxClient:   c,
		Database:       db,
		Counters:       counters,
		Host:           host,
		Service:        service,
		prevThroughput: atomic.LoadInt64(&counters.Throughput),
		lastTime:       time.Now(),
	}, nil
}

func (mp *MetricsPublisher) Start() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			mp.publish()
		}
	}()
}

func max0(val int64) int64 {
	if val < 0 {
		return 0
	}
	return val
}

func (mp *MetricsPublisher) publish() {
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil || len(cpuPercent) == 0 {
		fmt.Println("Error getting CPU percent:", err)
		return
	}

	vmem, err := mem.VirtualMemory()
	if err != nil {
		fmt.Println("Error getting memory stats:", err)
		return
	}

	bp, err := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  mp.Database,
		Precision: "s",
	})
	if err != nil {
		fmt.Println("Error creating batch points:", err)
		return
	}

	tags := map[string]string{
		"host":    mp.Host,
		"service": mp.Service,
	}

	current := atomic.LoadInt64(&mp.Counters.Throughput)
	now := time.Now()
	interval := now.Sub(mp.lastTime).Seconds()
	var throughputBps int64 = 0
	if interval > 0 {
		throughputBps = int64(float64(current-mp.prevThroughput) * 8 / interval)
	}
	if throughputBps < 0 {
		throughputBps = 0
	}
	mp.prevThroughput = current
	mp.lastTime = now

	ac := atomic.LoadInt64(&mp.Counters.ActiveConnections)
	if ac < 0 {
		ac = 0
	}
	tu := atomic.LoadInt64(&mp.Counters.TotalUsers)
	if tu < 0 {
		tu = 0
	}
	au := atomic.LoadInt64(&mp.Counters.ActiveUsers)
	if au < 0 {
		au = 0
	}

	fields := map[string]interface{}{
		"cpu_percent":         cpuPercent[0],
		"memory_used":         int64(vmem.Used),
		"memory_used_percent": vmem.UsedPercent,
		"active_connections":  ac,
		"total_users":         tu,
		"active_users":        au,
		"throughput_bps":      throughputBps,
	}

	pt, err := client.NewPoint("proxy_metrics", tags, fields, now)
	if err != nil {
		fmt.Println("Error creating InfluxDB point:", err)
		return
	}

	bp.AddPoint(pt)

	if err := mp.InfluxClient.Write(bp); err != nil {
		fmt.Println("Error writing to InfluxDB:", err)
		return
	}

}

func (mp *MetricsPublisher) Close() error {
	return mp.InfluxClient.Close()
}
