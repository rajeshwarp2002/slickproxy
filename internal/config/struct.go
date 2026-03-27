package config

import (
	"sync/atomic"
	"time"
)

var Ct *cachedTime

type cachedTime struct {
	now atomic.Value
}

func NewCachedTime(refreshInterval time.Duration) {
	Ct = &cachedTime{}
	Ct.now.Store(time.Now())

	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for range ticker.C {
			Ct.now.Store(time.Now())
		}
	}()
}

func (ct *cachedTime) CurrentTime() time.Time {
	return ct.now.Load().(time.Time)
}

type RateLimiter struct {
	BytesPerSecond uint64
	BytesWritten   uint64
	lastReset      int64
	currentTime    func() int64
	Blocked        int64

	noOvershootCount int64
}

func NewRateLimiter(bytesPerSecond uint64) *RateLimiter {
	return &RateLimiter{
		BytesPerSecond:   bytesPerSecond,
		lastReset:        time.Now().Unix(),
		currentTime:      func() int64 { return Ct.CurrentTime().Unix() },
		noOvershootCount: 0,
	}
}

func (rl *RateLimiter) Write(bytesToBeWritten uint64, block bool) {
	now := rl.currentTime()
	lastReset := atomic.LoadInt64(&rl.lastReset)

	if now != lastReset {

		if atomic.CompareAndSwapInt64(&rl.lastReset, lastReset, now) {
			total := atomic.LoadUint64(&rl.BytesWritten)

			if total <= rl.BytesPerSecond {

				atomic.AddInt64(&rl.noOvershootCount, 1)
				if atomic.LoadInt64(&rl.noOvershootCount) >= 2 && atomic.LoadInt64(&rl.Blocked) == 1 {

					atomic.StoreInt64(&rl.Blocked, 0)
				}
			} else {

				atomic.StoreInt64(&rl.noOvershootCount, 0)
			}

			atomic.StoreUint64(&rl.BytesWritten, 0)
		}
	}

	newTotal := atomic.AddUint64(&rl.BytesWritten, bytesToBeWritten)

	if block && newTotal > rl.BytesPerSecond {
		atomic.StoreInt64(&rl.Blocked, 1)

		time.Sleep(1 * time.Second)
	}
}

type ServerConfig struct {
	Logging           string      `json:"logging"`
	SniCheck          bool        `json:"sni-check"`
	Inflation         int         `json:"inflation"`
	Retry             RetryConfig `json:"retries"`
	MaxSessions       int         `json:"max-sessions"`
	DefaultSessionTTL int         `json:"default-session-ttl"`
	StatelessSession  bool        `json:"stateless-session"`
}
type RetryConfig struct {
	MaxRetries int `json:"max-retries"`
	Timeout    int `json:"timeout"`
}

type ProxyConfigEntry struct {
	Name           string `json:"name"`
	IP             string `json:"ip"`
	Port           uint16 `json:"port"`
	Socks5         bool   `json:"socks5"`
	Username       string `json:"username"`
	Password       string `json:"password"`
	BytesPerSecond int    `json:"bytes_per_second"`

	Key         string
	RateLimiter *RateLimiter
	IsRemote    bool
}

type ConfigUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Config struct {
	General struct {
		Log                  string `json:"log"`
		LB                   bool   `json:"lb"`
		TrackUsage           bool   `json:"trackusage"`
		Cluster              bool   `json:"cluster"`
		DNSServer            string `json:"dns_server"`
		Viprox               bool   `json:"viprox"`
		Viprox_auth          bool   `json:"viprox_auth"`
		Viprox_log           bool   `json:"viprox_log"`
		Viprox_users_file    string `json:"viprox_users_file"`
		ProxyFilesPath       string `json:"proxy_files_path"`
		ProxyFilesRegex      string `json:"proxy_files_regex"`
		RefreshUsersInterval int    `json:"refresh_users_interval"`
		UDPEphemeralPort     bool   `json:"udp_ephemeral_port"`   // Use ephemeral ports for UDP relay (default: false, use ConnMap)
		UDPTimeout           int    `json:"udp_timeout"`          // UDP connection keepalive timeout in seconds (default: 60)
		UDPConnectionReuse   bool   `json:"udp_connection_reuse"` // Reuse/cache UDP connections for multiple packets (default: true), set false for request-response model
		NoAuthError          bool   `json:"no_auth_error"`        // Suppress auth error responses (407) unless debug flag enabled (default: false)
		Socks5Disabled       bool   `json:"socks5_disabled"`      // Disable SOCKS5 protocol support (default: false, SOCKS5 enabled)
	} `json:"general"`
	DB struct {
		Connection  string `json:"connection"`
		GlobalUsage bool   `json:"global_usage"`
	} `json:"db"`
	Stats struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Enabled  bool   `json:"enabled"`
		Password string `json:"password"`
	} `json:"stats"`
	IPBlocking struct {
		Enabled          bool `json:"enabled"`            // enable/disable IP blocking
		FailureThreshold int  `json:"failure_threshold"`  // defaults to 100 if not set
		BlockDurationMin int  `json:"block_duration_min"` // defaults to 5 if not set
	} `json:"ip_blocking"`
	Server  ServerConfig       `json:"server"`
	Ports   []string           `json:"ports"`
	Subnets []string           `json:"subnets"`
	Proxies []ProxyConfigEntry `json:"proxies"`
	Users   []ConfigUser       `json:"users"`

	ProxyTable []ProxyConfigEntry
}
