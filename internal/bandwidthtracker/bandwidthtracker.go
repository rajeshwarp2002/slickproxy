package bandwidthtracker

import (
	"fmt"
	"net"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/config"
	"sync/atomic"
)

type BandwidthTrackedConnection struct {
	net.Conn
	rv           *clientrequest.Request
	bytesTracked int64
}

func (c *BandwidthTrackedConnection) Read(b []byte) (int, error) {
	bytesRead, err := c.Conn.Read(b)
	if err != nil {
		return bytesRead, err
	}
	atomic.AddInt64(&c.rv.Bytes, int64(bytesRead))
	atomic.AddInt64(&c.rv.InBytes, int64(bytesRead))
	atomic.AddInt64(&config.UserMetricsObj.Throughput, int64(bytesRead))
	if config.Cfg.General.TrackUsage {
		if c.rv.UpstreamProxy.BytesPerSecond != 0 {
			c.rv.UpstreamProxy.RateLimiter.Write(uint64(bytesRead), true)
		}
		if c.rv.Credentials.UserDetail.ThroughputPerSecond != 0 {
			isUpstreamBlocked := int64(0)
			if c.rv.UpstreamProxy.BytesPerSecond != 0 {
				isUpstreamBlocked = atomic.LoadInt64(&c.rv.UpstreamProxy.RateLimiter.Blocked)
			}
			c.rv.Credentials.UserDetail.RateLimiter.Write(uint64(bytesRead), c.rv.UpstreamProxy.BytesPerSecond == 0 || isUpstreamBlocked == 1)
		}

		c.rv.Credentials.UserDetail.Dirty = true
		totalBytesUsed := atomic.AddInt64(c.rv.Credentials.UserDetail.TotalUsedBytes, int64(bytesRead))
		if c.rv.Credentials.UserDetail.TotalQuota != 0 && totalBytesUsed+c.rv.Credentials.UserDetail.PersistedUsedBytes > c.rv.Credentials.UserDetail.TotalQuota {
			c.Conn.Close()
			return bytesRead, fmt.Errorf("quota exceeded")
		}
	}
	return bytesRead, nil
}

func (c *BandwidthTrackedConnection) Write(b []byte) (int, error) {
	bytesWritten, err := c.Conn.Write(b)
	if err != nil {
		return bytesWritten, err
	}

	atomic.AddInt64(&c.rv.Bytes, int64(bytesWritten))
	atomic.AddInt64(&c.rv.OutBytes, int64(bytesWritten))
	atomic.AddInt64(&config.UserMetricsObj.Throughput, int64(bytesWritten))

	if config.Cfg.General.TrackUsage {
		if c.rv.UpstreamProxy.BytesPerSecond != 0 {
			c.rv.UpstreamProxy.RateLimiter.Write(uint64(bytesWritten), true)
		}

		if c.rv.Credentials.UserDetail.ThroughputPerSecond != 0 {
			isUpstreamBlocked := int64(0)
			if c.rv.UpstreamProxy.BytesPerSecond != 0 {
				isUpstreamBlocked = atomic.LoadInt64(&c.rv.UpstreamProxy.RateLimiter.Blocked)
			}
			c.rv.Credentials.UserDetail.RateLimiter.Write(uint64(bytesWritten), c.rv.UpstreamProxy.BytesPerSecond == 0 || isUpstreamBlocked == 1)
		}

		c.rv.Credentials.UserDetail.Dirty = true
		totalBytesUsed := atomic.AddInt64(c.rv.Credentials.UserDetail.TotalUsedBytes, int64(bytesWritten))
		if c.rv.Credentials.UserDetail.TotalQuota != 0 && totalBytesUsed+c.rv.Credentials.UserDetail.PersistedUsedBytes > c.rv.Credentials.UserDetail.TotalQuota {
			c.Conn.Close()
			return bytesWritten, fmt.Errorf("quota exceeded")
		}
	}
	return bytesWritten, nil
}

func NewBandwidthTrackedConnection(rv *clientrequest.Request) *BandwidthTrackedConnection {
	return &BandwidthTrackedConnection{Conn: rv.Conn, rv: rv}
}
