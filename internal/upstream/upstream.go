package upstream

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"slickproxy/internal/bandwidthtracker"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/config"
	"slickproxy/internal/userdb"
	"slickproxy/internal/utils"
	"slickproxy/internal/viprox"

	"math/rand"

	"golang.org/x/net/proxy"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}
func GetRandomProxy() config.ProxyConfigEntry {
	idx := rand.Intn(len(config.Cfg.ProxyTable))
	return config.Cfg.ProxyTable[idx]
}

func connectViaViprox(rv *clientrequest.Request) error {
	if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
			atomic.AddInt64(&config.UserMetricsObj.ActiveUsers, 1)
		}
	}
	defer func() {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

			if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
				atomic.AddInt64(&config.UserMetricsObj.ActiveUsers, -1)
			}

		}
	}()

	atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, 1)
	defer atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, -1)
	atomic.AddInt64(&userdb.CurrentActiveConnections, 1)
	defer atomic.AddInt64(&userdb.CurrentActiveConnections, -1)
	atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, 1)
	defer atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, -1)

	return viprox.Adapter.HandleClient(rv)

}

func HandleRequestUpstream(rv *clientrequest.Request) error {
	trackedConn := bandwidthtracker.NewBandwidthTrackedConnection(rv)
	defer trackedConn.Close()
	rv.Conn = trackedConn
	if config.Cfg.General.Viprox {
		return connectViaViprox(rv)
	}

	return attemptUpstreamConnection(rv)
}

func attemptUpstreamConnection(rv *clientrequest.Request) error {
	var lastErr error
	for attempt := 1; attempt <= config.Cfg.Server.Retry.MaxRetries; attempt++ {
		err := createUpstreamConnection(rv)
		if err == nil {
			return nil
		}
		lastErr = err

	}

	return fmt.Errorf("upstream connection failed after %d retry attempts: last error: %v", config.Cfg.Server.Retry.MaxRetries, lastErr)
}

func ComputeUpstreamProxy(req *clientrequest.Request) error {

	req.UpstreamProxy = GetRandomProxy()

	GenerateProxy(req)

	return nil
}
func createUpstreamConnection(rv *clientrequest.Request) error {
	var err error

	var port int
	parts := strings.Split(rv.Host, ":")
	if len(parts) != 2 {
		port = 80
	} else {
		port, _ = strconv.Atoi(parts[1])
		if port == 0 {
			port = 80
		}
	}
	err = ComputeUpstreamProxy(rv)
	if err != nil {
		return err
	}

	if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
			atomic.AddInt64(&config.UserMetricsObj.ActiveUsers, 1)
		}
	}
	defer func() {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

			if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
				atomic.AddInt64(&config.UserMetricsObj.ActiveUsers, -1)
			}

		}
	}()

	atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, 1)
	defer atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, -1)
	atomic.AddInt64(&userdb.CurrentActiveConnections, 1)
	defer atomic.AddInt64(&userdb.CurrentActiveConnections, -1)
	atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, 1)
	defer atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, -1)

	proxyConn, err := establishProxyConnection(rv)
	if err != nil {
		return err
	}
	defer proxyConn.Conn.Close()
	proxyConn.Conn.SetDeadline(time.Time{})
	rv.Conn.SetDeadline(time.Time{})

	return forwardProxyData(rv, proxyConn)
}

func ReplaceUserPartPrefix(rv *clientrequest.Request, newFirst string) bool {
	userPart := rv.Credentials.UserPart

	if !strings.Contains(userPart, "-rc_") {
		return false
	}

	parts := strings.SplitN(userPart, "-", 2)
	if len(parts) == 1 {
		rv.Credentials.UserPart = newFirst + "-rc_all"
		return true
	}
	rv.Credentials.UserPart = newFirst + "-" + parts[1]
	return true
}

func establishProxyConnection(rv *clientrequest.Request) (clientrequest.ProxyConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var conn net.Conn
	var err error
	ReplaceUserPartPrefix(rv, rv.UpstreamProxy.Username)

	if rv.UpstreamProxy.Socks5 {
		conn, err = connectViaSocks5Protocol(rv.UpstreamProxy.Key, rv)
	} else {
		dialer := &net.Dialer{}
		conn, err = dialer.DialContext(ctx, "tcp", rv.UpstreamProxy.Key)
	}

	if err != nil {
		return clientrequest.ProxyConn{}, fmt.Errorf("failed to establish connection to proxy at %s: %v", rv.UpstreamProxy.Key, err)
	}
	return clientrequest.ProxyConn{Conn: conn}, nil
}

func connectViaSocks5Protocol(proxyAddress string, rv *clientrequest.Request) (net.Conn, error) {
	var auth *proxy.Auth
	auth = &proxy.Auth{
		User:     rv.Credentials.UserPart,
		Password: rv.UpstreamProxy.Password,
	}

	dialer, err := proxy.SOCKS5("tcp", proxyAddress, auth, &net.Dialer{})
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer initialization failed for proxy %s: %v", proxyAddress, err)
	}
	if _, _, err := net.SplitHostPort(rv.Host); err != nil {
		rv.Host = net.JoinHostPort(rv.Host, "80")
	}
	return dialer.Dial("tcp", rv.Host)
}

func forwardProxyData(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if rv.Type == "http" {
		return routeHTTPTraffic(rv, proxyConn)
	}
	return routeSocksTraffic(rv, proxyConn)
}

func routeHTTPTraffic(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if rv.UpstreamProxy.Socks5 {
		if rv.RawRequest.Method == "CONNECT" {
			return relayHTTPSOverSocks5(rv, proxyConn)
		}
		return relayHTTPOverSocks5(rv, proxyConn)
	}

	if rv.RawRequest.Method == "CONNECT" {
		return relayHTTPSOverHTTP(rv, proxyConn)
	}
	return relayHTTPOverHTTP(rv, proxyConn)
}

func routeSocksTraffic(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {

	return relaySOCKS5OverSocks5(rv, proxyConn)
}

func relayHTTPSOverSocks5(rv *clientrequest.Request, conn clientrequest.ProxyConn) error {
	if _, err := rv.Conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return fmt.Errorf("failed to send HTTPS tunnel establishment response to SOCKS5 client: %v", err)
	}

	relayBidirectionalTraffic(rv.Conn, conn.Conn)
	return nil
}

func relayHTTPOverSocks5(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if err := rv.RawRequest.WriteProxy(proxyConn.Conn); err != nil {
		return fmt.Errorf("failed to forward HTTP request through SOCKS5 proxy: %v", err)
	}

	relayBidirectionalTraffic(proxyConn.Conn, rv.Conn)
	return nil
}

func relayHTTPOverHTTP(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	addProxyAuthHeaders(rv)
	if err := rv.RawRequest.WriteProxy(proxyConn.Conn); err != nil {
		return fmt.Errorf("failed to send HTTP request to upstream HTTP proxy: %v", err)
	}
	proxyConn.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(proxyConn.Conn), rv.RawRequest)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response from upstream proxy: %v", err)
	}

	if err := response.Write(rv.Conn); err != nil {
		return fmt.Errorf("failed to forward HTTP response from proxy to client: %v", err)
	}
	return nil
}

func relayHTTPSOverHTTP(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if err := sendProxyConnectRequest(proxyConn, rv); err != nil {
		return err
	}
	proxyConn.Conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response, err := http.ReadResponse(bufio.NewReader(proxyConn.Conn), rv.RawRequest)
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response from HTTP upstream proxy: %v", err)
	}

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("upstream proxy CONNECT request failed: got status %d (expected 200 OK)", response.StatusCode)
	}

	if _, err := rv.Conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		return fmt.Errorf("failed to send HTTPS tunnel acknowledgment to client: %v", err)
	}

	relayBidirectionalTraffic(rv.Conn, proxyConn.Conn)
	return nil
}

func relaySOCKS5OverSocks5(rv *clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	tcpAddr := proxyConn.Conn.LocalAddr().(*net.TCPAddr)
	utils.SetIPZone(tcpAddr)
	rep := utils.CreateSocks5Response(tcpAddr)
	if _, err := rv.Conn.Write(rep); err != nil {
		return err
	}

	relayBidirectionalTraffic(rv.Conn, proxyConn.Conn)
	return nil
}

func relayBidirectionalTraffic(conn1, conn2 net.Conn) {
	idleTimeout := 1 * time.Minute

	go func() {
		copyDataWithIdleTimeout(conn2, conn1, idleTimeout)
		conn1.Close()
		conn2.Close()
	}()

	copyDataWithIdleTimeout(conn1, conn2, idleTimeout)
	conn1.Close()
	conn2.Close()
}

func copyDataWithIdleTimeout(dst, src net.Conn, timeout time.Duration) {
	buf := make([]byte, 32*1024)

	for {
		src.SetReadDeadline(time.Now().Add(timeout))
		n, err := src.Read(buf)

		if n > 0 {
			dst.SetWriteDeadline(time.Now().Add(timeout))
			_, werr := dst.Write(buf[:n])
			if werr != nil {
				return
			}
		}

		if err != nil {
			return
		}
	}
}

func sendProxyConnectRequest(proxyConn clientrequest.ProxyConn, rv *clientrequest.Request) error {
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", rv.Host, rv.Host)
	if rv.UpstreamProxy.Username != "" && rv.UpstreamProxy.Password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", rv.Credentials.UserPart, rv.UpstreamProxy.Password)))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	req += "Connection: close\r\n\r\n"
	_, err := proxyConn.Conn.Write([]byte(req))
	return err
}

func addProxyAuthHeaders(rv *clientrequest.Request) {
	if rv.UpstreamProxy.Username != "" && rv.UpstreamProxy.Password != "" {
		credentials := fmt.Sprintf("%s:%s", rv.Credentials.UserPart, rv.UpstreamProxy.Password)
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(credentials))
		rv.RawRequest.Header.Set("Proxy-Authorization", "Basic "+encodedAuth)
	}
}
