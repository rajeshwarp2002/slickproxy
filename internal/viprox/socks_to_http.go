package viprox

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slickproxy/internal/config"
	"slickproxy/internal/request"
	"slickproxy/internal/utils"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"net/http"
	_ "net/http/pprof" // Register pprof handlers

	"github.com/natefinch/lumberjack"
)

const (
	socks5Version   = 0x05
	authUserVersion = 0x01
	authResponse    = 0x01
	authUserPass    = 0x02
	cmdConnect      = 0x01
	atypIPv4        = 0x01
	atypDomainName  = 0x03
	statusSucceeded = 0x00
	statusFailure   = 0x01
	accessLogFormat = "%.3f %d %s TCP_TUNNEL/%s %d CONNECT %s %s HIER_DIRECT/%s - %s %d %s %s"
)

var portIPMapper *PortIPMapper

type PeerInfo struct {
	TTL        int64  // expiration timestamp (Unix seconds)
	Peer       string // peer name or address
	IsRemote   bool   // whether it's a remote proxy
	LastAccess int64  // last access timestamp (Unix seconds)
}

type BigHolder struct {
	mu       sync.RWMutex
	Data     map[int]PeerInfo
	Capacity int // maximum allowed entries
}

// NewBigHolder creates a holder with optional initial capacity and max entries.
func NewBigHolder(capacity int) *BigHolder {
	return &BigHolder{
		Data:     make(map[int]PeerInfo),
		Capacity: capacity,
	}
}

var BigHolderInstance *BigHolder
var CounterMapInstance *CounterMap

// joinNumbers takes num1 (max 3 digits) and num2, and returns a number
// with num1 in the MSB position followed by num2
func joinNumbers(num1 int, num2 int) int {
	// Calculate how many digits num2 has
	num2Digits := int(math.Log10(float64(num2))) + 1

	// Shift num1 left by the number of digits in num2 and add num2
	result := num1*int(math.Pow10(num2Digits)) + num2
	return result
}

// Set adds or updates an entry. Does nothing if capacity is exceeded.
func (bh *BigHolder) Set(key int, ttl int64, peer string, isRemote bool) {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	//fmt.Printf("BigHolder Set: key=%d, ttl=%d, peer=%s, isRemote=%v\n", key, ttl, peer, isRemote)

	if len(bh.Data) >= bh.Capacity {
		// Capacity reached, ignore new insert
		return
	}
	//fmt.Printf("BigHolder Set: key=%d, ttl=%d, peer=%s, isRemote=%v\n", key, ttl, peer, isRemote)

	now := time.Now().Unix()
	bh.Data[key] = PeerInfo{
		TTL:        ttl,
		Peer:       peer,
		IsRemote:   isRemote,
		LastAccess: now, // set current time on creation
	}
}

// Get returns the Peer string if valid. Removes expired entries automatically.
func (bh *BigHolder) Get(key int) (string, bool) {
	bh.mu.RLock()
	entry, exists := bh.Data[key]
	bh.mu.RUnlock()

	//fmt.Printf("BigHolder Get: key=%d, exists=%v, entry=%+v\n", key, exists, entry)
	if !exists {
		return "", false
	}

	now := time.Now().Unix()
	if entry.TTL > now && entry.Peer != "" {
		// update last access time under write lock
		bh.mu.Lock()
		entry.LastAccess = now
		bh.Data[key] = entry
		bh.mu.Unlock()
		//fmt.Printf("BigHolder Get: key=%d, found valid entry=%+v\n", key, entry)
		return entry.Peer, entry.IsRemote
	}
	//fmt.Printf("BigHolder Get: key=%d, found expired entry=%+v\n", key, entry)

	// Entry exists but expired → delete it
	bh.mu.Lock()
	if cur, ok := bh.Data[key]; ok && cur.TTL <= now {
		delete(bh.Data, key)
	}
	bh.mu.Unlock()

	return "", false
}

// Delete removes an entry manually.
func (bh *BigHolder) Delete(key int) {
	bh.mu.Lock()
	defer bh.mu.Unlock()
	delete(bh.Data, key)
}

// Size returns current number of entries.
func (bh *BigHolder) Size() int {
	bh.mu.RLock()
	defer bh.mu.RUnlock()
	return len(bh.Data)
}

// CleanupOldEntries continuously checks and removes entries
// not accessed within `maxAge` every 5 minutes,
// but only runs cleanup when size >= 80 million entries.
func (bh *BigHolder) CleanupOldEntries(maxAge time.Duration) {
	const cleanupThreshold = 80_000_000

	for {
		time.Sleep(5 * time.Minute)
		fmt.Printf("[Cleanup] Starting cleanup check...\n")

		bh.mu.RLock()
		size := len(bh.Data)
		bh.mu.RUnlock()

		if size < cleanupThreshold {
			continue // skip cleanup if not large enough
		}

		now := time.Now().Unix()
		expireBefore := now - int64(maxAge.Seconds())
		deleted := 0

		bh.mu.Lock()
		for key, entry := range bh.Data {
			if entry.LastAccess < expireBefore {
				delete(bh.Data, key)
				deleted++
			}
		}
		newSize := len(bh.Data)
		bh.mu.Unlock()
		fmt.Printf("[Cleanup] Deleted %d old entries (now size = %d)\n", deleted, newSize)
	}
}

// CounterMap holds a thread-safe map with int values
type CounterMap struct {
	lock sync.RWMutex
	data map[string]int
	next int // next value to assign to new keys
}

// NewCounterMap creates a new CounterMap
func NewCounterMap() *CounterMap {
	return &CounterMap{
		data: make(map[string]int),
		next: 1, // start counting from 1
	}
}

// Get returns the value for the key. If key is missing, creates it and increments the counter
func (c *CounterMap) Get(key string) int {
	// First, read lock to check if key exists
	c.lock.RLock()
	val, exists := c.data[key]
	c.lock.RUnlock()

	if exists {
		return val
	}

	// Key doesn't exist, acquire write lock
	c.lock.Lock()
	defer c.lock.Unlock()

	// Check again in case another goroutine added it
	val, exists = c.data[key]
	if exists {
		return val
	}

	// Assign next value and increment counter
	val = c.next
	c.data[key] = val
	c.next++

	return val
}

var appConfig *Config

var reStatus = regexp.MustCompile(`HTTP/[\d.]+\s+(\d{3})`)

type SOCKS5ToHTTPAdapter struct {
	EndPointConfigPath   string
	EndPointConfig       atomic.Value // stores Config
	configMu             sync.RWMutex
	AccessLog            *log.Logger
	AuthHelper           *AuthHelper
	LogChan              chan string
	AuthMapCache         *CredentialCache
	RemoteProxyPortStart int
	RemoteProxyPortEnd   int
}

// calculateHandshakeBytes estimates the bytes received during SOCKS5 handshake
func calculateHandshakeBytes(username, password string) int64 {
	// SOCKS5 handshake: version(1) + nmethods(1) + methods(nmethods)
	// + auth version(1) + username length(1) + username + password length(1) + password
	baseBytes := int64(2) // version + nmethods
	baseBytes += int64(1) // at least one method

	if username != "" && password != "" {
		baseBytes += int64(1) // auth version
		baseBytes += int64(1) // username length
		baseBytes += int64(len(username))
		baseBytes += int64(1) // password length
		baseBytes += int64(len(password))
	}

	return baseBytes
}

// calculateRequestBytes estimates the bytes received during SOCKS5 request
func calculateRequestBytes(targetAddr string) int64 {
	// SOCKS5 request: version(1) + command(1) + reserved(1) + address type(1) + address + port(2)
	baseBytes := int64(4) // version + command + reserved + address type

	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return baseBytes + int64(4) + int64(2) // default to IPv4
	}

	if net.ParseIP(host) != nil {
		if ip := net.ParseIP(host); ip.To4() != nil {
			baseBytes += int64(4) // IPv4 address
		} else {
			baseBytes += int64(16) // IPv6 address
		}
	} else {
		baseBytes += int64(1) + int64(len(host)) // domain length + domain
	}

	baseBytes += int64(2) // port

	return baseBytes
}

func (adapter *SOCKS5ToHTTPAdapter) logAccessLog(
	clientConn net.Conn,
	proxyAddr string,
	targetAddr string,
	username string,
	inBytes, outBytes int64,
	startTime time.Time,
	targetIP string,
	responseCode string,
) {
	// Skip logging if access log file is not configured
	if appConfig.AccessLogFileName == "" {
		return
	}

	duration := time.Since(startTime).Milliseconds()
	timestamp := float64(time.Now().UnixNano()) / 1e9

	localIP := "-"
	targetHost := ""

	sourceIP, _, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
	if proxyAddr != "" {
		localIP, _, _ = net.SplitHostPort(proxyAddr)
	}

	if targetAddr != "" {
		targetHost, _, _ = net.SplitHostPort(targetAddr)
	}

	logLine := fmt.Sprintf(accessLogFormat,
		timestamp,
		inBytes,
		sourceIP,
		responseCode,
		outBytes,
		targetAddr,
		username,
		targetHost,
		proxyAddr,
		duration,
		targetIP,
		localIP,
	)

	select {
	case adapter.LogChan <- logLine:
	default:
		// Drop if channel is full
		adapter.AccessLog.Printf("⚠️ logChan full — dropped log: %s", logLine)
	}
}

// generateUUID creates a simple UUID for request tracking
func generateUUID() string {
	b := make([]byte, 8)
	cryptorand.Read(b)
	return hex.EncodeToString(b)
}

// isIgnorableErr checks if an error should be ignored during data transfer
// These errors are common and expected when connections are closed or reset
func isIgnorableErr(err error) bool {
	if errors.Is(err, io.EOF) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "connection has been closed when write") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "network is unreachable")
}

func (a *SOCKS5ToHTTPAdapter) getConfig() *EndpointConfig {
	return a.EndPointConfig.Load().(*EndpointConfig)
}

func (a *SOCKS5ToHTTPAdapter) isRemoteProxy(start, end int) bool {
	if start >= a.RemoteProxyPortStart && start <= a.RemoteProxyPortEnd &&
		end >= a.RemoteProxyPortStart && end <= a.RemoteProxyPortEnd {
		return true
	}
	return false
}

func (a *SOCKS5ToHTTPAdapter) FindEndpoint(code string) (*Endpoint, error) {
	code = strings.ToLower(code)
	cfg := a.getConfig()
	if ep, exists := cfg.Endpoints[code]; exists {
		return ep, nil
	}
	return nil, fmt.Errorf("code %s not found in endpoint EndPointConfig", code)
}

func (a *SOCKS5ToHTTPAdapter) resolveProxyAddress(code, sid string, attempt int) (string, bool, error) {
	endpoint, _ := a.FindEndpoint(code)
	if endpoint == nil {
		return "", false, fmt.Errorf("code %s not found in endpoint EndPointConfig", code)
	}

	var peer Peer
	var port int

	if sid == "" {

		if attempt <= 1 && code == "rc_all" {
			entry, err := portIPMapper.GetNextDifEndpoint()
			if err != nil {
				return "", false, err
			}
			return fmt.Sprintf("%s:%d", entry.PeerIP, entry.Port), false, nil
		}
		peer = endpoint.Peers[rand.Intn(len(endpoint.Peers))]
		port, _ = strconv.Atoi(peer.RP)
		for _, pr := range peer.Ports {
			parts := strings.Split(pr, "-")
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, _ := strconv.Atoi(parts[1])
				if a.isRemoteProxy(start, end) {
					return fmt.Sprintf("%s:%d", peer.Addr, port), true, nil
				}
			}
		}
	} else {
		sidVal, err := strconv.Atoi(sid)
		if err != nil {
			return "", false, fmt.Errorf("invalid sid: %v", err)
		}
		if attempt <= 1 && code == "rc_all" {
			entry, err := portIPMapper.GetBySID(sidVal)
			if err != nil {
				return "", false, err
			}
			return fmt.Sprintf("%s:%d", entry.PeerIP, entry.Port), false, nil
		}

		sidVal += attempt
		if attempt > 0 {
			sidVal += len(endpoint.Peers) / (2 * attempt) // Ensure sidVal is always positive and within bounds
		}
		peerIndex := sidVal % len(endpoint.Peers)
		peer = endpoint.Peers[peerIndex]

		// Flatten and expand port ranges
		var portList []int
		for _, pr := range peer.Ports {
			parts := strings.Split(pr, "-")
			if len(parts) == 2 {
				start, _ := strconv.Atoi(parts[0])
				end, _ := strconv.Atoi(parts[1])

				if a.isRemoteProxy(start, end) {
					port, _ = strconv.Atoi(peer.RP)
					return fmt.Sprintf("%s:%d", peer.Addr, port), true, nil
				}

				for i := start; i <= end; i++ {
					portList = append(portList, i)
				}
			}
		}
		if len(portList) == 0 {
			return "", false, fmt.Errorf("no valid ports found for peer")
		}
		if attempt > 0 {
			sidVal += len(portList) / (2 * attempt) // Ensure sidVal is always positive and within bounds
		}
		// Use division to cycle through all ports of this peer before moving to next peer
		portIndex := (sidVal / len(endpoint.Peers)) % len(portList)
		port = portList[portIndex]
	}

	return fmt.Sprintf("%s:%d", peer.Addr, port), false, nil
}

func (adapter *SOCKS5ToHTTPAdapter) checkExternalAuth(username, password, ip string) (bool, error) {
	// Note: This function doesn't have access to requestID, so we log without it
	fmt.Printf("INFO Checking external auth for user: %s", username)
	ok, err := adapter.AuthHelper.Check(username, password, ip)
	if err != nil {
		return false, fmt.Errorf("auth script failed: %w", err)
	}
	return ok, nil
}

func bidirectionalDataCopyNoTimeout(conn1, conn2 net.Conn) {
	// Close connections when either copy completes
	go func() {
		io.Copy(conn2, conn1)
		conn1.Close()
		conn2.Close()
	}()

	io.Copy(conn1, conn2)
	conn1.Close()
	conn2.Close()
}

func bidirectionalDataCopy(conn1, conn2 net.Conn, inBytes *int64, outBytes *int64, idleTimeout time.Duration) {
	// Close connections when either copy completes
	go func() {
		copyWithIdleTimeout(conn2, conn1, inBytes, outBytes, idleTimeout)
		conn1.Close()
		conn2.Close()
	}()

	copyWithIdleTimeout(conn1, conn2, inBytes, outBytes, idleTimeout)
	conn1.Close()
	conn2.Close()
}

func copyWithIdleTimeout(dst, src net.Conn, inBytes *int64, outBytes *int64, timeout time.Duration) {
	buf := make([]byte, 32*1024)
	//fmt.Printf("DEBUG Starting copyWithIdleTimeout between %s and %s with timeout %v\n", src.RemoteAddr(), dst.RemoteAddr(), timeout)
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

func (adapter *SOCKS5ToHTTPAdapter) HandleClientOverHTTP(Type string, req *http.Request, clientConn net.Conn, tcpAddr *net.TCPAddr) (error, bool) {
	isHttp := false
	if Type == "socks5" {
		utils.SetIPZone(tcpAddr)
		rep := utils.CreateSocks5Response(tcpAddr)
		if _, err := clientConn.Write(rep); err != nil {
			return err, isHttp
		}
	} else {
		if req.Method == "CONNECT" {
			if _, err := clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
				return fmt.Errorf("error writing to client connection: %v", err), isHttp
			}
		} else {
			isHttp = true
			req.Header.Del("Proxy-Authorization")
		}
	}
	return nil, isHttp
}

func (adapter *SOCKS5ToHTTPAdapter) HandleClient(rv *request.Request) error {

	statrtTime := time.Now()
	_, isHttp := adapter.HandleClientOverHTTP(rv.Type, rv.RawRequest, rv.Conn, &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	// Generate UUID for this request
	requestID := generateUUID()
	if config.Cfg.General.Viprox_log {
		fmt.Println("[" + requestID + "] DEBUG HandleClient started: code=" + rv.Credentials.Code + " sid=" + rv.Credentials.Session + " targetAddr=" + rv.Host)
	}

	_, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	var firstBuf []byte
	gAttempts := 0
	defer func() { rv.Attempts = gAttempts }()
	// Retry logic: attempt 0 is the first attempt, so we retry up to PeerRetryAttempts times
	// Total attempts = 1 + PeerRetryAttempts
	// Access logs are only written when retries are exhausted (final attempt fails)
	for attempt := 0; attempt <= appConfig.PeerRetryAttempts; attempt++ {

		gAttempts = attempt
		if config.Cfg.General.Viprox_log {
			fmt.Println("--------------------------------------------------")
			fmt.Println("[" + requestID + "] DEBUG Attempt " + strconv.Itoa(attempt) + " of " + strconv.Itoa(appConfig.PeerRetryAttempts))
		}
		proxyAddr, isRemoteProxy, err := adapter.resolveProxyAddress(rv.Credentials.Code, rv.Credentials.OriginalSession, attempt)
		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Resolved proxyAddr: " + proxyAddr + " isRemoteProxy=" + strconv.FormatBool(isRemoteProxy))
		}

		if err != nil {
			fmt.Printf("[%s] ERROR failed to resolve proxy address for user , code %s: %v, retry: %d", requestID, rv.Credentials.Code, err, attempt)
			if attempt < appConfig.PeerRetryAttempts {
				continue // RETRY
			}
			adapter.logAccessLog(rv.Conn, "", rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "503")
			return err
		}

		rv.UpstreamProxy.IsRemote = isRemoteProxy
		// split proxyAddr into host and port
		host, portStr, _ := net.SplitHostPort(proxyAddr)
		rv.UpstreamProxy.IP = host
		port, _ := strconv.Atoi(portStr)
		rv.UpstreamProxy.Port = uint16(port)

		//proxyConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Attempting to connect to proxy: " + proxyAddr)
		}
		proxyConn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Proxy dial completed, err=" + fmt.Sprint(err))
		}
		if err != nil {
			//fmt.Printf("[%s] ERROR failed to connect to HTTP proxy %s for user : %v, retry: %d", requestID, proxyAddr, err, attempt)
			if attempt < appConfig.PeerRetryAttempts {
				rv.Error += fmt.Sprintf("proxy connection failed while tcp connect: %v; ", err)
				continue // RETRY
			}
			adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "503")
			return err
		}
		defer func() {
			proxyConn.Close()
		}()

		targetIP, _, _ := net.SplitHostPort(proxyConn.RemoteAddr().String())

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n", rv.Host)
		connectReq += fmt.Sprintf("Host: %s\r\n", rv.Host)
		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Building CONNECT request for target: " + rv.Host)
		}

		if adapter.AuthMapCache != nil && isRemoteProxy {
			//fmt.Printf("["+requestID+"] INFO Using proxy %s for target %s (remote proxy: %v, auth map cache: %v) \n", proxyAddr, rv.Host, isRemoteProxy, adapter.AuthMapCache != nil)
			uname, pass, ok := adapter.AuthMapCache.GetCredentials(strings.ToLower(rv.Credentials.Code))
			if ok {
				if rv.Credentials.Session != "" {
					//str := strconv.Itoa(intSid)
					uname = uname + "-" + rv.Credentials.OriginalSession
				}
				//fmt.Printf("[%s] INFO Adding Proxy-Authorization header for user: %s", requestID, uname)
				authHeader := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", uname, pass)))
				connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", authHeader)
			}

			rv.UpstreamProxy.Username = uname
			rv.UpstreamProxy.Password = pass
		}
		connectReq += "Connection: keep-alive\r\n"
		connectReq += "Accept: */*\r\n\r\n"

		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Sending CONNECT request to proxy")
		}
		if _, err := proxyConn.Write([]byte(connectReq)); err != nil {
			fmt.Printf("[%s] ERROR failed to send HTTP CONNECT to %s for user : %s, retry: %d, err: %v", requestID, proxyAddr, rv.Host, attempt, err)
			//fmt.Printf("[%s] ERROR failed to send HTTP CONNECT to %s for user : %v, retry: %d", requestID, proxyAddr, err, attempt)
			rv.Error += fmt.Sprintf("failed to send HTTP CONNECT: %v; ", err)
			proxyConn.Close()
			if attempt < appConfig.PeerRetryAttempts {
				continue // RETRY
			}
			adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "502")
			return err
		}

		timeout := time.Duration(appConfig.ConnectTimeout) * time.Second // pick whatever you want
		if timeout == 0 {
			timeout = 2 * time.Second
		}
		proxyConn.SetReadDeadline(time.Now().Add(timeout))
		// Parse HTTP proxy response

		proxyReader := bufio.NewReader(proxyConn)
		statusLine, err := proxyReader.ReadString('\n')

		if err != nil || !strings.Contains(statusLine, "200") {
			if err == nil {
				fmt.Printf("[%s] ERROR proxy returned non-200 status on %s for user : %s, retry: %d, status line: %s", requestID, proxyAddr, rv.Host, attempt, statusLine)
				adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, strings.TrimSpace(statusLine))
				if attempt < appConfig.PeerRetryAttempts {
					continue // RETRY
				}
				//fmt.Printf("[%s] ERROR proxy returned non-200 status on %s for user : %s, retry: %d, status line: %s", requestID, proxyAddr, statusLine, attempt, statusLine)
				return fmt.Errorf("proxy returned non-200 status: %s", strings.TrimSpace(statusLine))
			}
			//fmt.Printf("[%s] ERROR proxy connection failed on %s for user : %s, retry: %d err: %v %s", requestID, proxyAddr, statusLine, attempt, err, rv.Host)
			rv.Error += fmt.Sprintf("proxy connection failed while connecting: %v; ", err)
			proxyConn.Close()
			if attempt < appConfig.PeerRetryAttempts {
				continue // RETRY
			}
			adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "505")
			return err
		}

		// Drain remaining headers
		for {
			line, err := proxyReader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}

		// --- NEW: read and store first bytes from client (before entering copy goroutines) ---
		if len(firstBuf) == 0 {
			// small timeout to avoid blocking indefinitely if client doesn't send immediately
			if config.Cfg.General.Viprox_log {
				fmt.Println("["+requestID+"] DEBUG Reading initial bytes from client", isHttp, rv.Port)
			}

			if isHttp {

				// For HTTP, we may have already read some bytes from the client (the initial request)
				// so set the inBytes accordingly and prepare to forward that to the proxy before starting the tunnel
				var buf strings.Builder
				if err := rv.RawRequest.WriteProxy(&buf); err != nil {
					adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "502")
					return fmt.Errorf("error writing proxy request: %v", err)
				}
				firstBuf = []byte(buf.String())
				atomic.AddInt64(&rv.InBytes, int64(len(firstBuf)))
			} else if rv.EndPort == "443" {

				//clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				tmp := make([]byte, 4*1024) // read up to 4KB initial chunk
				n, rerr := rv.Conn.Read(tmp)
				if config.Cfg.General.Viprox_log {
					fmt.Println("[" + requestID + "] DEBUG Read " + strconv.Itoa(n) + " bytes from client, err=" + fmt.Sprint(rerr))
				}
				// clear deadline
				//clientConn.SetReadDeadline(time.Time{})
				if n > 0 {
					// copy to owned slice
					firstBuf = append([]byte(nil), tmp[:n]...)
					//fmt.Printf("[%s] INFO read %d initial bytes from client to replay on proxy", requestID, n)
				}
				if rerr != nil {
					// if it's not just a timeout/EOF, treat as error
					fmt.Printf("[%s] WARN error reading initial bytes from client: %v", requestID, rerr)
					adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "400")
					return rerr
					// continue — we'll try with what we have (possibly zero-length)
				}
			}
		}

		// If we have initial bytes, attempt to send them to proxy now.
		if len(firstBuf) > 0 {
			if config.Cfg.General.Viprox_log {
				fmt.Println("[" + requestID + "] DEBUG Writing " + strconv.Itoa(len(firstBuf)) + " initial bytes to proxy")
			}
			//proxyConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			wn, werr := proxyConn.Write(firstBuf)
			if config.Cfg.General.Viprox_log {
				fmt.Println("[" + requestID + "] DEBUG Wrote " + strconv.Itoa(wn) + " bytes to proxy, err=" + fmt.Sprint(werr))
			}
			//fmt.Printf("**************bolo wn=%d, werr=%v\n", wn, werr)
			//proxyConn.SetWriteDeadline(time.Time{})
			if werr != nil || wn == 0 {
				fmt.Printf("[%s] *********** ERROR failed to write initial bytes to proxy %s for user : wn=%d err=%v, retry: %d", requestID, proxyAddr, wn, werr, attempt)
				proxyConn.Close()
				rv.Error += fmt.Sprintf("failed to write initial bytes to proxy: %v; ", werr)
				// if we still have attempts left, continue to retry with next proxy
				if attempt < appConfig.PeerRetryAttempts {
					continue
				}
				adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "502")
				// otherwise log and return
				return fmt.Errorf("failed to write initial bytes to proxy: %w", werr)
			}
			//fmt.Printf("[%s] INFO wrote %d initial bytes to proxy %s for user %s", requestID, wn, proxyAddr, username)
		}

		if len(firstBuf) > 0 && readAndForwardInitial(proxyConn, rv.Conn, 10000*time.Millisecond) {
			fmt.Printf("[%s] ERROR proxy connection closed by peer on %s for user , retry: %d", requestID, proxyAddr, attempt)
			rv.Error += "proxy connection closed by peer; "
			proxyConn.Close()
			if attempt < appConfig.PeerRetryAttempts {
				continue // RETRY
			}
			adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, 0, 0, statrtTime, rv.Host, "502")
			return fmt.Errorf("failed to write initial bytes to proxy: connection closed")
		}

		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Starting bidirectional data copy")
		}
		var inBytes, outBytes int64
		if IdlePeerTimeout := appConfig.IdlePeerTimeout; IdlePeerTimeout > 0 {
			bidirectionalDataCopy(proxyConn, rv.Conn, &inBytes, &outBytes, time.Duration(IdlePeerTimeout)*time.Second)
		} else {
			bidirectionalDataCopyNoTimeout(proxyConn, rv.Conn)
		}
		rv.Success = true
		adapter.logAccessLog(rv.Conn, proxyAddr, rv.Host, rv.Credentials.User, rv.InBytes, rv.OutBytes, statrtTime, targetIP, "200")
		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Data copy completed, inBytes=" + strconv.FormatInt(inBytes, 10) + " outBytes=" + strconv.FormatInt(outBytes, 10))
		}

		if config.Cfg.General.Viprox_log {
			fmt.Println("[" + requestID + "] DEBUG Breaking out of retry loop, connection successful")
		}
		break
	}

	if config.Cfg.General.Viprox_log {
		fmt.Println("[" + requestID + "] DEBUG HandleClient completed successfully")
	}
	return nil
}

// readAndForwardInitial reads from proxyConn with a short timeout
// and forwards any bytes to clientConn. Returns error if the proxy connection is closed/broken.
func readAndForwardInitial(proxyConn, clientConn net.Conn, timeout time.Duration) bool {
	if config.Cfg.General.Viprox_log {
		fmt.Println("DEBUG readAndForwardInitial: Setting read deadline")
	}
	proxyConn.SetReadDeadline(time.Now().Add(timeout))
	defer proxyConn.SetReadDeadline(time.Time{}) // reset deadline

	buf := make([]byte, 1*1024) // 1KB initial buffer
	if config.Cfg.General.Viprox_log {
		fmt.Println("DEBUG readAndForwardInitial: Reading from proxy connection")
	}
	n, err := proxyConn.Read(buf)
	if config.Cfg.General.Viprox_log {
		fmt.Println("DEBUG readAndForwardInitial: Read " + strconv.Itoa(n) + " bytes, err=" + fmt.Sprint(err))
	}
	if n > 0 {
		if config.Cfg.General.Viprox_log {
			fmt.Println("DEBUG readAndForwardInitial: Forwarding " + strconv.Itoa(n) + " bytes to client")
		}
		clientConn.Write(buf[:n])

		//fmt.Printf("INFO forwarded %d initial bytes from proxy to client", n)
		return false
	}
	if config.Cfg.General.Viprox_log {
		fmt.Println("ERROR readAndForwardInitial: no data read from proxy during initial read, err=" + fmt.Sprint(err))
	}
	return true //retry
}

var Adapter *SOCKS5ToHTTPAdapter

func init() {
	configPath := "viprox.json"

	const N = 100_000_000
	BigHolderInstance = NewBigHolder(N)
	CounterMapInstance = NewCounterMap()

	go BigHolderInstance.CleanupOldEntries(8 * time.Hour)

	appConfig = LoadConfigOrDefault(configPath)

	if appConfig.DebugLogFileName != "" {
		log.SetOutput(&lumberjack.Logger{
			Filename:   filepath.Join(appConfig.LogPath, appConfig.DebugLogFileName),
			MaxSize:    10,
			MaxBackups: 3,
			MaxAge:     30,
			Compress:   true,
		})
	}

	accessLogger := log.New(os.Stdout, "", log.LstdFlags)
	if appConfig.AccessLogFileName != "" {
		accessLogger = log.New(&lumberjack.Logger{
			Filename:   filepath.Join(appConfig.LogPath, appConfig.AccessLogFileName),
			MaxSize:    100,
			MaxBackups: 20,
			MaxAge:     14,
			Compress:   true,
		}, "", 0)
	}

	Adapter = &SOCKS5ToHTTPAdapter{
		EndPointConfigPath: appConfig.EndpointConfFile,
		AccessLog:          accessLogger,
		LogChan:            make(chan string, 1000),
	}

	parts := strings.Split(appConfig.RemoteProxyPortRange, "-")

	start, err1 := strconv.Atoi(parts[0])
	end, err2 := strconv.Atoi(parts[1])

	if err1 != nil || err2 != nil {
		fmt.Println("ERROR Invalid Remote Proxy Range")
		return
	}

	Adapter.RemoteProxyPortStart = start
	Adapter.RemoteProxyPortEnd = end

	ctx, cancel := context.WithCancel(context.Background())
	// Don't defer cancel here - let it run for the lifetime of the app
	_ = cancel // Keep reference for future cleanup if needed

	go func() {
		fmt.Println("INFO Starting endpoint config reloader", appConfig.EndpointRefreshInterval, appConfig.EndpointUrl)
		ticker := time.NewTicker(time.Duration(appConfig.EndpointRefreshInterval) * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// fetch file from url wget http://198.24.187.90/navepsul_endpoints.conf
				// at appConfig.EndpointConfFile
				fmt.Println("INFO Checking for endpoint config updates...")
				if appConfig.EndpointUrl != "" {
					fmt.Println("INFO Fetching endpoint config from ", appConfig.EndpointUrl)
					tmpFile := Adapter.EndPointConfigPath + ".tmp"
					cmd := exec.Command("wget", appConfig.EndpointUrl, "-O", tmpFile)
					if err := cmd.Run(); err != nil {
						fmt.Println("ERROR Failed to fetch endpoint config: ", err)
						os.Remove(tmpFile) // clean up partial file
						continue
					}

					// replace only after success
					os.Rename(tmpFile, Adapter.EndPointConfigPath)
				}

				data, err := os.ReadFile(Adapter.EndPointConfigPath)
				if err != nil {
					fmt.Printf("ERROR Failed to reload EndPointConfig: %v", err)
					continue
				}
				var cfg EndpointConfig
				if err := json.Unmarshal(data, &cfg); err != nil {
					fmt.Printf("ERROR Invalid EndPointConfig format: %v", err)
					continue
				}
				Adapter.EndPointConfig.Store(&cfg)
				fmt.Println("INFO endpoint.conf reloaded with", len(cfg.Endpoints), "endpoints")
			case <-ctx.Done():
				fmt.Println("INFO Stopping endpoint config reloader")
				return
			}
		}
	}()

	fmt.Println("INFO Loading initial endpoint config from file: " + Adapter.EndPointConfigPath)
	data, err := os.ReadFile(Adapter.EndPointConfigPath)
	if err != nil {
		fmt.Println("ERROR failed to read endpoint EndPointConfig:", err)
		log.Fatalf("ERROR failed to read endpoint EndPointConfig: %v", err)
	}
	fmt.Printf("INFO Initial endpoint config loaded, size=%d bytes", len(data))

	var initialCfg EndpointConfig
	if err := json.Unmarshal(data, &initialCfg); err != nil {
		fmt.Println("ERROR failed to parse endpoint EndPointConfig:", err)
		log.Println("err steps8")
		log.Fatalf("ERROR failed to parse EndPointConfig: %v", err)
	}
	Adapter.EndPointConfig.Store(&initialCfg)
	fmt.Printf("INFO Initial endpoint config parsed successfully, endpoints=%d\n", len(initialCfg.Endpoints))

	authHelper := NewAuthHelper(ctx, appConfig.DBAuthPath, appConfig.IPAuthPath)
	Adapter.AuthHelper = authHelper

	if appConfig.AuthMapFile != "" {
		Adapter.AuthMapCache = NewCredentialCache()
		err = Adapter.AuthMapCache.LoadFromFile(appConfig.AuthMapFile)
		if err != nil {
			fmt.Printf("ERROR Failed to load credentials: %v\n", err)
			return
		}
	}

	go func() {
		for {
			select {
			case line, ok := <-Adapter.LogChan:
				if !ok {
					return
				}
				Adapter.AccessLog.Println(line)
			case <-ctx.Done():
				return
			}
		}
	}()

	portIPMapper = NewPortIPMapper(appConfig.EndpointConfFile, 0, 0)
	portIPMapper.Start(Adapter)

	/*defer func() {
		cancel()
		close(adapter.LogChan)
	}()*/
}
