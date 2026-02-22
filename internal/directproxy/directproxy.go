package directproxy

import (
	"fmt"
	"log"
	"net"
	"os"
	"slickproxy/internal/bandwidthtracker"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/dns"
	"slickproxy/internal/userdb"
	"slickproxy/internal/utils"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"slickproxy/internal/config"
)

const (
	InitialInterval = 1 * time.Millisecond
	MaxInterval     = 15 * time.Millisecond
	MaxElapsedTime  = 10 * time.Second
	ReadTimeout     = 10 * time.Second
)

func HandleRequestLocal(rv clientrequest.Request) error {
	rv.Credentials.UserDetail.TotalQuota = 0
	trackedConn := bandwidthtracker.NewBandwidthTrackedConnection(&rv)
	defer trackedConn.Close()
	rv.Conn = trackedConn
	err := attemptDirectConnection(rv)
	return err
}

func attemptDirectConnection(rv clientrequest.Request) error {
	return createDirectConnection(rv)
}

func establishTCPConnection(localIP net.IP, localPort int, remoteIP string, remotePort string) (net.Conn, error, int) {
	parsedRemoteIP := net.ParseIP(remoteIP)
	if parsedRemoteIP == nil {
		return nil, fmt.Errorf("invalid remote IP address: %v", remoteIP), 0
	}

	parsedRemotePort, err := strconv.Atoi(remotePort)
	if err != nil {
		return nil, fmt.Errorf("invalid remote port: %v", remotePort), 0
	}

	var fd int
	var saLocal, saRemote syscall.Sockaddr

	if parsedRemoteIP.To4() != nil {

		fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv4 socket: %v", err), 0
		}

		localSockAddr := &syscall.SockaddrInet4{}
		if localIP != nil {
			copy(localSockAddr.Addr[:], localIP.To4())
		}
		localSockAddr.Port = localPort
		saLocal = localSockAddr

		remoteSockAddr := &syscall.SockaddrInet4{}
		copy(remoteSockAddr.Addr[:], parsedRemoteIP.To4())
		remoteSockAddr.Port = parsedRemotePort
		saRemote = remoteSockAddr
	} else if parsedRemoteIP.To16() != nil {

		fd, err = syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
		if err != nil {
			return nil, fmt.Errorf("failed to create IPv6 socket: %v", err), 0
		}

		localSockAddr := &syscall.SockaddrInet6{}
		if localIP != nil {
			copy(localSockAddr.Addr[:], localIP.To16())
		}
		localSockAddr.Port = localPort
		saLocal = localSockAddr

		remoteSockAddr := &syscall.SockaddrInet6{}
		copy(remoteSockAddr.Addr[:], parsedRemoteIP.To16())
		remoteSockAddr.Port = parsedRemotePort
		saRemote = remoteSockAddr
	} else {
		return nil, fmt.Errorf("unsupported address type for remote IP: %v", remoteIP), 0
	}

	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set SO_REUSEADDR: %v", err), 0
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IP_TRANSPARENT: %v", err), 0
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set non-blocking: %v", err), 0
	}

	if saLocal != nil {
		err := syscall.Bind(fd, saLocal)
		if err != nil {
			syscall.Close(fd)
			return nil, fmt.Errorf("failed to bind socket: %v", err), 0
		}
	}

	err = syscall.Connect(fd, saRemote)
	if err != nil && err != syscall.EINPROGRESS && err != syscall.EALREADY {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to connect to remote address: %v", err), 0
	}

	file := os.NewFile(uintptr(fd), "")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to create net.Conn: %v, fd: %d", err, fd), 0
	}

	return conn, nil, fd
}

func createDirectConnection(rv clientrequest.Request) error {
	rv.Credentials.UserDetail.Dirty = true
	host, ip, err := resolveIPForRequest(rv)
	if err != nil {
		log.Println("DNS lookup error:", err, rv.Domain)
		return err
	}
	if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
			atomic.StoreInt64(&config.UserMetricsObj.ActiveUsers, 1)
		}
	}
	defer func() {

		if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {

			if atomic.LoadInt64(rv.Credentials.UserDetail.CurrentActiveConnections) == 0 {
				atomic.StoreInt64(&config.UserMetricsObj.ActiveUsers, -1)
			}

		}
	}()

	atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, 1)
	defer atomic.AddInt64(rv.Credentials.UserDetail.CurrentActiveConnections, -1)
	atomic.AddInt64(&userdb.CurrentActiveConnections, 1)
	defer atomic.AddInt64(&userdb.CurrentActiveConnections, -1)
	atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, 1)
	defer atomic.AddInt64(&config.UserMetricsObj.ActiveConnections, -1)

	var dialHost string
	if rv.Type == "http" {
		dialHost = host
	} else {
		dialHost = host
	}

	dialConn, err, fd := establishTCPConnection(ip, 0, dialHost, rv.EndPort)
	if err != nil {
		log.Println("Connection error:", err, rv.Domain, dialHost)

		return err
	}

	proxyConn := clientrequest.NewProxyConn(dialConn, fd)
	defer func() {

	}()

	if rv.Type == "http" {
		if rv.RawRequest.Method == "CONNECT" {
			return handleHTTPSConnection(rv, proxyConn)
		} else {
			return handleHTTPConnection(rv, proxyConn)
		}
	} else {
		return handleSOCKS5Connection(rv, proxyConn)
	}
}

func handleHTTPConnection(rv clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if err := rv.RawRequest.Write(proxyConn.Conn); err != nil {
		proxyConn.Close()
		return err
	}
	relayBidirectionalTraffic(rv.Conn, proxyConn.Conn)
	return nil
}

func relayBidirectionalTraffic(conn1, conn2 net.Conn) {
	idleTimeout := 1 * time.Minute

	go func() {
		copyDataWithIdleTimeout(conn2, conn1, idleTimeout, false)
		conn1.Close()
		conn2.Close()
	}()

	copyDataWithIdleTimeout(conn1, conn2, idleTimeout, true)
	conn1.Close()
	conn2.Close()
}

func copyDataWithIdleTimeout(dst, src net.Conn, timeout time.Duration, shortFirstTimeout bool) {
	buf := make([]byte, 32*1024)
	firstRead := shortFirstTimeout

	for {

		currentTimeout := timeout
		if firstRead {
			currentTimeout = 20 * time.Second
			firstRead = false
		}

		src.SetReadDeadline(time.Now().Add(currentTimeout))
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

func handleHTTPSConnection(rv clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	if _, err := rv.Conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
		log.Println("Error writing 200 OK:", err, rv.Domain)
		proxyConn.Close()
		return err
	}
	relayBidirectionalTraffic(rv.Conn, proxyConn.Conn)

	return nil
}

func handleSOCKS5Connection(rv clientrequest.Request, proxyConn clientrequest.ProxyConn) error {
	tcpAddr := proxyConn.Conn.LocalAddr().(*net.TCPAddr)
	utils.SetIPZone(tcpAddr)
	rep := utils.CreateSocks5Response(tcpAddr)

	if _, err := rv.Conn.Write(rep); err != nil {
		log.Println("Error writing SOCKS5 response:", err, rv.Domain)
		proxyConn.Close()
		return err
	}
	relayBidirectionalTraffic(rv.Conn, proxyConn.Conn)
	return nil
}

var num uint64

func resolveIPForRequest(rv clientrequest.Request) (string, net.IP, error) {
	var host string
	var err error
	var ip net.IP

	ip1, exists := rv.Credentials.UserDetail.PortToIP[uint16(rv.Port)]
	if exists {
		outIp := net.ParseIP(ip1)
		host, err = dns.Cache.LookupAndCache(rv.Domain, outIp.To4() != nil)
		if err != nil {
			return "", nil, err
		}
		return host, outIp, nil
	}

	if rv.Credentials.IpMode == userdb.IPv4V6Mode {
		num = num + 1
		rv.Credentials.IpMode = userdb.IPVersion(num % 2)
	}
	var epochTime int64
	if rv.Credentials.UserDetail.RotationIntervalSec != 0 {

		epochTime = config.Ct.CurrentTime().Unix()
	}

	if rv.Credentials.IpMode == userdb.IPv6Mode && len(rv.Credentials.UserDetail.ProxyIPListv6) != 0 {
		host, err = dns.Cache.LookupAndCache(rv.Domain, false)
		if err != nil {
			return "", nil, err
		}
		if rv.Credentials.Session != "" {
			ip, _ = RetrieveIPv6ForSessionKey(rv.Credentials.Session, rv.Credentials.Time, rv.Credentials.UserDetail)
		} else if rv.Credentials.UserDetail.RotationIntervalSec == 0 || (rv.Credentials.UserDetail.LastIpTime == 0 || (rv.Credentials.UserDetail.LastIpTime+int64(rv.Credentials.UserDetail.RotationIntervalSec)) > epochTime) {
			ip, _ = RetrieveRandomIPv6Address(rv.Credentials.UserDetail.ProxyIPListv6)
			rv.Credentials.UserDetail.LastIpTime = epochTime

			if rv.Credentials.UserDetail.RotationIntervalSec != 0 {
				rv.Credentials.UserDetail.Mu.Lock()
				defer rv.Credentials.UserDetail.Mu.Unlock()
				rv.Credentials.UserDetail.LastIp = ip
				rv.Credentials.UserDetail.LastIpTime = epochTime
			}
		} else {
			rv.Credentials.UserDetail.Mu.Lock()
			defer rv.Credentials.UserDetail.Mu.Unlock()
			ip = rv.Credentials.UserDetail.LastIp
		}
	} else if len(rv.Credentials.UserDetail.ProxyIPListv4) != 0 && rv.Credentials.UserDetail.ProxyIP != "" {

		host, err = dns.Cache.LookupAndCache(rv.Domain, true)
		if err != nil {
			return "", nil, err
		}
		if rv.Credentials.Session != "" {
			ip, _ = RetrieveIPv4ForSessionKey(rv.Credentials.Session, rv.Credentials.Time, rv.Credentials.UserDetail)
		} else if rv.Credentials.UserDetail.RotationIntervalSec == 0 || (rv.Credentials.UserDetail.LastIpTime == 0 || (rv.Credentials.UserDetail.LastIpTime+int64(rv.Credentials.UserDetail.RotationIntervalSec)) > epochTime) {
			ip, _ = RetrieveRandomIPv4Address(rv.Credentials.UserDetail.ProxyIPListv4)

			if rv.Credentials.UserDetail.RotationIntervalSec != 0 {
				rv.Credentials.UserDetail.Mu.Lock()
				defer rv.Credentials.UserDetail.Mu.Unlock()
				rv.Credentials.UserDetail.LastIp = ip
				rv.Credentials.UserDetail.LastIpTime = epochTime
			}

		} else {
			log.Printf("Reusing IPv4 %s for user %s\n", rv.Credentials.UserDetail.LastIp.String(), rv.Credentials.User)
			rv.Credentials.UserDetail.Mu.Lock()
			defer rv.Credentials.UserDetail.Mu.Unlock()
			ip = rv.Credentials.UserDetail.LastIp

		}
	} else {
		host, err = dns.Cache.LookupAndCache(rv.Domain, true)
		if err != nil {
			return "", nil, err
		}

		ip = net.ParseIP(rv.Credentials.UserDetail.ProxyIP)
		if rv.Credentials.UserDetail.ProxyIP == "" {

			ip = net.ParseIP(rv.LocalIP.String())
		}

	}

	return host, ip, nil
}
