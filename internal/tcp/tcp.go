package tcp

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/config"
	"slickproxy/internal/protocol/http"
	"slickproxy/internal/protocol/socks5"
	"slickproxy/internal/stats"
	"slickproxy/internal/userdb"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ConnMap sync.Map // Global sync.Map to hold source IPs of active connections

func SetSocketOptions(fd uintptr) error {
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, unix.TCP_DEFER_ACCEPT, 1); err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 2*1024*1024); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 2*1024*1024); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
		return err
	}
	//log.Println("Socket options set successfully")

	return nil
}

func StartTcpServer(port uint16) {
	listener, err := createListener(port)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error on port %d: %v", port, err)
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// For permanent errors, try to recreate the listener
			log.Printf("Permanent error on port %d, attempting to recreate listener", port)
			listener.Close()

			newListener, newErr := createListener(port)
			if newErr != nil {
				log.Fatalf("Failed to recreate listener on port %d: %v", port, newErr)
			}

			listener = newListener
			log.Printf("Listener recreated successfully on port %d", port)
			continue
		}

		if userdb.CpuOverThreshold || userdb.FdThreshold {
			log.Printf("CPU or FD over threshold, rejecting connection: CPU=%v, FD=%v", userdb.CpuOverThreshold, userdb.FdThreshold)
			conn.Close()
			continue
		}

		go handleConnection(conn)
	}
}

func createListener(port uint16) (net.Listener, error) {
	var lc net.ListenConfig

	lc.Control = func(network, address string, c syscall.RawConn) error {
		var err error
		err = c.Control(func(fd uintptr) {
			err = SetSocketOptions(fd)
		})
		return err
	}

	// Retry for 10 seconds in case port is in TIME_WAIT state
	retryDeadline := time.Now().Add(10 * time.Second)
	var listener net.Listener
	var err error
	for {
		listener, err = lc.Listen(context.Background(), "tcp", ":"+strconv.Itoa(int(port)))
		if err == nil {
			return listener, nil
		}

		// Check if we've exceeded the retry deadline
		if time.Now().After(retryDeadline) {
			return nil, fmt.Errorf("failed to bind to port %d after 10 seconds: %v", port, err)
		}

		// Wait before retrying
		time.Sleep(100 * time.Millisecond)
	}
}

func handleConnection(c net.Conn) {
	defer c.Close()
	var dataStore userdb.DataStore
	dataStore.GlobalBlacklistDomains = userdb.GlobalBlacklistDomains
	dataStore.GlobalBlacklistPorts = userdb.GlobalBlacklistPorts
	dataStore.Users = userdb.Users

	var err error
	reader := bufio.NewReader(c)
	buf, err := reader.Peek(1)
	if err != nil {
		return
	}

	statsReq := stats.NewRequest()

	if config.Cfg.Stats.Enabled {
		statsReq.ClientIP = c.RemoteAddr().String()
	}

	rv := clientrequest.NewRequest(c, "http")

	// Check if SOCKS5 is disabled before handling
	if isSocks5Request(buf) && config.Cfg.General.Socks5Disabled {
		log.Printf("SOCKS5 request received but SOCKS5 is disabled, closing connection from %s", c.RemoteAddr().String())
		return
	}

	if isSocks5Request(buf) {
		rv, err = socks5.HandleSOCKS5Connection(reader, c, dataStore)
	} else {
		rv, err = http.HandleHTTPRequest(reader, c, dataStore)
	}
	if config.Cfg.Stats.Enabled {
		statsReq.Type = rv.Type
		statsReq.Host = rv.Host
		statsReq.Bytes = rv.Bytes
		statsReq.User = rv.Credentials.User
		statsReq.Country = rv.Credentials.Country
		statsReq.Session = rv.Credentials.Session
		statsReq.Password = rv.Credentials.Password
		statsReq.City = rv.Credentials.City
		statsReq.State = rv.Credentials.State
		statsReq.Code = rv.Credentials.Code
		statsReq.UpstreamProxyIp = rv.UpstreamProxy.IP
		statsReq.UpstreamProxyPort = int(rv.UpstreamProxy.Port)
		statsReq.UpstreamProxyUser = rv.UpstreamProxy.Username
		statsReq.UpstreamProxyPass = rv.UpstreamProxy.Password
		statsReq.UpstreamProxyRemote = rv.UpstreamProxy.IsRemote
		statsReq.Success = rv.Success
		statsReq.Attempts = rv.Attempts
		if err != nil {
			statsReq.Error = err.Error()
		}
		statsReq.Error += rv.Error

	}

	if err != nil {

		return
	}

	err = stats.AddStatsRequest(statsReq)
	if err != nil {
		fmt.Printf("Failed to add stats request: %v", err)
	}
}

func isSocks5Request(buf []byte) bool {
	return len(buf) >= 1 && buf[0] == 0x05
}
