package udp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/config"
	"slickproxy/internal/utils"
	"strconv"
	"sync"
	"time"
)

// ATYP address type of following address declaration
const (
	// AddressIPv4 IP V4 address: X'01'
	AddressIPv4 = uint8(1)
	// AddressDomainName DOMAINNAME: X'03'
	AddressDomainName = uint8(3)
	// AddressIPv6 IP V6 address: X'04'
	AddressIPv6 = uint8(4)
)

const maxUDPPacketSize = 65535 // Max UDP datagram size

// ClientAddr stores the client's IP and port for validation
type ClientAddr struct {
	IP       string // Client's IP address
	Port     int    // Client's source port
	Declared bool   // True if client declared address, false if using 0.0.0.0:0 fallback
	ProxyIP  net.IP // Selected proxy IP for outbound connections
}

var ConnMap sync.Map // Global sync.Map to hold ClientAddr for active connections (used when UDPEphemeralPort is disabled)

// connMapKey creates a key for the ConnMap using srcIP and srcPort
// If port is 0, it represents an undeclared client (fallback case)
func connMapKey(srcIP string, srcPort int) string {
	return fmt.Sprintf("%s:%d", srcIP, srcPort)
}

var errUnrecognizedAddrType = fmt.Errorf("unrecognized address type")

var udpPacketBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxUDPPacketSize)
	},
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func HandleUDPStart(rv *clientrequest.Request) error {
	// Extract the server-side IP from the TCP connection (where client connected to)
	tcpAddr, ok := rv.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("failed to get TCP local address")
	}
	localIP := tcpAddr.IP

	// Choose implementation based on config
	if config.Cfg.General.UDPEphemeralPort {
		return handleUDPStartEphemeral(rv, localIP)
	} else {
		return handleUDPStartConnMap(rv, localIP)
	}
}

// handleUDPStartEphemeral creates a dedicated UDP listener on an ephemeral port for each session
func handleUDPStartEphemeral(rv *clientrequest.Request, localIP net.IP) error {
	// Get client address for validation
	// Prefer client-declared address from SOCKS5 ASSOCIATE, fall back to TCP source
	clientIP := rv.UdpClientIP
	clientPort := rv.UdpClientPort

	// If client didn't declare (0.0.0.0:0), use TCP connection source
	declaredAddr := true
	if clientIP == "" || clientIP == "0.0.0.0" || clientIP == "::" || clientPort == 0 {
		declaredAddr = false
		remoteAddrStr := rv.Conn.RemoteAddr().String()
		var err error
		clientIP, _, err = net.SplitHostPort(remoteAddrStr)
		if err != nil {
			return fmt.Errorf("failed to parse client address %s: %w", remoteAddrStr, err)
		}
		clientPortStr := ""
		_, clientPortStr, err = net.SplitHostPort(remoteAddrStr)
		if err != nil {
			return fmt.Errorf("failed to parse client address %s: %w", remoteAddrStr, err)
		}
		var portErr error
		clientPort, portErr = strconv.Atoi(clientPortStr)
		if portErr != nil {
			return fmt.Errorf("failed to parse client port %s: %w", clientPortStr, portErr)
		}
		log.Printf("Client didn't declare UDP address, using TCP source %s:%d (IP validation only)", clientIP, clientPort)
	} else {
		log.Printf("Using client-declared UDP address from SOCKS5 ASSOCIATE: %s:%d (strict IP:port validation)", clientIP, clientPort)
	}

	// Create a dedicated UDP listener for this session on an ephemeral port
	listenAddr := &net.UDPAddr{
		IP:   localIP, // Bind to the selected proxy IP
		Port: 0,       // OS assigns ephemeral port
	}
	udpListener, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		log.Printf("Failed to create UDP listener: %v", err)
		return fmt.Errorf("failed to create UDP listener: %w", err)
	}
	defer udpListener.Close()

	// Get the actual port assigned by OS
	localAddr := udpListener.LocalAddr().(*net.UDPAddr)
	assignedPort := localAddr.Port
	log.Printf("Created UDP listener for client %s:%d on port %d", clientIP, clientPort, assignedPort)

	// Send SOCKS5 UDP ASSOCIATE response with the listener port
	tcpAddr := rv.Conn.LocalAddr().(*net.TCPAddr)
	utils.SetIPZone(tcpAddr)

	// Create response with the ephemeral UDP port
	responseAddr := &net.TCPAddr{
		IP:   tcpAddr.IP,
		Port: assignedPort, // Return the UDP listener port
	}
	rep := utils.CreateSocks5Response(responseAddr)
	if _, err := rv.Conn.Write(rep); err != nil {
		return fmt.Errorf("failed to send UDP ASSOCIATE response: %w", err)
	}

	// Create client address context for validation
	clientAddr := &ClientAddr{
		IP:       clientIP,
		Port:     clientPort,
		Declared: declaredAddr,
	}

	// Start goroutine to monitor TCP connection closure
	tcpClosedChan := make(chan struct{})
	go monitorTCPClosure(rv.Conn, tcpClosedChan)

	// Listen for UDP packets on the dedicated listener
	return listenAndForwardUDPEphemeral(udpListener, tcpClosedChan, clientAddr, rv)
}

// monitorTCPClosure watches the TCP control connection for closure
func monitorTCPClosure(conn net.Conn, closedChan chan struct{}) {
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("TCP connection closed: %v", err)
			} else {
				log.Printf("TCP connection closed gracefully")
			}
			close(closedChan)
			return
		}
	}
}

// listenAndForwardUDPEphemeral listens for UDP packets and forwards them (ephemeral mode)
func listenAndForwardUDPEphemeral(udpListener *net.UDPConn, tcpClosedChan chan struct{}, clientAddr *ClientAddr, rv *clientrequest.Request) error {
	for {
		buffer := getUDPPacketBuffer() // Get from pool

		// Set deadline to periodically check if TCP is closed
		udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, remoteAddr, err := udpListener.ReadFromUDP(buffer)

		// Check if TCP was closed
		select {
		case <-tcpClosedChan:
			log.Printf("TCP connection closed, stopping UDP relay")
			putUDPPacketBuffer(buffer) // Return to pool
			return nil
		default:
		}

		if err != nil {
			putUDPPacketBuffer(buffer) // Return to pool on error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout is expected, continue listening
				continue
			}
			if err == io.EOF {
				break
			}
			log.Printf("UDP listener error: %v", err)
			return err
		}

		// Validate source IP and port match registered client
		srcIP := remoteAddr.IP.String()
		srcPort := remoteAddr.Port

		// If address was declared, validate both IP and port
		// If not declared (0.0.0.0:0), only validate IP
		if clientAddr.Declared {
			if srcIP != clientAddr.IP || srcPort != clientAddr.Port {
				log.Printf("UDP packet from unexpected source %s:%d (expected declared %s:%d), dropping", srcIP, srcPort, clientAddr.IP, clientAddr.Port)
				putUDPPacketBuffer(buffer)
				continue
			}
		} else {
			if srcIP != clientAddr.IP {
				log.Printf("UDP packet from unexpected source IP %s (expected %s), dropping (port varies: got %d)", srcIP, clientAddr.IP, srcPort)
				putUDPPacketBuffer(buffer)
				continue
			}
		}

		// Process the UDP packet - copy from buffer to another pool buffer
		pktBuffer := getUDPPacketBuffer()
		copy(pktBuffer, buffer[:n])
		pktBuffer = pktBuffer[:n]
		putUDPPacketBuffer(buffer) // Return read buffer to pool

		go func(packet []byte, src *net.UDPAddr, request *clientrequest.Request) {
			defer putUDPPacketBuffer(packet)

			// Create a reply function that sends back through this UDP listener
			replyFunc := func(data []byte) error {
				_, err := udpListener.WriteToUDP(data, src)
				return err
			}

			err := serveUDPConn(packet, replyFunc, request.ProxyIP)
			if err != nil {
				log.Printf("Error handling UDP packet from %s: %v", src.String(), err)
			}
		}(pktBuffer, remoteAddr, rv)
	}
	return nil
}

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

func getUDPPacketBuffer() []byte {
	return udpPacketBufferPool.Get().([]byte)
}

func putUDPPacketBuffer(p []byte) {
	p = p[:cap(p)]
	udpPacketBufferPool.Put(p)
}

/*********************************************************
    UDP PACKAGE to proxy
    +----+------+------+----------+----------+----------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    +----+------+------+----------+----------+----------+
    | 2  |  1   |  1   | Variable |    2     | Variable |
    +----+------+------+----------+----------+----------+
**********************************************************/

// ErrUDPFragmentNoSupported UDP fragments not supported error
var ErrUDPFragmentNoSupported = errors.New("")

func serveUDPConn(udpPacket []byte, reply func([]byte) error, proxyIP net.IP) error {
	// RSV  Reserved X'0000'
	// FRAG Current fragment number, donnot support fragment here
	if len(udpPacket) < 3 {
		err := fmt.Errorf("short UDP package header, %d bytes only", len(udpPacket))
		log.Printf("udp socks: Failed to get UDP package header: %v", err)
		return err
	}
	header := udpPacket[0:3]
	if header[0] != 0x00 || header[1] != 0x00 {
		err := fmt.Errorf("unsupported socks UDP package header, %+v", header[:2])
		log.Printf("udp socks: Failed to parse UDP package header: %v", err)
		return err
	}
	if header[2] != 0x00 {
		log.Printf("udp socks: %+v", ErrUDPFragmentNoSupported)
		return ErrUDPFragmentNoSupported
	}

	// Read in the destination address
	targetAddrRaw := udpPacket[3:]
	targetAddrSpec := &AddrSpec{}
	targetAddrRawSize := 0
	errShortAddrRaw := func() error {
		err := fmt.Errorf("short UDP package Addr. header, %d bytes only", len(targetAddrRaw))
		log.Printf("udp socks: Failed to get UDP package header: %v", err)
		return err
	}
	if len(targetAddrRaw) < 1+4+2 /* ATYP + DST.ADDR.IPV4 + DST.PORT */ {
		return errShortAddrRaw()
	}
	targetAddrRawSize = 1
	switch targetAddrRaw[0] {
	case AddressIPv4:
		targetAddrSpec.IP = net.IP(targetAddrRaw[targetAddrRawSize : targetAddrRawSize+4])
		targetAddrRawSize += 4
	case AddressIPv6:
		if len(targetAddrRaw) < 1+16+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.IP = net.IP(targetAddrRaw[1 : 1+16])
		targetAddrRawSize += 16
	case AddressDomainName:
		addrLen := int(targetAddrRaw[1])
		if len(targetAddrRaw) < 1+1+addrLen+2 {
			return errShortAddrRaw()
		}
		targetAddrSpec.FQDN = string(targetAddrRaw[1+1 : 1+1+addrLen])
		targetAddrRawSize += (1 + addrLen)
	default:
		log.Printf("udp socks: Failed to get UDP package header: %v", errUnrecognizedAddrType)
		return errUnrecognizedAddrType
	}
	targetAddrSpec.Port = (int(targetAddrRaw[targetAddrRawSize]) << 8) | int(targetAddrRaw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	targetAddrRaw = targetAddrRaw[:targetAddrRawSize]

	// resolve addr - prefer IPv6 if proxyIP is IPv6, else IPv4
	if targetAddrSpec.FQDN != "" {
		var addrNetwork string
		if proxyIP.To4() == nil {
			// proxyIP is IPv6, prefer IPv6 resolution
			addrNetwork = "ip6"
		} else {
			// proxyIP is IPv4, prefer IPv4 resolution
			addrNetwork = "ip4"
		}

		addr, err := net.ResolveIPAddr(addrNetwork, targetAddrSpec.FQDN)
		if err != nil {
			// If preferred network fails, try the other
			var fallbackNetwork string
			if addrNetwork == "ip6" {
				fallbackNetwork = "ip4"
			} else {
				fallbackNetwork = "ip6"
			}
			addr, err = net.ResolveIPAddr(fallbackNetwork, targetAddrSpec.FQDN)
			if err != nil {
				err := fmt.Errorf("failed to resolve destination '%v': %v", targetAddrSpec.FQDN, err)
				log.Printf("udp socks: %+v", err)
				return err
			}
		}
		targetAddrSpec.IP = addr.IP
	}

	// make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddrSpec.Address())
	if err != nil {
		err := fmt.Errorf("failed to resolve destination UDP Addr '%v': %v", targetAddrSpec.Address(), err)
		return err
	}

	// Bind to the selected proxy IP for outbound connection
	// Determine network type based on proxy IP (localAddr), not target
	var network string
	if proxyIP.To4() == nil {
		network = "udp6" // proxyIP is IPv6, use udp6
	} else {
		network = "udp4" // proxyIP is IPv4, use udp4
	}

	localAddr := &net.UDPAddr{IP: proxyIP, Port: 0}
	target, err := net.DialUDP(network, localAddr, targetUDPAddr)
	if err != nil {
		err = fmt.Errorf("connect to %v failed: %v", targetUDPAddr, err)
		log.Printf("udp socks: %+v", err)
		return err
	}

	// write data to target
	if _, err := target.Write(udpPacket[len(header)+len(targetAddrRaw):]); err != nil {
		log.Printf("udp socks: fail to write udp data to dest %s: %+v",
			targetUDPAddr.String(), err)
		target.Close()
		return err
	}

	// Start listener goroutine for server responses (bidirectional relay)
	// This keeps the connection open and relays any unsolicited packets from server
	go func() {
		defer target.Close()

		// Gaming keepalive timeout: 60 seconds (typical for game servers)
		keepaliveTimeout := 60 * time.Second
		respBuffer := getUDPPacketBuffer()
		defer putUDPPacketBuffer(respBuffer)

		// Copy header and address to response buffer template
		copy(respBuffer[0:len(header)], header)
		copy(respBuffer[len(header):len(header)+len(targetAddrRaw)], targetAddrRaw)
		headerSize := len(header) + len(targetAddrRaw)

		for {
			// Set read deadline with keepalive timeout
			target.SetReadDeadline(time.Now().Add(keepaliveTimeout))

			n, err := target.Read(respBuffer[headerSize:])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					log.Printf("UDP keepalive timeout for %s (no response in %v), closing", targetUDPAddr.String(), keepaliveTimeout)
				} else {
					log.Printf("UDP read error from %s: %v", targetUDPAddr.String(), err)
				}
				return
			}

			// Relay response back to client
			if err := reply(respBuffer[:headerSize+n]); err != nil {
				log.Printf("udp socks: fail to relay response back: %+v", err)
				return
			}
		}
	}()

	// Return immediately - listener goroutine handles all responses
	return nil
}

// handleUDPStartConnMap uses source IP and port validation with a global UDP listener (legacy mode)
func handleUDPStartConnMap(rv *clientrequest.Request, localIP net.IP) error {
	// Get client address for validation
	// Prefer client-declared address from SOCKS5 ASSOCIATE, fall back to TCP source
	srcIP := rv.UdpClientIP
	srcPort := rv.UdpClientPort
	declaredAddr := true

	// If client didn't declare (0.0.0.0:0), use TCP connection source
	if srcIP == "" || srcIP == "0.0.0.0" || srcIP == "::" || srcPort == 0 {
		declaredAddr = false
		remoteAddrStr := rv.Conn.RemoteAddr().String()
		var err error
		srcIP, srcPortStr, err := net.SplitHostPort(remoteAddrStr)
		if err != nil {
			return fmt.Errorf("failed to parse client address %s: %w", remoteAddrStr, err)
		}
		var portErr error
		srcPort, portErr = strconv.Atoi(srcPortStr)
		if portErr != nil {
			return fmt.Errorf("failed to parse client port %s: %w", srcPortStr, portErr)
		}
		log.Printf("Client didn't declare UDP address, using TCP source %s:%d (IP validation only)", srcIP, srcPort)
	} else {
		log.Printf("Using client-declared UDP address from SOCKS5 ASSOCIATE: %s:%d (strict IP:port validation)", srcIP, srcPort)
	}

	// Create client address for validation
	clientAddr := &ClientAddr{
		IP:       srcIP,
		Port:     srcPort,
		Declared: declaredAddr,
		ProxyIP:  rv.ProxyIP,
	}

	// Create key based on whether address was declared
	// If declared: key is "srcIP:srcPort" (exact match required)
	// If not declared: key is "srcIP:0" (fallback match allowed)
	var keyPort int
	if declaredAddr {
		keyPort = srcPort
	} else {
		keyPort = 0
	}
	key := connMapKey(srcIP, keyPort)

	// Defer cleanup
	defer func() {
		log.Printf("Closing UDP connection for %s (Declared=%v)", key, declaredAddr)
		ConnMap.Delete(key)
	}()

	log.Printf("Adding UDP connection for client %s:%d with key %s (Declared=%v)", srcIP, srcPort, key, declaredAddr)
	ConnMap.Store(key, clientAddr)

	// Send SOCKS5 UDP ASSOCIATE response with the same port as TCP
	tcpAddr := rv.Conn.LocalAddr().(*net.TCPAddr)
	utils.SetIPZone(tcpAddr)

	rep := utils.CreateSocks5Response(tcpAddr)
	if _, err := rv.Conn.Write(rep); err != nil {
		return fmt.Errorf("failed to send UDP ASSOCIATE response: %w", err)
	}

	// Monitor TCP connection for closure
	buf := make([]byte, 1)
	for {
		rv.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := rv.Conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("TCP connection closed for %s: %v", srcIP, err)
			} else {
				log.Printf("TCP connection closed gracefully for %s", srcIP)
			}
			return nil
		}
	}
}

// HandleUDP starts a global UDP listener for the ConnMap mode (source IP validation)
// This is called from main.go when UDPEphemeralPort is disabled
func HandleUDP(port uint16) error {
	listenAddr := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
	udpConn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP port %d: %w", port, err)
	}

	log.Printf("UDP listener started on port %d (ConnMap mode)", port)

	// Run the listener in this goroutine - HandleUDPGlobalListener blocks
	HandleUDPGlobalListener(udpConn)
	return nil
}

// HandleUDPGlobalListener handles UDP packets from a global listener (used with ConnMap mode)
func HandleUDPGlobalListener(udpConn *net.UDPConn) {
	for {
		buffer := getUDPPacketBuffer() // Get from pool
		n, src, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("UDP listener error: %v", err)
			putUDPPacketBuffer(buffer)
			continue
		}

		// Get source IP and port from the remote address
		srcIP := src.IP.String()
		srcPort := src.Port

		// Try to find exact match first: srcIP:srcPort
		exactKey := connMapKey(srcIP, srcPort)
		clientAddrInterface, loaded := ConnMap.Load(exactKey)

		// If exact match not found and srcPort != 0, try fallback: srcIP:0 (undeclared session)
		if !loaded && srcPort != 0 {
			fallbackKey := connMapKey(srcIP, 0)
			clientAddrInterface, loaded = ConnMap.Load(fallbackKey)
			if loaded {
				log.Printf("Found session via fallback key %s for packet from %s", fallbackKey, exactKey)
			}
		}

		if !loaded {
			log.Printf("No matching session found for %s (tried exact match and fallback)", exactKey)
			putUDPPacketBuffer(buffer)
			continue
		}

		clientAddr, ok := clientAddrInterface.(*ClientAddr)
		if !ok {
			log.Printf("Invalid ClientAddr type in ConnMap for key %s, dropping packet", exactKey)
			putUDPPacketBuffer(buffer)
			continue
		}

		// Validate based on whether address was declared
		if clientAddr.Declared {
			// Strict: client declared exact IP:port, must match
			if srcPort != clientAddr.Port {
				log.Printf("UDP packet from %s:%d but session declared port %d (strict validation), dropping", srcIP, srcPort, clientAddr.Port)
				putUDPPacketBuffer(buffer)
				continue
			}
		} else {
			// Loose: client didn't declare (used 0.0.0.0:0), only IP must match
			// Log if port differs from stored port
			if srcPort != clientAddr.Port {
				log.Printf("UDP packet from %s:%d for undeclared session (expected IP %s, port varies from stored %d)", srcIP, srcPort, clientAddr.IP, clientAddr.Port)
			}
		}

		// Process the UDP packet - copy from buffer to another pool buffer
		pktBuffer := getUDPPacketBuffer()
		copy(pktBuffer, buffer[:n])
		pktBuffer = pktBuffer[:n]
		putUDPPacketBuffer(buffer) // Return read buffer to pool

		go func(packet []byte, src *net.UDPAddr) {
			defer putUDPPacketBuffer(packet)

			// Create a reply function that sends back through the global UDP listener
			replyFunc := func(data []byte) error {
				_, err := udpConn.WriteToUDP(data, src)
				return err
			}

			err := serveUDPConn(packet, replyFunc, clientAddr.ProxyIP)
			if err != nil {
				log.Printf("Error handling UDP packet from %s: %v", src.String(), err)
			}
		}(pktBuffer, src)
	}
}
