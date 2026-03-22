package udp

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slickproxy/internal/clientrequest"
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

const maxUDPPacketSize = 2 * 1024

var ConnMap sync.Map // Global sync.Map to hold source IPs of active connections

var errUnrecognizedAddrType = fmt.Errorf("unrecognized address type")

var udpClientSrcAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 0}

var udpPacketBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxUDPPacketSize, maxUDPPacketSize)
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
	// Defer the connection close and clean up the map entry based on the source IP
	defer func() {
		// Extract the source IP from the connection's remote address
		remoteAddr := rv.Conn.RemoteAddr().(*net.TCPAddr)
		srcIP := remoteAddr.IP.String()

		// Log the closing of the connection
		log.Printf("Closing connection from %s", srcIP)

		// Erase the entry for this source IP from the sync.Map
		ConnMap.Delete(srcIP)

		// Close the connection
		if err := rv.Conn.Close(); err != nil {
			log.Printf("Error closing connection: %v", err)
		}
	}()
	// Extract source IP and store it in the map (before reading)
	remoteAddr := rv.Conn.RemoteAddr().(*net.TCPAddr)
	srcIP := remoteAddr.IP.String()
	log.Printf("Adding connection from %s", srcIP)
	ConnMap.Store(srcIP, rv.Conn)

	tcpAddr := rv.Conn.LocalAddr().(*net.TCPAddr)
	utils.SetIPZone(tcpAddr)

	rep := utils.CreateSocks5Response(tcpAddr)
	if _, err := rv.Conn.Write(rep); err != nil {
		return err
	}

	// wait here till the client close the connection
	// check every 10 secs
	tmp := make([]byte, 1024) // Buffer to hold incoming data
	var neverTimeout time.Time
	for {
		rv.Conn.SetReadDeadline(neverTimeout)
		log.Println("wait")
		if _, err := rv.Conn.Read(tmp); err == io.EOF {
			log.Println("wait over")
			break
		} else if err != nil {
			// If the error is a timeout, simply ignore it
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				rv.Conn.SetReadDeadline(neverTimeout)
				// Ignore timeout errors, just continue to the next read attempt
				time.Sleep(10 * time.Second)
				continue
			}
			log.Printf("Error while reading data: %v", err)
			break // Break the loop on any other error
		} else {
			log.Println("wait oho")
			rv.Conn.SetReadDeadline(neverTimeout)
		}
		time.Sleep(10 * time.Second)
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

//FIXME: insecure implementation of UDP server, anyone could send package here without authentication

func HandleUDP(udpConn *net.UDPConn, connMap *sync.Map) {
	for {
		buffer := make([]byte, 1024) // buffer to hold incoming UDP packet
		n, src, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("udp socks: Failed to accept udp traffic: %v", err)
			continue
		}

		// Get source IP from the remote address
		srcIP := src.IP.String()

		// Check if the source IP is in the sync.Map
		_, loaded := connMap.Load(srcIP)
		if !loaded {
			log.Printf("Source IP %s not found in connMap. Exiting...", srcIP)
			continue // Skip the packet if source IP is not in the map
		}

		buffer = buffer[:n]
		go func() {
			// Handle the UDP connection (e.g., serve the data)
			// Just echo back the data for this example
			err := serveUDPConn(buffer, func(data []byte) error {
				_, err := udpConn.WriteToUDP(data, src)
				return err
			})

			if err != nil {
				log.Printf("Error handling UDP connection: %v", err)
			}
		}()
	}
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

func serveUDPConn(udpPacket []byte, reply func([]byte) error) error {
	// RSV  Reserved X'0000'
	// FRAG Current fragment number, donnot support fragment here
	header := []byte{0, 0, 0}
	if len(udpPacket) <= 3 {
		err := fmt.Errorf("short UDP package header, %d bytes only", len(udpPacket))
		log.Printf("udp socks: Failed to get UDP package header: %v", err)
		return err
	}
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

	// resolve addr.
	if targetAddrSpec.FQDN != "" {
		addr, err := net.ResolveIPAddr("ip", targetAddrSpec.FQDN)
		if err != nil {
			err := fmt.Errorf("failed to resolve destination '%v': %v", targetAddrSpec.FQDN, err)
			log.Printf("udp socks: %+v", err)
			return err
		}
		targetAddrSpec.IP = addr.IP
	}

	// make a writer and write to dst
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddrSpec.Address())
	if err != nil {
		err := fmt.Errorf("failed to resolve destination UDP Addr '%v': %v", targetAddrSpec.Address(), err)
		return err
	}
	target, err := net.DialUDP("udp", udpClientSrcAddr, targetUDPAddr)
	if err != nil {
		err = fmt.Errorf("connect to %v failed: %v", targetUDPAddr, err)
		log.Printf("udp socks: %+v", err)
		return err
	}
	defer target.Close()

	// write data to target and read the response back
	if _, err := target.Write(udpPacket[len(header)+len(targetAddrRaw):]); err != nil {
		log.Printf("udp socks: fail to write udp data to dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	respBuffer := getUDPPacketBuffer()
	defer putUDPPacketBuffer(respBuffer)
	copy(respBuffer[0:len(header)], header)
	copy(respBuffer[len(header):len(header)+len(targetAddrRaw)], targetAddrRaw)
	n, err := target.Read(respBuffer[len(header)+len(targetAddrRaw):])
	if err != nil {
		log.Printf("udp socks: fail to read udp resp from dest %s: %+v",
			targetUDPAddr.String(), err)
		return err
	}
	respBuffer = respBuffer[:len(header)+len(targetAddrRaw)+n]

	if reply(respBuffer); err != nil {
		log.Printf("udp socks: fail to send udp resp back: %+v", err)
		return err
	}
	return nil
}
