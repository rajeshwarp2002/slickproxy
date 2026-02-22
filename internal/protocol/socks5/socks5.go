package socks5

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slickproxy/internal/config"

	"slickproxy/internal/directproxy"
	"slickproxy/internal/request"
	"slickproxy/internal/upstream"
	"slickproxy/internal/userdb"

	"encoding/binary"
	"strconv"

	"slickproxy/internal/protocol/http"
)

func isIPInUserWhitelist(ipAddress net.IP, user *userdb.User) bool {
	ipAddressStr := ipAddress.String()
	if len(user.WhiteListIP) == 0 {
		return true
	}

	for _, whitelistedIP := range user.WhiteListIP {
		if ipAddressStr == whitelistedIP {
			return true
		}
	}
	return false
}

func validateUserCredentials(requestObj *request.Request, dataStore userdb.DataStore) error {
	buf := make([]byte, 513)
	n, err := io.ReadFull(requestObj.Conn, buf[:2])
	if err != nil {
		return err
	}
	if buf[0] != 0x01 {
		response := []byte{0x01, 0x01}
		requestObj.Conn.Write(response)
		return fmt.Errorf("socks version not supported")
	}
	usernameLen := int(buf[1])
	bytesRead := 2

	n, err = io.ReadFull(requestObj.Conn, buf[bytesRead:bytesRead+usernameLen])
	if err != nil {
		return err
	}
	bytesRead += n
	username := string(buf[2 : 2+usernameLen])

	n, err = io.ReadFull(requestObj.Conn, buf[bytesRead:bytesRead+1])
	if err != nil {
		return err
	}
	bytesRead += n
	passwordLen := int(buf[bytesRead-1])

	_, err = io.ReadFull(requestObj.Conn, buf[bytesRead:bytesRead+passwordLen])
	if err != nil {
		return err
	}
	password := string(buf[bytesRead : bytesRead+passwordLen])

	requestObj.Credentials.User = username
	requestObj.Credentials.Password = password
	credentialsKey := fmt.Sprintf("%s:%s", requestObj.Credentials.User, requestObj.Credentials.Password)
	err1 := http.PerformProxyAuthenticationValidation(requestObj, credentialsKey, dataStore)
	if err1 != nil {
		response := []byte{0x01, 0x01}
		requestObj.Conn.Write(response)
		return fmt.Errorf("user not found: %w", err1)
	}
	user := requestObj.Credentials.UserDetail

	requestObj.Credentials.IpMode = user.IpMode
	requestObj.Credentials.UserDetail = user

	response := []byte{0x01, 0x00}
	requestObj.Conn.Write(response)
	return nil
}

var (
	errAddressTypeNotSupported = errors.New("SOCKS address type not supported")
	errCommandNotSupported     = errors.New("SOCKS only supports CONNECT command")
	errExtraDataInRequest      = errors.New("SOCKS request has extra data")
)

const socksCommandConnect = 0x01

func extractTargetAddress(reader *bufio.Reader, conn net.Conn) (string, error) {
	const (
		versionIdx     = 0
		commandIdx     = 1
		addressTypeIdx = 3
		ipv4AddressIdx = 4
		domainLenIdx   = 4
		domainStartIdx = 5

		addressTypeIPv4   = 1
		addressTypeDomain = 3
		addressTypeIPv6   = 4

		ipv4RequiredLen = 10
		ipv6RequiredLen = 22
		domainBaseLen   = 7
	)

	buf := make([]byte, 263)
	n, err := io.ReadAtLeast(reader, buf, domainLenIdx+1)
	if err != nil {
		return "", err
	}

	if buf[versionIdx] != socksProtocolVersion {
		return "", errInvalidSOCKSVersion
	}
	if buf[commandIdx] != socksCommandConnect {
		return "", errCommandNotSupported
	}

	var requiredLength int
	switch buf[addressTypeIdx] {
	case addressTypeIPv4:
		requiredLength = ipv4RequiredLen
	case addressTypeIPv6:
		requiredLength = ipv6RequiredLen
	case addressTypeDomain:
		requiredLength = int(buf[domainLenIdx]) + domainBaseLen
	default:
		return "", errAddressTypeNotSupported
	}

	if n < requiredLength {
		if _, err := io.ReadFull(reader, buf[n:requiredLength]); err != nil {
			return "", err
		}
	} else if n > requiredLength {
		return "", errExtraDataInRequest
	}

	var targetHost string
	switch buf[addressTypeIdx] {
	case addressTypeIPv4:
		targetHost = net.IP(buf[ipv4AddressIdx : ipv4AddressIdx+net.IPv4len]).String()
	case addressTypeIPv6:
		targetHost = net.IP(buf[ipv4AddressIdx : ipv4AddressIdx+net.IPv6len]).String()
	case addressTypeDomain:
		targetHost = string(buf[domainStartIdx : domainStartIdx+buf[domainLenIdx]])
	}

	port := binary.BigEndian.Uint16(buf[requiredLength-2:])
	return net.JoinHostPort(targetHost, strconv.Itoa(int(port))), nil
}

var (
	statusRequestApproved              = []byte{socksProtocolVersion, 0x00}
	statusGeneralServerFailure         = []byte{socksProtocolVersion, 0x01}
	statusConnectionNotAllowedByRules  = []byte{socksProtocolVersion, 0x02}
	statusNetworkUnreachableError      = []byte{socksProtocolVersion, 0x03}
	statusHostUnreachableError         = []byte{socksProtocolVersion, 0x04}
	statusConnectionRefusedByDestHost  = []byte{socksProtocolVersion, 0x05}
	statusTTLExpiredInTransit          = []byte{socksProtocolVersion, 0x06}
	statusCommandNotImplemented        = []byte{socksProtocolVersion, 0x07}
	statusAddressTypeNotSupportedError = []byte{socksProtocolVersion, 0x08}
	statusNoAcceptableMethods          = []byte{socksProtocolVersion, 0xff}
)

const socksProtocolVersion = 0x05

var (
	errInvalidSOCKSVersion          = errors.New("SOCKS version not supported")
	errExtraDataInAuthentication    = errors.New("SOCKS authentication received extra data")
	errNoValidAuthenticationMethods = errors.New("no acceptable authentication methods")
)

func initiateSOCKS5Protocol(requestObj request.Request, reader *bufio.Reader) error {
	buf := make([]byte, 258)

	n, err := io.ReadFull(reader, buf[:2])
	if err != nil {
		return err
	}

	if buf[0] != socksProtocolVersion {
		return errInvalidSOCKSVersion
	}

	methodCount := int(buf[1])
	totalMessageLen := methodCount + 2

	if methodCount > 0 && n < totalMessageLen {
		if _, err := io.ReadFull(reader, buf[2:totalMessageLen]); err != nil {
			return err
		}
	}
	if n > totalMessageLen {
		return errExtraDataInAuthentication
	}

	response := chooseAuthenticationMethod(buf[2:totalMessageLen])
	requestObj.Conn.Write(response)
	return nil
}

func chooseAuthenticationMethod(methods []byte) []byte {
	needsAuthentication := requiresAuthentication(methods)
	switch {
	case needsAuthentication:
		return statusConnectionNotAllowedByRules
	default:
		return statusNoAcceptableMethods
	}
}

func requiresAuthentication(methods []byte) bool {
	for _, method := range methods {
		if method == 0x02 {
			return true
		}
	}
	return false
}

func HandleSOCKS5Connection(reader *bufio.Reader, conn net.Conn, dataStore userdb.DataStore) (request.Request, error) {
	requestObj := request.NewRequest(conn, "socks5")
	defer func(requestObj *request.Request) {
		requestObj.Close()
	}(&requestObj)

	if err := initiateSOCKS5Protocol(requestObj, reader); err != nil {
		return requestObj, fmt.Errorf("socks5 handshake error")
	}

	if err := validateUserCredentials(&requestObj, dataStore); err != nil {
		return requestObj, fmt.Errorf("socks5 handshake failed")
	}

	destinationAddr, err := extractTargetAddress(reader, requestObj.Conn)
	if err != nil {
		return requestObj, fmt.Errorf("socks5 destination parse error")
	}
	requestObj.Host = destinationAddr

	if err = userdb.IsDomainBlacklisted(destinationAddr, dataStore.GlobalBlacklistDomains); err != nil {
		log.Println("Domain is blacklisted:", err)
		return requestObj, err
	}

	requestObj.Domain, requestObj.EndPort, err = net.SplitHostPort(requestObj.Host)
	if err != nil {
		requestObj.Domain = requestObj.Host
		requestObj.EndPort = "80"
		log.Println("Failed to split host and port, defaulting to port 80:", err)
	}
	portIsBlacklisted := userdb.IsPortBlacklisted(requestObj.EndPort, dataStore.GlobalBlacklistPorts)
	if portIsBlacklisted != nil {
		log.Println("Port is blacklisted:", requestObj.EndPort)
		requestObj.Conn.Write(statusConnectionNotAllowedByRules)
		return requestObj, fmt.Errorf("port %s is blacklisted", requestObj.EndPort)
	}

	if config.Cfg.General.LB {
		err = upstream.HandleRequestUpstream(&requestObj)
	} else {
		err = directproxy.HandleRequestLocal(requestObj)
	}
	if err != nil {
		return requestObj, err
	}

	return requestObj, nil
}
