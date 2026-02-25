package http

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"slickproxy/internal/clientrequest"
	"slickproxy/internal/config"
	"slickproxy/internal/directproxy"
	"slickproxy/internal/upstream"
	"slickproxy/internal/userdb"

	"encoding/base64"
	"errors"

	"log"
	"slickproxy/internal/viprox"
	"strings"
	"sync/atomic"
)

var proxyAuthenticationRequiredResponse = []byte(
	"HTTP/1.1 407 Proxy Authentication Required\r\n" +
		"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 66\r\n" +
		"\r\n" +
		"Proxy Authentication Required: Please provide authentication details.\r\n",
)
var rateLimitExceededResponse = []byte(
	"HTTP/1.1 429 Too Many Requests\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 58\r\n" +
		"\r\n" +
		"Rate limit exceeded: you have reached your maximum allowed speed.\r\n",
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

func decodeBase64Auth(authHeader string, isBase64Encoded bool) string {
	if len(authHeader) > 6 && strings.HasPrefix(authHeader, "Basic ") {
		authHeader = authHeader[6:]
	}

	var decodedAuthString string
	if isBase64Encoded {
		decodedBytes, err := base64.StdEncoding.DecodeString(authHeader)
		if err != nil {
			return ""
		}
		decodedAuthString = string(decodedBytes)
	} else {
		decodedAuthString = authHeader
	}

	return decodedAuthString
}
func readProxyAuthHeader(requestObj *clientrequest.Request, parsedRequest *http.Request) (string, error) {
	authHeader := parsedRequest.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		// Try to lookup by client IP in whitelist map (no lock needed - pointer read is atomic)
		clientIP := requestObj.ClientIp.String()
		if userdb.WhitelistIPMap != nil {
			ipCreds, found := (*userdb.WhitelistIPMap)[clientIP]
			if found {
				// Found credentials for this IP, combine username:password
				decodedCredentials := ipCreds.User + ":" + ipCreds.Password
				log.Printf("Found whitelist IP credentials for %s: %s", clientIP, ipCreds.User)
				return decodedCredentials, nil
			}
		}

		requestObj.Conn.Write(proxyAuthenticationRequiredResponse)
		return "", fmt.Errorf("no auth header and no whitelist IP match for %s", clientIP)
	}
	decodedCredentials := decodeBase64Auth(authHeader, true)
	if decodedCredentials == "" {
		return "", fmt.Errorf("failed to decode auth header")
	}
	return decodedCredentials, nil
}

func validateProxyAuthorization(requestObj *clientrequest.Request, parsedRequest *http.Request, dataStore userdb.DataStore) error {
	decodedCredentials, err := readProxyAuthHeader(requestObj, parsedRequest)
	if err != nil {
		return err
	}
	return PerformProxyAuthenticationValidation(requestObj, decodedCredentials, dataStore)
}
func waitForRateLimitRecovery(user *userdb.User) error {
	const maxRetries = 10
	for i := 0; i < maxRetries; i++ {
		if atomic.LoadInt64(&user.RateLimiter.Blocked) != 1 {
			return nil
		}
		log.Println("sleeping cause of ratelimiting")
		user.RateLimiter.Write(0, true)
	}
	return errors.New("user still blocked after 10 retries")
}

func checkIPInProxyList(localIP net.IP, proxyIPList []string) bool {
	for _, entry := range proxyIPList {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			_, ipNetwork, err := net.ParseCIDR(entry)
			if err != nil {
				continue
			}
			if ipNetwork.Contains(localIP) {
				return true
			}
		} else {
			parsedIP := net.ParseIP(entry)
			if parsedIP == nil {
				continue
			}
			if parsedIP.Equal(localIP) {
				return true
			}
		}
	}

	return false
}

func isUserIPPortAuthorized(user *userdb.User, localIP net.IP, localPort uint16) bool {
	if user.ProxyIP != "" {
		return user.ProxyIP == localIP.String()
	}

	if len(user.ProxyIPListv4) > 0 {
		return checkIPInProxyList(localIP, user.ProxyIPListv4)
	}

	if len(user.PortToIP) > 0 {
		if mappedIP, portExists := user.PortToIP[localPort]; portExists {
			return mappedIP == localIP.String()
		}
		return false
	}

	return true
}

func PerformProxyAuthenticationValidation(requestObj *clientrequest.Request, decodedCredentials string, dataStore userdb.DataStore) error {
	requestObj.Credentials.ParseAuthentication(decodedCredentials)

	credentialsKey := fmt.Sprintf("%s:%s", requestObj.Credentials.User, requestObj.Credentials.Password)
	userRecord, authErr := userdb.UserExists(credentialsKey, dataStore.Users)
	if authErr != nil {
		requestObj.Conn.Write(proxyAuthenticationRequiredResponse)
		fmt.Println("AUTH: invalid user", credentialsKey, requestObj.Host, requestObj.Conn.RemoteAddr().String())
		return fmt.Errorf("not authrorized user")
	}

	if config.Cfg.General.Viprox {
		_, err := viprox.Adapter.FindEndpoint(requestObj.Credentials.Code)
		if err != nil {
			return err
		}
	}

	isIPWhitelisted := isIPInUserWhitelist(requestObj.ClientIp, userRecord)
	activeConnections := atomic.LoadInt64(userRecord.CurrentActiveConnections)
	requestObj.Credentials.UserDetail = userRecord

	if !config.Cfg.General.Cluster {
		if (userRecord.ProxyPort != 0 && userRecord.ProxyPort != requestObj.Port) ||
			(userRecord.ProxyPortRange[0] != 0 && userRecord.ProxyPortRange[0] > requestObj.Port) || (userRecord.ProxyPortRange[0] != 0 && userRecord.ProxyPortRange[1] < requestObj.Port) ||
			!isIPWhitelisted || !isUserIPPortAuthorized(userRecord, requestObj.LocalIP, requestObj.Port) {
			fmt.Println("AUTH: not authrorized port or ip", userRecord.ProxyIP, requestObj.LocalIP.String(), requestObj.Port, userRecord.ProxyPort, userRecord.ProxyPortRange, isIPWhitelisted, credentialsKey, requestObj.Host, requestObj.Conn.RemoteAddr().String())
			requestObj.Conn.Write(proxyAuthenticationRequiredResponse)
			return fmt.Errorf("rate limit reached %v %v", !isIPWhitelisted, (int64(userRecord.ActiveConnections) != 0 && activeConnections+1 > int64(userRecord.ActiveConnections)))
		}
	}

	if config.Cfg.General.TrackUsage && ((int64(userRecord.ActiveConnections) != 0 && activeConnections+1 > int64(userRecord.ActiveConnections)) ||
		userRecord.TimeQuota != 0 && userRecord.TimeQuota < config.Ct.CurrentTime().Unix()) {
		requestObj.Conn.Write(proxyAuthenticationRequiredResponse)
		fmt.Println("AUTH: active connection or time quota exceeded for user", credentialsKey, requestObj.Host, requestObj.Conn.RemoteAddr().String())
		return fmt.Errorf("not authrorized port %v %v", !isIPWhitelisted, (int64(userRecord.ActiveConnections) != 0 && activeConnections+1 > int64(userRecord.ActiveConnections)))
	}

	requestObj.Credentials.IpMode = userRecord.IpMode

	return validateDomainBlacklist(requestObj, dataStore)
}

var badRequestErrorResponse = []byte("HTTP/1.1 400 Bad Request\r\n" +
	"Content-Type: text/plain\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"Bad Request: The request is malformed or missing required parameters.")

var forbiddenAccessResponse = []byte(
	"HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 58\r\n" +
		"\r\n" +
		"Forbidden: You do not have permission to access this resource.\r\n",
)

func HandleHTTPRequest(reader *bufio.Reader, conn net.Conn, dataStore userdb.DataStore) (clientrequest.Request, error) {
	requestObj := clientrequest.NewRequest(conn, "http")

	defer func(requestObj *clientrequest.Request) {
		requestObj.Close()

	}(&requestObj)

	parsedRequest, err := http.ReadRequest(reader)
	if err != nil {
		if config.Cfg.General.Log == "debug" {
			fmt.Println("Failed to read HTTP request:", err)
		}
		requestObj.Conn.Write(badRequestErrorResponse)
		return requestObj, fmt.Errorf("Bad Request")
	}
	requestObj.RawRequest = parsedRequest
	requestObj.Host = requestObj.RawRequest.Host

	if err = validateProxyAuthorization(&requestObj, parsedRequest, dataStore); err != nil {
		return requestObj, err
	}

	requestObj.RawRequest.Header.Set("Connection", "close")

	requestObj.Domain, requestObj.EndPort, err = net.SplitHostPort(requestObj.Host)
	if err != nil {
		requestObj.Domain = requestObj.Host
		requestObj.Host = requestObj.Host + ":80"
		requestObj.EndPort = "80"
	}

	portIsBlacklisted := userdb.IsPortBlacklisted(requestObj.EndPort, dataStore.GlobalBlacklistPorts)
	if portIsBlacklisted != nil {
		requestObj.Conn.Write(forbiddenAccessResponse)
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

func validateDomainBlacklist(requestObj *clientrequest.Request, dataStore userdb.DataStore) error {
	if requestObj.RawRequest != nil {
		if err := userdb.IsDomainBlacklisted(requestObj.RawRequest.Host, dataStore.GlobalBlacklistDomains); err != nil {
			return err
		}
	}
	return nil
}
