package directproxy

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"slickproxy/internal/config"
	"slickproxy/internal/userdb"
	"strings"
	"sync"
	"time"
)

type sessionIPInfo struct {
	ip        net.IP
	timestamp time.Time
	ttl       int
}

var (
	sessionIPMap sync.Map
)

const cleanupInterval = 1 * time.Minute

func init() {
	go startSessionIPCleanupLoop()
}

func generateRandomIPv6InSubnet(subnet string, prefixLength int) (net.IP, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR subnet: %v", err)
	}

	if ipNet.IP.To16() == nil {
		return nil, fmt.Errorf("provided IP is not a valid IPv6 address: %v", subnet)
	}

	generatedIP := make(net.IP, len(ipNet.IP))
	copy(generatedIP, ipNet.IP)

	randomBits := 128 - prefixLength

	rand.Seed(time.Now().UnixNano())

	for i := len(generatedIP) - 1; i >= 0; i-- {
		if randomBits > 0 {
			if randomBits >= 8 {
				generatedIP[i] = byte(rand.Intn(256))
				randomBits -= 8
			} else {
				generatedIP[i] = byte(rand.Intn(1 << randomBits))
				randomBits = 0
			}
		} else {
			break
		}
	}

	return generatedIP, nil
}

func RetrieveRandomIPv6Address(proxyIPv6List []string) (net.IP, error) {
	subnets, weights, err := retrieveSubnetsAndWeights(proxyIPv6List)
	if err != nil {
		return nil, err
	}

	randomBytes := make([]byte, 32)
	rand.Seed(time.Now().UnixNano())
	for i := range randomBytes {
		randomBytes[i] = byte(rand.Intn(256))
	}
	var hash [32]byte
	copy(hash[:], randomBytes)

	selectedIndex := selectWeightedSubnetIndex(hash, weights)
	if selectedIndex < 0 || selectedIndex >= len(subnets) {
		return nil, fmt.Errorf("selected subnet index out of range: %d", selectedIndex)
	}
	selectedSubnet := subnets[selectedIndex]

	generatedIP := make(net.IP, 16)
	copy(generatedIP, selectedSubnet.IP)

	hostBits := 128 - selectedSubnet.PrefixLen
	if hostBits > 0 {
		byteOffset := selectedSubnet.PrefixLen / 8
		bitOffset := selectedSubnet.PrefixLen % 8

		for i := byteOffset; i < 16; i++ {
			generatedIP[i] = byte(rand.Intn(256))
		}

		if bitOffset != 0 && byteOffset < 16 {
			mask := byte(0xff >> bitOffset)
			generatedIP[byteOffset] = (generatedIP[byteOffset] & mask) | (selectedSubnet.IP[byteOffset] & ^mask)
		}
	}

	return generatedIP, nil
}

type Subnet struct {
	IP        net.IP
	PrefixLen int
}

func parseSubnetCIDRs(cidrs []string) ([]Subnet, error) {
	subnets := make([]Subnet, 0, len(cidrs))
	for _, cidr := range cidrs {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		prefixLength, _ := network.Mask.Size()
		subnets = append(subnets, Subnet{
			IP:        ip.To16(),
			PrefixLen: prefixLength,
		})
	}
	return subnets, nil
}

type parsedCacheEntry struct {
	subnets []Subnet
	weights []float64
}

var parsedCache sync.Map

func retrieveSubnetsAndWeights(cidrs []string) ([]Subnet, []float64, error) {
	if len(cidrs) == 0 {
		return nil, nil, fmt.Errorf("no cidrs provided")
	}

	cacheKey := strings.Join(cidrs, "|")
	if cachedEntry, exists := parsedCache.Load(cacheKey); exists {
		parsedEntry := cachedEntry.(parsedCacheEntry)
		return parsedEntry.subnets, parsedEntry.weights, nil
	}

	subnets, err := parseSubnetCIDRs(cidrs)
	if err != nil {
		return nil, nil, err
	}
	weights := calculateSubnetWeights(subnets)

	parsedCache.Store(cacheKey, parsedCacheEntry{subnets: subnets, weights: weights})
	return subnets, weights, nil
}

func calculateSubnetWeights(subnets []Subnet) []float64 {
	logWeights := make([]float64, len(subnets))
	var totalWeight float64
	for i, subnet := range subnets {
		logWeights[i] = float64(128 - subnet.PrefixLen)
		totalWeight += logWeights[i]
	}
	weights := make([]float64, len(subnets))
	for i := range subnets {
		weights[i] = logWeights[i] / totalWeight
	}
	return weights
}

func selectWeightedSubnetIndex(hash [32]byte, weights []float64) int {
	hashValue := binary.BigEndian.Uint64(hash[0:8])
	normalizedValue := float64(hashValue) / float64(math.MaxUint64)
	cumulativeWeight := 0.0
	for i, weight := range weights {
		cumulativeWeight += weight
		if normalizedValue < cumulativeWeight {
			return i
		}
	}
	return len(weights) - 1
}

func GenerateWeightedIPv6Address(input string, cidrs []string) (net.IP, error) {
	if input == "" {
		return RetrieveRandomIPv6Address(cidrs)
	}

	subnets, weights, err := retrieveSubnetsAndWeights(cidrs)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(input))
	selectedIndex := selectWeightedSubnetIndex(hash, weights)
	if selectedIndex < 0 || selectedIndex >= len(subnets) {
		return nil, fmt.Errorf("selected subnet index out of range: %d", selectedIndex)
	}
	selectedSubnet := subnets[selectedIndex]

	generatedIP := make(net.IP, 16)
	copy(generatedIP, selectedSubnet.IP)

	hostBits := 128 - selectedSubnet.PrefixLen
	if hostBits <= 0 {
		return generatedIP, nil
	}

	byteOffset := selectedSubnet.PrefixLen / 8
	bitOffset := selectedSubnet.PrefixLen % 8

	hashPos := 8

	for i := 0; i < (hostBits+7)/8; i++ {
		if byteOffset+i >= 16 || hashPos+i >= len(hash) {
			break
		}
		generatedIP[byteOffset+i] = hash[hashPos+i]
	}

	if bitOffset != 0 && byteOffset < 16 {
		mask := byte(0xff >> bitOffset)
		generatedIP[byteOffset] = (generatedIP[byteOffset] & mask) | (selectedSubnet.IP[byteOffset] & ^mask)
	}

	return generatedIP, nil
}

func RetrieveIPv6ForSessionKey(sessionKey string, ttl int, userRecord *userdb.User) (net.IP, error) {
	if config.Cfg.Server.StatelessSession {
		return GenerateWeightedIPv6Address(sessionKey, userRecord.ProxyIPListv6)
	}

	now := time.Now()

	if cachedValue, exists := sessionIPMap.Load(sessionKey); exists {
		ipInfo := cachedValue.(sessionIPInfo)
		if now.Sub(ipInfo.timestamp) < time.Duration(ipInfo.ttl)*time.Second {
			return ipInfo.ip, nil
		}
	}

	generatedIP, _ := RetrieveRandomIPv6Address(userRecord.ProxyIPListv6)
	if generatedIP == nil {
		return nil, fmt.Errorf("failed to generate IPv6 address")
	}

	sessionIPMap.Store(sessionKey, sessionIPInfo{
		ip:        generatedIP,
		timestamp: now,
		ttl:       ttl,
	})

	return generatedIP, nil
}

func startSessionIPCleanupLoop() {
	for {
		time.Sleep(cleanupInterval)
		currentTime := time.Now()

		sessionIPMap.Range(func(key, value interface{}) bool {
			ipInfo := value.(sessionIPInfo)
			if currentTime.Sub(ipInfo.timestamp) >= time.Duration(ipInfo.ttl)*time.Second {
				sessionIPMap.Delete(key)
			}
			return true
		})
	}
}

func generateRandomIPv4InSubnet(subnet string) (net.IP, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return net.ParseIP(subnet), nil
	}

	generatedIP := make(net.IP, len(ipNet.IP))
	copy(generatedIP, ipNet.IP)

	prefixLength, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("not an IPv4 subnet")
	}

	hostBits := 32 - prefixLength
	if hostBits == 0 {
		return generatedIP, nil
	}

	rand.Seed(time.Now().UnixNano())
	maxHost := 1 << hostBits
	hostValue := rand.Intn(maxHost)

	for i := 0; i < 4; i++ {
		maskBits := 8
		if prefixLength >= 8 {
			prefixLength -= 8
			continue
		}
		if prefixLength > 0 {
			maskBits -= prefixLength
			prefixLength = 0
		}
		if maskBits > 0 {
			generatedIP[i] &= 0xFF << maskBits
			generatedIP[i] |= byte((hostValue >> ((3 - i) * 8)) & (0xFF >> (8 - maskBits)))
		}
	}
	return generatedIP, nil
}

func RetrieveRandomIPv4Address(proxyIPv4List []string) (net.IP, error) {
	rand.Seed(time.Now().UnixNano())
	index := rand.Intn(len(proxyIPv4List))
	selectedIP := proxyIPv4List[index]

	if strings.Contains(selectedIP, "/") {
		subnetParts := strings.Split(selectedIP, "/")
		if len(subnetParts) != 2 {
			return nil, fmt.Errorf("invalid IP format")
		}
		randomIP, err := generateRandomIPv4InSubnet(selectedIP)
		if err != nil {
			return nil, err
		}
		return randomIP, nil
	}

	parsedIP := net.ParseIP(selectedIP)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IPv4 address: %s", selectedIP)
	}
	return parsedIP, nil
}

func RetrieveIPv4ForSessionKey(sessionKey string, ttl int, userRecord *userdb.User) (net.IP, error) {
	currentTime := time.Now()
	if cachedValue, exists := sessionIPMap.Load(sessionKey); exists {
		ipInfo := cachedValue.(sessionIPInfo)
		if currentTime.Sub(ipInfo.timestamp) < time.Duration(ipInfo.ttl)*time.Second {
			return ipInfo.ip, nil
		}
	}
	generatedIP, _ := RetrieveRandomIPv4Address(userRecord.ProxyIPListv4)
	if generatedIP == nil {
		return nil, fmt.Errorf("failed to retrieve or generate IP address")
	}

	sessionIPMap.Store(sessionKey, sessionIPInfo{
		ip:        generatedIP,
		timestamp: currentTime,
		ttl:       ttl,
	})

	return generatedIP, nil
}
