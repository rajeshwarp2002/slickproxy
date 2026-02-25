package viprox

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var refreshNeededCount int64
var globalSIDCounter int64

type IPMapEntry struct {
	PeerIP  string
	ProxyIP string
	Port    int
}

type PortIPMapper struct {
	SIDToIPMap map[string]*IPMapEntry

	IPToSIDMap map[string]string

	EndpointToSIDArray map[string][]int

	NextSID int

	AvailableSIDs map[string]bool

	mu sync.RWMutex

	EndpointConfigPath string

	EndpointConfig *EndpointConfig

	PeerEndpointsMap map[string][]string

	PeerIPPortToEndpointMap map[string]string

	EndpointRefreshInterval time.Duration

	SIDRefreshInterval time.Duration

	stopChan chan struct{}

	LastSessionCounter int64

	PeerChecksums map[string]string

	LastSIDIndex map[string]int64

	SidIndexLock sync.RWMutex
}

func NewPortIPMapper(endpointConfigPath string, endpointRefreshInterval, sidRefreshInterval time.Duration) *PortIPMapper {
	if endpointRefreshInterval == 0 {
		endpointRefreshInterval = 5 * time.Minute
	}
	if sidRefreshInterval == 0 {
		sidRefreshInterval = 5 * time.Second
	}
	return &PortIPMapper{
		SIDToIPMap:              make(map[string]*IPMapEntry),
		IPToSIDMap:              make(map[string]string),
		EndpointToSIDArray:      make(map[string][]int),
		NextSID:                 1,
		AvailableSIDs:           make(map[string]bool),
		EndpointConfigPath:      endpointConfigPath,
		PeerEndpointsMap:        make(map[string][]string),
		EndpointRefreshInterval: endpointRefreshInterval,
		SIDRefreshInterval:      sidRefreshInterval,
		stopChan:                make(chan struct{}),
		PeerChecksums:           make(map[string]string),
		LastSIDIndex:            make(map[string]int64),
		PeerIPPortToEndpointMap: make(map[string]string),
	}
}

func (pim *PortIPMapper) Start(adapter *SOCKS5ToHTTPAdapter) {
	if appConfig.UsePortToIpMapping {
		go func() {
			endpointTicker := time.NewTicker(pim.EndpointRefreshInterval)
			sidTicker := time.NewTicker(pim.SIDRefreshInterval)
			loggingTicker := time.NewTicker(5 * time.Minute)
			defer endpointTicker.Stop()
			defer sidTicker.Stop()
			defer loggingTicker.Stop()

			pim.LoadEndpointConfig()
			pim.RefreshAllPeerMappings()

			for {
				select {
				case <-endpointTicker.C:
					fmt.Println("DEBUG PortIPMapper: Reloading endpoint config")
					pim.LoadEndpointConfig()

					pim.RefreshAllPeerMappings()

				case <-sidTicker.C:

					if pim.CheckIfRefreshNeeded() {
						fmt.Println("INFO PortIPMapper: Checksum indicates data changed, performing refresh")
						pim.RefreshAllPeerMappings()
					}

				case <-loggingTicker.C:

				case <-pim.stopChan:
					fmt.Println("INFO PortIPMapper stopped")
					return
				}
			}
		}()
	}
}

func (pim *PortIPMapper) Stop() {
	close(pim.stopChan)
}

func (pim *PortIPMapper) LoadEndpointConfig() error {
	fmt.Printf("DEBUG Loading endpoint config from: %s\n", pim.EndpointConfigPath)

	data, err := os.ReadFile(pim.EndpointConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read endpoint config file: %w", err)
	}

	var cfg EndpointConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse endpoint config JSON: %w", err)
	}

	peerEndpointsMap := make(map[string][]string)
	peerIPPortToEndpointMap := make(map[string]string)
	for _, endpoint := range cfg.Endpoints {
		if endpoint == nil || len(endpoint.Peers) == 0 {
			continue
		}
		for _, peer := range endpoint.Peers {
			if peer.Addr != "" {
				peerEndpointsMap[peer.Addr] = append(peerEndpointsMap[peer.Addr], endpoint.Endpoint)

				for _, portRange := range peer.Ports {

					parts := strings.Split(portRange, "-")
					if len(parts) == 2 {

						startPort, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
						endPort, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
						if errStart == nil && errEnd == nil {
							for p := startPort; p <= endPort; p++ {
								key := peer.Addr + ":" + strconv.Itoa(p)

								peerIPPortToEndpointMap[key] = endpoint.Endpoint
							}
						}
					} else if len(parts) == 1 {

						port, err := strconv.Atoi(strings.TrimSpace(portRange))
						if err == nil {
							key := peer.Addr + ":" + strconv.Itoa(port)
							peerIPPortToEndpointMap[key] = endpoint.Endpoint
						}
					}
				}
			}
		}
	}

	pim.mu.Lock()
	pim.EndpointConfig = &cfg
	pim.PeerEndpointsMap = peerEndpointsMap
	pim.PeerIPPortToEndpointMap = peerIPPortToEndpointMap
	pim.mu.Unlock()

	fmt.Printf("INFO PortIPMapper loaded %d endpoints and %d unique peer IPs from %s\n", len(cfg.Endpoints), len(peerEndpointsMap), pim.EndpointConfigPath)
	return nil
}

func (pim *PortIPMapper) RefreshAllPeerMappings() {
	fmt.Println("DEBUG Refreshing SID-to-proxy mappings from all peers")
	pim.mu.RLock()
	peerEndpointsMap := pim.PeerEndpointsMap
	pim.mu.RUnlock()

	if len(peerEndpointsMap) == 0 {
		fmt.Println("WARN PortIPMapper: No peer IPs found in config")
		return
	}

	newSIDToIPMap := make(map[string]*IPMapEntry)
	newIPToSIDMap := make(map[string]string)
	newAvailableSIDs := make(map[string]bool)
	seenProxyIPs := make(map[string]bool)
	var nextSID int64 = 1

	var sidLock sync.RWMutex
	var ipLock sync.RWMutex
	var availableLock sync.Mutex
	var seenLock sync.Mutex
	var nextSIDLock sync.Mutex

	pim.mu.RLock()
	for sid, entry := range pim.SIDToIPMap {
		newSIDToIPMap[sid] = entry
		newIPToSIDMap[entry.ProxyIP] = sid
		seenProxyIPs[entry.ProxyIP] = false
		if sidInt, err := strconv.Atoi(sid); err == nil && int64(sidInt) >= nextSID {
			nextSID = int64(sidInt) + 1
		}
	}
	for sid := range pim.AvailableSIDs {
		newAvailableSIDs[sid] = true
	}
	pim.mu.RUnlock()

	var wg sync.WaitGroup
	failed = 0

	for peerIP := range peerEndpointsMap {
		wg.Add(1)
		go func(peer string) {
			defer wg.Done()
			pim.FetchAndPopulateMaps(
				peer,
				newSIDToIPMap, newIPToSIDMap, newAvailableSIDs, seenProxyIPs,
				&sidLock, &ipLock, &availableLock, &seenLock, &nextSIDLock,
				&nextSID,
			)
		}(peerIP)
	}

	wg.Wait()

	pim.mu.RLock()
	oldIPToSIDMap := pim.IPToSIDMap
	pim.mu.RUnlock()

	for proxyIP, sid := range oldIPToSIDMap {
		if !seenProxyIPs[proxyIP] {

			delete(newIPToSIDMap, proxyIP)
			delete(newSIDToIPMap, sid)
			newAvailableSIDs[sid] = true
		}
	}

	if len(newSIDToIPMap) == 0 {
		fmt.Println("WARN PortIPMapper: No mappings collected from any peer")
		return
	}

	pim.mu.Lock()
	pim.SIDToIPMap = newSIDToIPMap
	pim.IPToSIDMap = newIPToSIDMap
	pim.NextSID = int(nextSID)
	pim.AvailableSIDs = newAvailableSIDs
	pim.mu.Unlock()

	endpointToSIDArray := make(map[string][]int)
	for sid, entry := range newSIDToIPMap {

		if endpoints, ok := peerEndpointsMap[entry.PeerIP]; ok {

			sidInt, _ := strconv.Atoi(sid)
			for _, endpoint := range endpoints {

				pim.mu.RLock()
				key := entry.PeerIP + ":" + strconv.Itoa(entry.Port)
				mappedEndpoint, ok := pim.PeerIPPortToEndpointMap[key]

				if ok && strings.ToLower(mappedEndpoint) == strings.ToLower(endpoint) {
					endpointToSIDArray[strings.ToLower(endpoint)] = append(endpointToSIDArray[strings.ToLower(endpoint)], sidInt)
				}
				pim.mu.RUnlock()
			}
		}
	}

	for _, sidArray := range endpointToSIDArray {
		sort.Ints(sidArray)
	}

	if rcAllArray, exists := endpointToSIDArray["rc_all"]; exists {
		fmt.Printf("INFO PortIPMapper: rc_all endpoint has %d SIDs\n", len(rcAllArray))
	}
	if rcGBArray, exists := endpointToSIDArray["rc_gb"]; exists {
		fmt.Printf("INFO PortIPMapper: rc_gb endpoint has %d SIDs\n", len(rcGBArray))
	}
	if rcUSArray, exists := endpointToSIDArray["rc_us"]; exists {
		fmt.Printf("INFO PortIPMapper: rc_us endpoint has %d SIDs\n", len(rcUSArray))
	}

	pim.mu.Lock()
	pim.EndpointToSIDArray = endpointToSIDArray
	pim.mu.Unlock()

	fmt.Printf("INFO PortIPMapper: Refreshed %d SID->IP mappings from %d peers (NextSID=%d, AvailableSIDs=%d)\n",
		len(newSIDToIPMap), len(peerEndpointsMap), nextSID, len(newAvailableSIDs))
}

func (pim *PortIPMapper) FetchPortIPMap(peerAddr string) (map[int]string, error) {

	peerHost := peerAddr
	if idx := strings.LastIndex(peerAddr, ":"); idx != -1 {
		peerHost = peerAddr[:idx]
	}

	url := fmt.Sprintf("http://%s/all_port_ip_map.json", peerHost)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("peer returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var portIPMap map[string]string
	if err := json.Unmarshal(body, &portIPMap); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	result := make(map[int]string)
	for portStr, proxyIP := range portIPMap {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			fmt.Printf("WARN PortIPMapper: Invalid port number %s: %v\n", portStr, err)
			continue
		}
		result[port] = proxyIP
	}

	return result, nil
}

func (pim *PortIPMapper) CheckIfRefreshNeeded() bool {
	pim.mu.RLock()
	rcAllEndpoint := pim.EndpointToSIDArray["rc_all"]
	peerEndpointsMapCopy := pim.PeerEndpointsMap
	pim.mu.RUnlock()

	if len(rcAllEndpoint) == 0 {
		fmt.Println("INFO PortIPMapper: rc_all endpoint empty, refresh needed")
		return true
	}

	var peersToCheck []string
	for peerIP := range peerEndpointsMapCopy {
		peersToCheck = append(peersToCheck, peerIP)
	}
	sort.Strings(peersToCheck)

	maxSamples := 10
	if len(peersToCheck) < maxSamples {
		maxSamples = len(peersToCheck)
	}

	step := len(peersToCheck) / maxSamples
	if step < 1 {
		step = 1
	}

	var samplesToCheck []string
	for i := 0; i < len(peersToCheck); i += step {
		if len(samplesToCheck) < maxSamples {
			samplesToCheck = append(samplesToCheck, peersToCheck[i])
		}
	}

	if len(samplesToCheck) > maxSamples {
		samplesToCheck = samplesToCheck[:maxSamples]
	}

	needsRefresh := false

	for _, peerIP := range samplesToCheck {
		portIPMap, err := pim.FetchPortIPMap(peerIP)
		if err != nil {

			continue
		}

		jsonData, _ := json.Marshal(portIPMap)
		newChecksum := fmt.Sprintf("%x", md5.Sum(jsonData))

		pim.mu.RLock()
		oldChecksum := pim.PeerChecksums[peerIP]
		pim.mu.RUnlock()

		if oldChecksum != newChecksum {
			fmt.Printf("INFO PortIPMapper: Checksum changed for peer %s (was %s, now %s), refresh needed\n",
				peerIP, oldChecksum, newChecksum)

			pim.mu.Lock()
			pim.PeerChecksums[peerIP] = newChecksum
			pim.mu.Unlock()

			atomic.AddInt64(&refreshNeededCount, 1)
			needsRefresh = true
		}
	}

	return needsRefresh
}

var failed int64

func (pim *PortIPMapper) FetchAndPopulateMaps(
	peerIP string,
	newSIDToIPMap map[string]*IPMapEntry,
	newIPToSIDMap map[string]string,
	newAvailableSIDs map[string]bool,
	seenProxyIPs map[string]bool,
	sidLock, ipLock *sync.RWMutex,
	availableLock, seenLock, nextSIDLock *sync.Mutex,
	nextSID *int64,
) {

	portIPMap, err := pim.FetchPortIPMap(peerIP)

	if err != nil {
		atomic.AddInt64(&failed, 1)

		return
	}

	for port, proxyIP := range portIPMap {

		seenLock.Lock()
		seenProxyIPs[proxyIP] = true
		seenLock.Unlock()

		ipLock.RLock()
		sid, exists := newIPToSIDMap[proxyIP]
		ipLock.RUnlock()

		if !exists {

			availableLock.Lock()

			var foundInPool bool
			for availableSID := range newAvailableSIDs {
				sid = availableSID
				delete(newAvailableSIDs, availableSID)
				foundInPool = true
				break
			}

			if !foundInPool {
				nextVal := atomic.AddInt64(nextSID, 1)
				sid = strconv.FormatInt(nextVal, 10)
			}

			availableLock.Unlock()

			ipLock.Lock()
			newIPToSIDMap[proxyIP] = sid
			ipLock.Unlock()
		}

		entry := &IPMapEntry{
			PeerIP:  peerIP,
			ProxyIP: proxyIP,
			Port:    port,
		}

		sidLock.Lock()
		newSIDToIPMap[sid] = entry
		sidLock.Unlock()

	}
}

func (pim *PortIPMapper) GetIPBySessionID(sessionID string) (*IPMapEntry, error) {
	pim.mu.RLock()
	defer pim.mu.RUnlock()

	if len(pim.SIDToIPMap) == 0 {
		return nil, fmt.Errorf("no IP mappings available")
	}

	var sidInt int

	if sessionID == "" {
		counter := atomic.AddInt64(&pim.LastSessionCounter, 1)

		maxSID := int64(pim.NextSID)
		if maxSID <= 0 {
			maxSID = 1
		}
		sidInt = int((counter - 1) % maxSID)
	} else {

		var err error
		sidInt, err = strconv.Atoi(sessionID)
		if err != nil {
			return nil, fmt.Errorf("invalid session ID format %s: %w", sessionID, err)
		}
	}

	maxAttempts := len(pim.SIDToIPMap) + 1000
	for attempts := 0; attempts < maxAttempts; attempts++ {
		currentSID := strconv.Itoa(sidInt + attempts)
		if entry, exists := pim.SIDToIPMap[currentSID]; exists {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("no mapping found for SID %s or any subsequent SID", sessionID)
}

var num int

func (pim *PortIPMapper) GetIPByEndpointAndSID(endpoint string, sidInt int) (*IPMapEntry, error) {
	pim.mu.RLock()
	sidArray, endpointExists := pim.EndpointToSIDArray[strings.ToLower(endpoint)]
	pim.mu.RUnlock()
	num++

	if !endpointExists || len(sidArray) == 0 {
		return nil, fmt.Errorf("no SIDs available for endpoint %s", endpoint)
	}

	index := sidInt % len(sidArray)
	selectedSID := sidArray[index]
	selectedSIDStr := strconv.Itoa(selectedSID)

	pim.mu.RLock()
	entry, exists := pim.SIDToIPMap[selectedSIDStr]
	pim.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no mapping found for selected SID %d (from endpoint %s, index %d)", selectedSID, endpoint, index)
	}

	return entry, nil
}

func (pim *PortIPMapper) GetNextSIDByEndpoint(endpoint string) (*IPMapEntry, error) {

	endpointLower := strings.ToLower(endpoint)

	pim.SidIndexLock.RLock()
	currentIndex := pim.LastSIDIndex[endpointLower]
	pim.SidIndexLock.RUnlock()

	if currentIndex < 0 {
		pim.SidIndexLock.Lock()
		pim.LastSIDIndex[endpointLower] = 0
		pim.SidIndexLock.Unlock()
		currentIndex = 0
	}

	pim.mu.RLock()
	sidArray, endpointExists := pim.EndpointToSIDArray[endpointLower]
	if !endpointExists || len(sidArray) == 0 {
		pim.mu.RUnlock()
		return nil, fmt.Errorf("no SIDs available for endpoint %s", endpoint)
	}

	pim.SidIndexLock.Lock()
	pim.LastSIDIndex[endpointLower]++
	pim.SidIndexLock.Unlock()

	index := int(currentIndex % int64(len(sidArray)))
	selectedSID := sidArray[index]

	pim.mu.RUnlock()

	selectedSIDStr := strconv.Itoa(selectedSID)

	pim.mu.RLock()
	entry, exists := pim.SIDToIPMap[selectedSIDStr]
	pim.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no mapping found for selected SID %d (from endpoint %s, index %d)", selectedSID, endpoint, currentIndex)
	}

	return entry, nil
}

func (pim *PortIPMapper) GetNextDifEndpoint() (*IPMapEntry, error) {
	pim.mu.RLock()
	sidMap := pim.SIDToIPMap
	nextSID := pim.NextSID
	pim.mu.RUnlock()

	if len(sidMap) == 0 {
		return nil, fmt.Errorf("no IP mappings available")
	}

	counter := atomic.AddInt64(&globalSIDCounter, 1)

	maxSID := int64(nextSID)
	if maxSID <= 0 {
		maxSID = 1
	}
	currentSIDInt := int((counter - 1) % maxSID)

	for attempts := 0; attempts < 10000; attempts++ {
		sidStr := strconv.Itoa(currentSIDInt + attempts)
		if entry, exists := sidMap[sidStr]; exists {
			return entry, nil
		}
	}

	return nil, fmt.Errorf("no available SID found after 10000 attempts (counter=%d)", counter)
}

func (pim *PortIPMapper) GetBySID(sid int) (*IPMapEntry, error) {
	pim.mu.RLock()
	sidStr := strconv.Itoa(sid)
	entry, exists := pim.SIDToIPMap[sidStr]
	pim.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no mapping found for SID %d", sid)
	}

	return entry, nil
}

func (pim *PortIPMapper) GetSIDByProxyIP(proxyIP string) (string, error) {
	pim.mu.RLock()
	defer pim.mu.RUnlock()

	sid, exists := pim.IPToSIDMap[proxyIP]
	if !exists {
		return "", fmt.Errorf("no SID found for proxy IP %s", proxyIP)
	}

	return sid, nil
}

func (pim *PortIPMapper) LogEndpointSIDArrayToFile() {
	logFile := "/var/log/myfile"
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	pim.mu.RLock()
	defer pim.mu.RUnlock()

	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Printf("WARN PortIPMapper: Failed to open log file %s: %v\n", logFile, err)
		return
	}
	defer f.Close()

	header := fmt.Sprintf("\n===== EndpointToSIDArray Snapshot at %s =====\n", timestamp)
	if _, err := f.WriteString(header); err != nil {
		fmt.Printf("WARN PortIPMapper: Failed to write header to log file: %v\n", err)
		return
	}

	for endpoint, sidArray := range pim.EndpointToSIDArray {
		sidArrayStr := make([]string, len(sidArray))
		for i, sid := range sidArray {
			sidArrayStr[i] = strconv.Itoa(sid)
		}
		endpointLine := fmt.Sprintf("Endpoint: %s | SID Count: %d | SIDs: [%s]\n",
			endpoint, len(sidArray), strings.Join(sidArrayStr, ", "))
		if _, err := f.WriteString(endpointLine); err != nil {
			fmt.Printf("WARN PortIPMapper: Failed to write endpoint line: %v\n", err)
			return
		}

		for idx, sid := range sidArray {
			sidStr := strconv.Itoa(sid)
			if entry, exists := pim.SIDToIPMap[sidStr]; exists {
				detailLine := fmt.Sprintf("  [%d] SID=%d -> PeerIP=%s | ProxyIP=%s | Port=%d\n",
					idx, sid, entry.PeerIP, entry.ProxyIP, entry.Port)
				if _, err := f.WriteString(detailLine); err != nil {
					fmt.Printf("WARN PortIPMapper: Failed to write detail line: %v\n", err)
					return
				}
			}
		}
	}

	footer := fmt.Sprintf("===== END Snapshot =====\n\n")
	if _, err := f.WriteString(footer); err != nil {
		fmt.Printf("WARN PortIPMapper: Failed to write footer: %v\n", err)
	}
}
