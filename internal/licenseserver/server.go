package licenseserver

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const licenseEncryptionKey = "hyi76gsr"

type LicenseRequest struct {
	MachineInfo string `json:"machine_info"` // Hostname and all local IPs
}

type LicenseResponse struct {
	CutoffDate string `json:"cutoff_date"` // Encrypted cutoff date
	Status     string `json:"status"`      // "ok" or error message
}

// UnlicensedStrings is the list of strings that make a machine UNLICENSED
// If MachineInfo contains any of these strings, the machine is unlicensed (expires now)
// Otherwise, all machines are licensed (1 month from now)
var UnlicensedStrings = []string{} // Fill with strings that trigger unlicense

// encryptData encrypts data using AES with the given key
func encryptData(data string, keyStr string) (string, error) {
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

	nonce := make([]byte, gcm.NonceSize())
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// Return as hex string
	return fmt.Sprintf("%x", ciphertext), nil
}

// HandleLicenseCheck handles POST requests from slickproxy clients
func HandleLicenseCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var licReq LicenseRequest
	err := json.NewDecoder(r.Body).Decode(&licReq)
	if err != nil {
		log.Printf("Error decoding license request: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	log.Printf("License check request from: %s", licReq.MachineInfo)

	// Determine cutoff date based on whether machine is unlicensed
	var cutoffDate time.Time
	now := time.Now().UTC()
	isUnlicensed := false

	// Check if machine info contains any unlicensed strings
	for _, unlicensedStr := range UnlicensedStrings {
		if strings.Contains(licReq.MachineInfo, unlicensedStr) {
			isUnlicensed = true
			log.Printf("Unlicensed request (contains '%s') - cutoff: %s", unlicensedStr, now.Format(time.RFC3339))
			break
		}
	}

	if isUnlicensed {
		// Unlicensed machine - expires now
		cutoffDate = now
	} else {
		// Licensed machine (default) - give 1 month license
		cutoffDate = now.AddDate(0, 1, 0) // Add 1 month
		log.Printf("Licensed request - cutoff: %s", cutoffDate.Format(time.RFC3339))
	}

	// Encrypt cutoff date
	cutoffDateStr := cutoffDate.Format(time.RFC3339)
	encryptedCutoff, err := encryptData(cutoffDateStr, licenseEncryptionKey)
	if err != nil {
		log.Printf("Error encrypting cutoff date: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Build response
	response := LicenseResponse{
		CutoffDate: encryptedCutoff,
		Status:     "ok",
	}

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)

	log.Printf("License response sent with cutoff: %s", cutoffDate.Format(time.RFC3339))
}

// StartLicenseServer starts the licensing server on the specified port
func StartLicenseServer(port string) error {
	http.HandleFunc("/license/check", HandleLicenseCheck)

	log.Printf("Starting license server on port %s", port)
	log.Printf("Unlicensed strings list: %v (default license: 1 month)", UnlicensedStrings)
	return http.ListenAndServe(":"+port, nil)
}

// AddUnlicensedString adds a string to the unlicensed strings list
func AddUnlicensedString(s string) {
	UnlicensedStrings = append(UnlicensedStrings, s)
	log.Printf("Added unlicensed string: '%s'", s)
}

// SetUnlicensedStrings replaces the entire unlicensed strings list
func SetUnlicensedStrings(strings []string) {
	UnlicensedStrings = strings
	log.Printf("Unlicensed strings set to: %v", strings)
}
