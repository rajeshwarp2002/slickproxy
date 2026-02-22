package viprox

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type CredentialCache struct {
	data map[string][2]string
	mu   sync.RWMutex
}

func NewCredentialCache() *CredentialCache {
	return &CredentialCache{
		data: make(map[string][2]string),
	}
}

func (c *CredentialCache) LoadFromFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			fmt.Printf("Skipping malformed line: %s\n", line)
			continue
		}

		code := strings.ToLower(parts[0])
		username := parts[1]
		password := parts[2]

		c.mu.Lock()
		c.data[code] = [2]string{username, password}
		c.mu.Unlock()
	}

	return scanner.Err()
}

func (c *CredentialCache) GetCredentials(code string) (string, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	creds, ok := c.data[code]

	if !ok {
		return "", "", false
	}
	return creds[0], creds[1], true
}
