package viprox

import (
	"bufio"
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type userAuthData struct {
	password   string
	dayLimit   int
	allowedIPs map[string]struct{}
}

type AuthHelper struct {
	basePassDir string
	baseIPDir   string
	data        map[string]*userAuthData
	dataMu      sync.RWMutex
}

func NewAuthHelper(ctx context.Context, passDir, ipDir string) *AuthHelper {
	auth := &AuthHelper{
		basePassDir: passDir,
		baseIPDir:   ipDir,
		data:        make(map[string]*userAuthData),
	}
	go auth.refreshLoop(ctx)
	return auth
}

func (a *AuthHelper) refreshLoop(ctx context.Context) {
	a.loadUserData()
	ticker := time.NewTicker(time.Duration(appConfig.AuthRefreshInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("🔄 Refreshing user credentials")
			a.loadUserData()
		}
	}
}

func (a *AuthHelper) loadUserData() {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()

	entries, err := os.ReadDir(a.basePassDir)
	if err != nil {
		log.Printf("read password dir failed: %v", err)
		return
	}

	existingUsers := make(map[string]struct{})

	for _, entry := range entries {
		user := entry.Name()
		existingUsers[user] = struct{}{}

		passBytes, err := os.ReadFile(filepath.Join(a.basePassDir, user))
		if err != nil {
			continue
		}
		pass := strings.TrimSpace(string(passBytes))

		limit := 0
		limitFile := filepath.Join(a.baseIPDir, user+"_day_limit")
		limitBytes, err := os.ReadFile(limitFile)
		if err == nil {
			limit, _ = strconv.Atoi(strings.TrimSpace(string(limitBytes)))
		}

		ipFile := filepath.Join(a.baseIPDir, user+"_day_ips")
		ips := make(map[string]struct{})
		if f, err := os.Open(ipFile); err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				ip := strings.TrimSpace(scanner.Text())
				if ip != "" {
					ips[ip] = struct{}{}
				}
			}
		}

		a.data[user] = &userAuthData{
			password:   pass,
			dayLimit:   limit,
			allowedIPs: ips,
		}
	}

	for user := range a.data {
		if _, ok := existingUsers[user]; !ok {
			delete(a.data, user)
		}
	}
}

func (a *AuthHelper) Check(username, password, sourceIP string) (bool, error) {
	a.dataMu.RLock()
	userData, exists := a.data[username]
	a.dataMu.RUnlock()
	if !exists || userData.password != password {
		return false, nil
	}

	if userData.dayLimit == 0 || userData.dayLimit > 1 && hasIP(userData.allowedIPs, sourceIP) {
		return true, nil
	}

	return false, nil
}

func hasIP(allowed map[string]struct{}, ip string) bool {
	_, ok := allowed[ip]
	return ok
}
