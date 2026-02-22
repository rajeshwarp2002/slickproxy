package upstream

import (
	"fmt"
	"math/rand"
	"slickproxy/internal/config"
	"slickproxy/internal/request"
	"slickproxy/internal/session_cache"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

var cache *session_cache.HeapCache

func GenerateProxy(rv *request.Request) error {
	if cache == nil {
		cache = session_cache.NewHeapCache(config.Cfg.Server.MaxSessions)
	}

	targetSessionId := ""
	if rv.Credentials.Session != "" {

		session, found := cache.Get(rv.Credentials.Session)
		if found {

			rv.Credentials.UserPart = session
			return nil
		}
		targetSessionId = fmt.Sprintf("%d", rand.Int63n(10000000000))

	}

	var username string
	switch rv.UpstreamProxy.Name {
	case "viprox":
		mobile := ""
		stateCity := ""
		if rv.Credentials.City != "" {
			stateCity = "_" + rv.Credentials.City
		}
		if rv.Credentials.Mobile {
			mobile = "_mob"
		}
		sessionIdStr := ""
		if rv.Credentials.Session != "" {
			sessionIdStr = "-" + targetSessionId
		}
		username = fmt.Sprintf("%s%s%s%s%s", rv.UpstreamProxy.Username, formatCountry("-rc_", rv.Credentials.Country, "all"), mobile, stateCity, sessionIdStr)
	case "plainproxies":
		sessionStrTtl := ""
		sessionStr := ""
		if rv.Credentials.Session != "" {
			sessionStr = "-session-" + targetSessionId
			sessionStrTtl = "-ttl-21600"
		}
		username = fmt.Sprintf("%s%s%s%s", rv.UpstreamProxy.Username, formatCountry("-country-", rv.Credentials.Country, ""), sessionStr, sessionStrTtl)

	default:
		return fmt.Errorf("provider %s is not implemented, custom generation not available", rv.UpstreamProxy.Name)
	}

	rv.Credentials.UserPart = username
	if rv.Credentials.Session != "" {

		cache.Set(rv.Credentials.Session, rv.Credentials.UserPart, time.Duration(rv.Credentials.Time)*time.Second)
	}
	return nil

}

func formatCountry(prefix string, country string, def string) string {
	if country == "" {
		country = def
	}
	if country == "" {
		return ""
	}
	return fmt.Sprintf("%s%s", prefix, country)
}

func formatSession(session bool, prefix string, countryCode string, length int) string {
	if session == false {
		return ""
	}

	return fmt.Sprintf("%s%s", prefix, GenerateRandomString(countryCode, length, "0123456789"))
}

func GenerateRandomString(prefix string, length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return prefix + string(b)
}

func GenerateRandomStringInRange(prefix string) string {

	min := 800000000
	max := 999999999
	num := rand.Intn(max-min+1) + min

	return fmt.Sprintf("%s%d", prefix, num)
}
