package request

import (
	"fmt"
	"log"
	"regexp"
	"slickproxy/internal/config"
	"strconv"
	"strings"
)

var (
	reCCSID          = regexp.MustCompile(`^([^-]+)-.*-cc-([^\s-]+)-sid-([^\s-]+)$`)
	reUserCodeSid    = regexp.MustCompile(`^([^-]+)-([^\s-]+)-([^\s-]+)$`)
	reUserCodeSidTtl = regexp.MustCompile(`^([^-]+)-([^\s-]+)-([^\s-]+)-(\d+)$`)
	reUserCode       = regexp.MustCompile(`^([^-]+)-([^\s-]+)$`)
)

func viproxParseUsername(fullUsername string) (user, code, sid string) {
	if matches := reCCSID.FindStringSubmatch(fullUsername); matches != nil {
		return matches[1], matches[2], matches[3]
	}
	if matches := reUserCodeSid.FindStringSubmatch(fullUsername); matches != nil {
		return matches[1], matches[2], matches[3]
	}
	if matches := reUserCode.FindStringSubmatch(fullUsername); matches != nil {
		return matches[1], matches[2], ""
	}
	log.Println("⚠️ Failed to parse username:", fullUsername)
	return fullUsername, "", ""
}

func (auth *AuthenticationCredentials) ParseAuthentication(decodedAuthString string) {
	if config.Cfg.General.Viprox_auth {
		parts := strings.SplitN(decodedAuthString, ":", 2)
		if len(parts) == 0 {
			return
		}
		userPart := parts[0]
		if len(parts) > 1 {
			auth.Password = parts[1]
		}

		auth.User, auth.Code, auth.Session = viproxParseUsername(userPart)
		return
	}

	extractedFields, extractedUser, extractedPassword, extractedUserPart := parseProxyCredentialsString(decodedAuthString)
	auth.User = extractedUser
	auth.UserPart = extractedUserPart
	auth.Password = extractedPassword

	for fieldKey, fieldValue := range extractedFields {
		switch fieldKey {
		case "password":
			auth.Password = fieldValue
		case "session":
			auth.Session = fieldValue
		case "country":
			auth.Country = fieldValue
		case "city":
			auth.City = fieldValue
		case "state":
			auth.State = fieldValue
		case "ttl":
			if parsedTTL, err := strconv.Atoi(fieldValue); err == nil {
				auth.Time = parsedTTL
			}
		case "time":
			if parsedTTL, err := strconv.Atoi(fieldValue); err == nil {
				auth.Time = parsedTTL
			}
		case "lifetime":
			if parsedTTL, err := strconv.Atoi(fieldValue); err == nil {
				auth.Time = parsedTTL
			}
		}
	}

	if (auth.Time == 0 && auth.Session != "") || (auth.Time > config.Cfg.Server.DefaultSessionTTL) {
		auth.Time = config.Cfg.Server.DefaultSessionTTL
	}

	if auth.Session != "" {
		auth.OriginalSession = auth.Session
		auth.Session = auth.User + "_" + auth.Session
	}

	auth.Code = "rc_all"
	if auth.Country != "" {
		auth.Code = "rc_" + auth.Country
	}
	if auth.City != "" {
		auth.Code += "_" + auth.City
	}
}

func parseProxyCredentialsString(proxyAuthString string) (map[string]string, string, string, string) {
	parts := strings.SplitN(proxyAuthString, ":", 2)
	usernamePart := parts[0]
	password := ""
	if len(parts) > 1 {
		password = parts[1]
	}

	segments := strings.Split(usernamePart, "-")
	extractedFields := make(map[string]string, len(segments)/2)
	username := segments[0]

	for i := 1; i < len(segments)-1; i += 2 {
		extractedFields[segments[i]] = segments[i+1]
	}

	return extractedFields, username, password, usernamePart
}

func ExtractPackageType(key string) (string, error) {
	firstColon := strings.IndexByte(key, ':')
	if firstColon == -1 {
		return "", fmt.Errorf("invalid key format")
	}
	return key[:firstColon], nil
}
