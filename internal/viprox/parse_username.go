package viprox

import (
	"log"
	"regexp"
)

var (
	reCCSID          = regexp.MustCompile(`^([^-]+)-.*-cc-([^\s-]+)-sid-([^\s-]+)$`)
	reUserCodeSid    = regexp.MustCompile(`^([^-]+)-([^\s-]+)-([^\s-]+)$`)
	reUserCodeSidTtl = regexp.MustCompile(`^([^-]+)-([^\s-]+)-([^\s-]+)-(\d+)$`)
	reUserCode       = regexp.MustCompile(`^([^-]+)-([^\s-]+)$`)
)

func parseUsername(full string) (user, code, sid string) {
	if m := reCCSID.FindStringSubmatch(full); m != nil {
		return m[1], m[2], m[3]
	}
	if m := reUserCodeSid.FindStringSubmatch(full); m != nil {
		return m[1], m[2], m[3]
	}
	if m := reUserCode.FindStringSubmatch(full); m != nil {
		return m[1], m[2], ""
	}
	log.Println("⚠️ Failed to parse username:", full)
	return full, "", ""
}
