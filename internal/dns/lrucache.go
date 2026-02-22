package dns

import (
	"container/list"
	"errors"
	"log"
	"math/rand"
	"net"
	"slickproxy/internal/config"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var Cache *LRUCache

type Entry struct {
	Key         string
	IPv4List    []string
	IPv6List    []string
	IPv4Expires time.Time
	IPv6Expires time.Time
}

type LRUCache struct {
	capacity int
	cache    map[string]*list.Element
	ll       *list.List
	mu       sync.RWMutex
}

func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,
		cache:    make(map[string]*list.Element),
		ll:       list.New(),
	}
}

func init() {
	Cache = NewLRUCache(50000)
}

func (l *LRUCache) Set(domain string, ipv4 []string, ipv6 []string, ipv4TTL, ipv6TTL time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	if element, exists := l.cache[domain]; exists {
		l.ll.Remove(element)
	}

	entry := &Entry{
		Key:         domain,
		IPv4List:    ipv4,
		IPv6List:    ipv6,
		IPv4Expires: now.Add(ipv4TTL),
		IPv6Expires: now.Add(ipv6TTL),
	}

	element := l.ll.PushFront(entry)
	l.cache[domain] = element

	if l.ll.Len() > l.capacity {
		l.removeOldest()
	}
}

func (l *LRUCache) Get(domain string, isIPv4 bool) ([]string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if element, exists := l.cache[domain]; exists {
		entry := element.Value.(*Entry)

		if isIPv4 {
			if time.Now().After(entry.IPv4Expires) {
				return nil, false
			}

			return entry.IPv4List, true
		} else {
			if time.Now().After(entry.IPv6Expires) {
				return nil, false
			}
			return entry.IPv6List, true
		}
	}
	return nil, false
}

func (l *LRUCache) removeOldest() {
	oldest := l.ll.Back()
	if oldest != nil {
		l.ll.Remove(oldest)
		entry := oldest.Value.(*Entry)
		delete(l.cache, entry.Key)
	}
}

var staticMap = map[string][]string{
	"ticket-onlineshop.com.":     {"95.101.46.169"},
	"www.ticket-onlineshop.com.": {"95.101.46.169"},
	"api.ticket-onlineshop.com.": {"95.101.46.169"},
}
var first bool

func ResolveDNS(domain string, isIPv4 bool) ([]string, time.Duration, error) {
	client := &dns.Client{
		Timeout: 5 * time.Second,
	}
	if ips, ok := staticMap[domain]; ok {
		if !first {
			first = true
			log.Printf("Using static DNS for %s: %v", domain, ips)
		}
		return ips, 24 * time.Hour, nil
	}

	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	if !isIPv4 {
		message.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
	}

	dnsServer := config.Cfg.General.DNSServer
	if dnsServer == "" {
		dnsServer = "8.8.8.8:53"
	}

	response, _, err := client.Exchange(message, dnsServer)
	if err != nil {
		return nil, 0, err
	}

	var addresses []string
	var ttl time.Duration

	for _, answer := range response.Answer {
		switch record := answer.(type) {
		case *dns.A:
			addresses = append(addresses, record.A.String())
			ttl = time.Duration(record.Hdr.Ttl) * time.Second
		case *dns.AAAA:
			addresses = append(addresses, record.AAAA.String())
			ttl = time.Duration(record.Hdr.Ttl) * time.Second
		}
	}

	if len(addresses) == 0 {
		return nil, 0, errors.New("no addresses found for " + domain)
	}

	return addresses, ttl, nil
}

func (l *LRUCache) LookupAndCache(domain string, isIPv4 bool) (string, error) {

	if net.ParseIP(domain) != nil {
		return domain, nil
	}

	addresses, found := l.Get(domain, isIPv4)
	if found && len(addresses) > 0 {
		return addresses[rand.Intn(len(addresses))], nil
	}

	addresses, ttl, err := ResolveDNS(domain, isIPv4)
	if err != nil {
		return "", err
	}

	if isIPv4 {
		l.Set(domain, addresses, nil, ttl, 0)
	} else {
		l.Set(domain, nil, addresses, 0, ttl)
	}

	if len(addresses) > 0 {
		return addresses[rand.Intn(len(addresses))], nil
	}

	return "", errors.New("no addresses found after lookup")
}
