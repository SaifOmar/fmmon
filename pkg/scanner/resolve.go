package scanner

import (
	"net"
	"sync"
	"time"
)

var customNames = make(map[string]string)

func SetCustomName(ip, name string) {
	customNames[ip] = name
}

func GetCustomName(ip string) (string, bool) {
	name, ok := customNames[ip]
	return name, ok
}

var dnsTimeout = 2 * time.Second

func ResolveHostname(ip net.IP) string {
	ipStr := ip.String()
	if name, ok := customNames[ipStr]; ok {
		return name
	}

	done := make(chan string, 1)
	go func() {
		names, err := net.LookupAddr(ipStr)
		if err == nil && len(names) > 0 {
			done <- names[0]
		}
		close(done)
	}()

	select {
	case name, ok := <-done:
		if ok {
			return name
		}
		return ""
	case <-time.After(dnsTimeout):
		return ""
	}
}

func ResolveHostnames(ips []net.IP) map[string]string {
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			hostname := ResolveHostname(ip)
			if hostname != "" {
				mu.Lock()
				results[ip.String()] = hostname
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}
