package scanner

import (
	"net"
)

var customNames = make(map[string]string)

func SetCustomName(ip, name string) {
	customNames[ip] = name
}

func GetCustomName(ip string) (string, bool) {
	name, ok := customNames[ip]
	return name, ok
}

func ResolveHostname(ip net.IP) string {
	ipStr := ip.String()
	if name, ok := customNames[ipStr]; ok {
		return name
	}

	names, err := net.LookupAddr(ipStr)
	if err == nil && len(names) > 0 {
		return names[0]
	}

	return ""
}
