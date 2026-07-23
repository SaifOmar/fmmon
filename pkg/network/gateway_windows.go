//go:build windows

package network

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func GetGateway() (net.IP, error) {
	cmd := exec.Command("netsh", "interface", "ip", "show", "route")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("netsh route: %w", err)
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "0.0.0.0/0" && i+1 < len(fields) {
				gw := fields[len(fields)-1]
				ip := net.ParseIP(gw)
				if ip != nil {
					return ip, nil
				}
				break
			}
		}
	}
	return nil, fmt.Errorf("no default gateway found")
}
