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
		if len(fields) >= 5 && fields[0] == "0.0.0.0/0" {
			ip := net.ParseIP(fields[2])
			if ip == nil {
				return nil, fmt.Errorf("parse gateway IP: %s", fields[2])
			}
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no default gateway found")
}
