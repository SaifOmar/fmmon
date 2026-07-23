//go:build linux

package arpspoof

import (
	"fmt"
	"net"
	"os/exec"
)

func FlushARPCache(ip net.IP) error {
	cmd := exec.Command("ip", "neigh", "del", ip.String(), "dev", "all")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("flush arp: %s: %w", string(out), err)
	}
	return nil
}
