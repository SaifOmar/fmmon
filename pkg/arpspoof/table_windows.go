//go:build windows

package arpspoof

import (
	"fmt"
	"net"
	"os/exec"
)

func FlushARPCache(ip net.IP) error {
	cmd := exec.Command("arp", "-d", ip.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("arp -d: %s: %w", string(out), err)
	}
	return nil
}
