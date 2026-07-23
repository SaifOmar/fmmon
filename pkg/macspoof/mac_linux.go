//go:build linux

package macspoof

import (
	"fmt"
	"net"
	"os/exec"
)

func SetMAC(ifaceName string, mac net.HardwareAddr) error {
	cmd := exec.Command("ip", "link", "set", "dev", ifaceName, "down")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link down: %s: %w", string(out), err)
	}

	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "address", mac.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set mac: %s: %w", string(out), err)
	}

	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link up: %s: %w", string(out), err)
	}

	return nil
}

func GetCurrentMAC(ifaceName string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	return iface.HardwareAddr, nil
}
