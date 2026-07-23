//go:build windows

package macspoof

import (
	"fmt"
	"net"
	"os/exec"
)

func SetMAC(ifaceName string, mac net.HardwareAddr) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", ifaceName),
		fmt.Sprintf("mac=%s", mac.String()))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set mac: %s: %w", string(out), err)
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
