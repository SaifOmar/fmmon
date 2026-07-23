package macspoof

import (
	"fmt"
	"math/rand"
	"net"
)

func RandomMAC() (net.HardwareAddr, error) {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("rand read: %w", err)
	}
	buf[0] = (buf[0] | 0x02) & 0xfe
	return net.HardwareAddr(buf), nil
}

func ValidateMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}
