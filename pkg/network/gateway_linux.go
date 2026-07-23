//go:build linux

package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func GetGateway() (net.IP, error) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/route: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" {
			ipBytes, err := parseHexIP(fields[2])
			if err != nil {
				return nil, err
			}
			return net.IP(ipBytes), nil
		}
	}
	return nil, fmt.Errorf("no default gateway found")
}

func parseHexIP(hex string) (net.IP, error) {
	if len(hex) != 8 {
		return nil, fmt.Errorf("invalid hex IP length: %s", hex)
	}
	val, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return nil, fmt.Errorf("parse hex: %w", err)
	}
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, uint32(val))
	return ip, nil
}
