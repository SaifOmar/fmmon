package network

import (
	"fmt"
	"net"

	"github.com/google/gopacket/pcap"
)

func ResolvePcapDeviceName(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("interface lookup: %w", err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("get interface addrs: %w", err)
	}

	var localIPs []net.IP
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		localIPs = append(localIPs, ipnet.IP.To4())
	}

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("find pcap devices: %w", err)
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP == nil {
				continue
			}
			for _, localIP := range localIPs {
				if addr.IP.Equal(localIP) {
					return dev.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no pcap device found for interface %q", ifaceName)
}
