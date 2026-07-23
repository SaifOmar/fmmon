package network

import (
	"fmt"
	"net"
)

func ListInterfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}

	var result []InterfaceInfo
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ips []net.IP
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}

		result = append(result, InterfaceInfo{
			Name:       iface.Name,
			MAC:        iface.HardwareAddr,
			IPs:        ips,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			MTU:        iface.MTU,
			Flags:      iface.Flags,
		})
	}
	return result, nil
}

func SelectInterface(name string) (*InterfaceInfo, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == name {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("interface %q not found", name)
}

func PickDefaultInterface() (*InterfaceInfo, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.IsUp && !iface.IsLoopback && len(iface.IPs) > 0 {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("no suitable interface found")
}
