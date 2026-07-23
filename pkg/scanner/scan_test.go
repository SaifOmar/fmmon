package scanner

import (
	"net"
	"testing"
)

func TestIterateIPs_24(t *testing.T) {
	netIP := net.ParseIP("192.168.1.0")
	_, subnet, _ := net.ParseCIDR("192.168.1.0/24")

	var ips []string
	iterateIPs(netIP, subnet, func(ip net.IP) {
		ips = append(ips, ip.String())
	})

	if len(ips) != 254 {
		t.Fatalf("expected 254 IPs for /24, got %d", len(ips))
	}
	if ips[0] != "192.168.1.1" {
		t.Errorf("first IP = %s, want 192.168.1.1", ips[0])
	}
	if ips[len(ips)-1] != "192.168.1.254" {
		t.Errorf("last IP = %s, want 192.168.1.254", ips[len(ips)-1])
	}
}

func TestIterateIPs_28(t *testing.T) {
	netIP := net.ParseIP("10.0.0.0")
	_, subnet, _ := net.ParseCIDR("10.0.0.0/28")

	count := 0
	var first, last string
	iterateIPs(netIP, subnet, func(ip net.IP) {
		if count == 0 {
			first = ip.String()
		}
		last = ip.String()
		count++
	})

	if count != 14 {
		t.Fatalf("expected 14 IPs for /28, got %d", count)
	}
	if first != "10.0.0.1" {
		t.Errorf("first IP = %s, want 10.0.0.1", first)
	}
	if last != "10.0.0.14" {
		t.Errorf("last IP = %s, want 10.0.0.14", last)
	}
}

func TestIterateIPs_30(t *testing.T) {
	netIP := net.ParseIP("10.0.0.0")
	_, subnet, _ := net.ParseCIDR("10.0.0.0/30")

	var ips []string
	iterateIPs(netIP, subnet, func(ip net.IP) {
		ips = append(ips, ip.String())
	})

	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs for /30, got %d", len(ips))
	}
	if ips[0] != "10.0.0.1" {
		t.Errorf("first IP = %s, want 10.0.0.1", ips[0])
	}
	if ips[1] != "10.0.0.2" {
		t.Errorf("second IP = %s, want 10.0.0.2", ips[1])
	}
}

func TestIterateIPs_16(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("172.16.0.0/16")

	count := 0
	iterateIPs(net.ParseIP("172.16.0.0"), subnet, func(ip net.IP) {
		count++
	})

	if count != 65534 {
		t.Errorf("expected 65534 IPs for /16, got %d", count)
	}
}
