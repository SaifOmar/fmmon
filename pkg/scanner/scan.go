package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/saif/spoofer/pkg/network"
)

type DiscoveredDevice struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Hostname string
}

func ARPScan(ifaceName string, timeout time.Duration) ([]DiscoveredDevice, error) {
	pcapName, err := network.ResolvePcapDeviceName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("resolve pcap device: %w", err)
	}

	handle, err := pcap.OpenLive(pcapName, 65536, false, 100*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		return nil, fmt.Errorf("set bpf filter: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}

	localIP, subnet, err := getLocalIPv4(iface)
	if err != nil {
		return nil, err
	}

	discovered := make(map[string]DiscoveredDevice)
	var mu sync.Mutex
	lastReply := time.Now()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	stopCollector := make(chan struct{})
	var listenerWg sync.WaitGroup
	listenerWg.Add(1)

	go func() {
		defer listenerWg.Done()
		for {
			select {
			case packet, ok := <-packetSource.Packets():
				if !ok {
					return
				}
				arpLayer := packet.Layer(layers.LayerTypeARP)
				if arpLayer == nil {
					continue
				}
				arpResp := arpLayer.(*layers.ARP)
				if arpResp.Operation != layers.ARPReply {
					continue
				}
				ip := net.IP(arpResp.SourceProtAddress)
				mac := net.HardwareAddr(arpResp.SourceHwAddress)
				key := ip.String()
				mu.Lock()
				if _, exists := discovered[key]; !exists {
					discovered[key] = DiscoveredDevice{IP: ip, MAC: mac}
					lastReply = time.Now()
				}
				mu.Unlock()
			case <-stopCollector:
				return
			}
		}
	}()

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	iterateIPs(localIP, subnet, func(targetIP net.IP) {
		if targetIP.Equal(localIP) {
			return
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			sendARPRequest(handle, iface, localIP, ip)
		}(targetIP)
	})

	wg.Wait()

	mu.Lock()
	lastReply = time.Now()
	mu.Unlock()

	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

pollLoop:
	for {
		select {
		case <-ticker.C:
			mu.Lock()
			silence := time.Since(lastReply)
			mu.Unlock()
			if silence > time.Second {
				break pollLoop
			}
		case <-deadline:
			break pollLoop
		}
	}

	close(stopCollector)
	listenerWg.Wait()

	mu.Lock()
	result := make([]DiscoveredDevice, 0, len(discovered))
	for _, d := range discovered {
		result = append(result, d)
	}
	mu.Unlock()

	if result == nil {
		result = []DiscoveredDevice{}
	}
	return result, nil
}

func getLocalIPv4(iface *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("get addrs: %w", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.To4() == nil {
			continue
		}
		return ipnet.IP, ipnet, nil
	}
	return nil, nil, fmt.Errorf("no IPv4 address on interface")
}

func iterateIPs(netIP net.IP, subnet *net.IPNet, fn func(net.IP)) {
	mask := subnet.Mask
	ip := netIP.Mask(mask)
	ones, bits := mask.Size()
	numIPs := 1 << (bits - ones)

	for i := 1; i < numIPs-1; i++ {
		target := make(net.IP, 4)
		copy(target, ip.To4())

		rem := i
		for j := 3; j >= 0 && rem > 0; j-- {
			target[j] += byte(rem)
			rem >>= 8
		}

		fn(target)
	}
}

func sendARPRequest(handle *pcap.Handle, iface *net.Interface, localIP, targetIP net.IP) {
	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   iface.HardwareAddr,
		SourceProtAddress: localIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buf, opts, eth, arp)
	if err != nil {
		return
	}

	handle.WritePacketData(buf.Bytes())
}
