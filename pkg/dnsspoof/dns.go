package dnsspoof

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Spoofer struct {
	iface *net.Interface
}

func New(ifaceName string) (*Spoofer, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}
	return &Spoofer{iface: iface}, nil
}

func (s *Spoofer) BuildSpoofedResponse(request []byte, fakeIP net.IP) ([]byte, error) {
	packet := gopacket.NewPacket(request, layers.LayerTypeEthernet, gopacket.Default)
	if packet == nil {
		return nil, fmt.Errorf("failed to parse packet")
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, fmt.Errorf("no DNS layer found")
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil, fmt.Errorf("not a DNS packet")
	}

	if len(dns.Questions) == 0 {
		return nil, fmt.Errorf("no DNS questions")
	}

	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	udpLayer := packet.Layer(layers.LayerTypeUDP)

	if ethLayer == nil || ipLayer == nil || udpLayer == nil {
		return nil, fmt.Errorf("missing ethernet/IP/UDP layers")
	}

	eth := *ethLayer.(*layers.Ethernet)
	ip := *ipLayer.(*layers.IPv4)
	udp := *udpLayer.(*layers.UDP)

	eth.SrcMAC, eth.DstMAC = eth.DstMAC, eth.SrcMAC

	ip.SrcIP, ip.DstIP = ip.DstIP, ip.SrcIP

	udp.SrcPort, udp.DstPort = udp.DstPort, udp.SrcPort

	answer := layers.DNSResourceRecord{
		Name:  dns.Questions[0].Name,
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
		TTL:   60,
		IP:    fakeIP,
	}

	resp := &layers.DNS{
		ID:        dns.ID,
		QR:        true,
		OpCode:    layers.DNSOpCodeQuery,
		AA:        true,
		TC:        false,
		RD:        dns.RD,
		RA:        true,
		Z:         0,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: dns.Questions,
		Answers:   []layers.DNSResourceRecord{answer},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, resp)
	if err != nil {
		return nil, fmt.Errorf("serialize: %w", err)
	}

	return buf.Bytes(), nil
}
