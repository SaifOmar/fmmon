package ipspoof

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func SendPacket(ifaceName string, srcIP, dstIP net.IP, dstPort layers.TCPPort, payload []byte) error {
	handle, err := pcap.OpenLive(ifaceName, 65536, false, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open: %w", err)
	}
	defer handle.Close()

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface lookup: %w", err)
	}

	srcPort := layers.TCPPort(12345)

	eth := &layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		SYN:     true,
		Window:  65535,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		return fmt.Errorf("serialize: %w", err)
	}

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return fmt.Errorf("write packet: %w", err)
	}

	return nil
}
