package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"crypto/sha256"
	_ "embed"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/miekg/dns"
)

type StoreTypes string

const (
	DBSTORE   StoreTypes = "db"
	FILESTORE StoreTypes = "file"
)

type Engine struct {
	Devices    DeviceMap
	Host       Device
	Stores     map[StoreTypes]Store
	cancelFunc context.CancelFunc
}

//go:embed data/ieee-oui.txt
var ouiData string

var (
	ouiOnce sync.Once
	ouiMap  = make(map[string]string)
)

var gateWay atomic.Pointer[gateway]
var store atomic.Pointer[[]FileStore] // TODO: remove

func (e *Engine) ChangeDeviceName(mac net.HardwareAddr, newName string) {
	capitalize := func(s string) string {
		r := []rune(strings.TrimSpace(s))
		if len(r) == 0 {
			return ""
		}
		r[0] = unicode.ToUpper(r[0])
		return string(r)
	}

	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()
	key := createDeviceHash("", mac.String())

	if _, ok := e.Devices.Devices[key]; !ok {
		log.Printf("Failed to find device with key: (%s) to change it's name", key)
		return
	}

	e.Devices.Devices[key].Name = capitalize(newName)
	st := e.Stores[DBSTORE]
	if st != nil {
		st.write(e.Devices.Devices[key])
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
	sent, recieved := int64(0), int64(0)
	ds := DeviceMap{
		Devices:       make(map[string]*Device),
		TotalSent:     &sent,
		TotalRecieved: &recieved,
		mu:            &sync.RWMutex{},
	}
	ds.Devices[createDeviceHash(host.IP.String(), net.HardwareAddr(host.MAC).String())] = &host
	e.Devices = ds
	handle, err := pcap.OpenLive(host.Interface, 1600, true, 1000*time.Millisecond)
	if err != nil {
		panic("Error opening device: " + err.Error())
	}
	defer handle.Close()

	if host.Reachable == false {
		panic("No active interface found")
	}

	if err = loadVendors(); err != nil {
		log.Println("Error loading vendors:", err)
	}

	ifaces := []string{host.Interface, host.IfaceFriendly}
	log.Println("Available devices")
	// blockForwardingForDev(ifaces)
	if err = setup_platform(ifaces, host); err != nil {
		panic("couldn't setup the platform layer, err :" + err.Error())
	}

	errChan := make(chan error)
	deviceCh := make(chan *Device)
	nameChan := make(chan nameCh)

	ctx, cancel := context.WithCancel(context.Background())
	e.cancelFunc = cancel
	defer cancel()

	dataDir, err := os.UserCacheDir()
	if err != nil {
		log.Printf("Error finding user cache dir %s", err.Error())
	}

	appCacheDir := filepath.Join(dataDir, "fmmon")

	if err := os.MkdirAll(appCacheDir, 0755); err != nil {
		log.Printf("Error creating app cache directory: %s", err.Error())
	}

	sqliteDbPath := filepath.Join(appCacheDir, "fmmon.db")
	dataFileStore := filepath.Join(appCacheDir, "fmmon.txt")

	// not good decide if you will have both of them or only one
	// if we only have one we should not have a map only a store interface
	dbs := &DatabaseStore{}
	e.Stores = make(map[StoreTypes]Store)
	if err := dbs.init(sqliteDbPath); err != nil {
		log.Printf("Error opening database store: %s", err.Error())
		filestore := &FileStore{}
		if err = filestore.init("somePath"); err != nil {
			log.Printf("Error opening file store: %s", err.Error())
		} else {
			e.Stores[DBSTORE] = filestore
		}
	} else {
		e.Stores[DBSTORE] = dbs
	}

	rn1 := rand.IntN(999)
	rn2 := rand.IntN(999)
	hashSeed := fmt.Sprintf("%d%d", rn1, rn2)
	runHash := createDeviceHash("", hashSeed)

	stored := make([]*Device, 0)
	for _, st := range e.Stores {
		if st == nil {
			continue
		}
		stored = append(stored, st.loadAll()...)
	}

	// for _, d := range stored {
	// 	if d.Blocked {
	// 		if err := cleanDeviceForwardBlock(d); err != nil {
	// 			log.Printf("err cleaning device block state %s", err.Error())
	// 		}
	// 		if err := setDeviceForwardBlock(d, true); err != nil {
	// 			log.Printf("err blocking device", err.Error())
	// 		}
	// 	}
	//
	// 	if d.UpRateLimit > 0 {
	// 		rate := strconv.FormatFloat(d.UpRateLimit, 'f', -1, 64) + "kbit"
	// 		addRateLimit(e.Host.Interface, d.IP.String(), "up", rate)
	// 	}
	// 	if d.DownRateLimit > 0 {
	// 		rate := strconv.FormatFloat(d.DownRateLimit, 'f', -1, 64) + "kbit"
	// 		addRateLimit(e.Host.Interface, d.IP.String(), "down", rate)
	// 	}
	//
	// 	ds.Devices[createDeviceHash("", net.HardwareAddr(d.MAC).String())] = d
	//
	// }

	for _, d := range stored {
		// always set to false until we get it from the devChan
		d.Reachable = false
		ds.Devices[createDeviceHash("", net.HardwareAddr(d.MAC).String())] = d
	}

	go arpRCV(deviceCh, host, handle, ctx, errChan)
	go arpSendRequests(host, handle, ctx, errChan)
	go arpSendForgedReplys(ds, host, handle, ctx, errChan)
	go Relay(ds, host, ctx, errChan)
	go persist(ds, e.Stores, dataFileStore, runHash, host, ctx, errChan)

	timer := time.Minute * 2
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
						d.Reachable = false
						// delete(ds.Devices, createDeviceHash(d.IP.String(), net.HardwareAddr(d.MAC).String()))
					}
				}
			}
			ds.mu.Unlock()
		case name := <-nameChan:
			ds.mu.Lock()
			hash := createDeviceHash(name.ip, name.mac)
			dv, ok := ds.Devices[hash]
			if ok {
				// TODO: actuall do this
				dv.Name = name.name
				dv.Vendor = name.name
			}

			// WARN :keep this for the day but refactor it after that
			st := store.Load()
			if st != nil {
				for _, t := range *st {
					if hash == t.key {
						ds.Devices[hash].BytesReceived = t.totalDown
						ds.Devices[hash].BytesSent = t.totalUp
					}
				}
			}
			ds.mu.Unlock()
		// TODO: clean this up
		case device := <-deviceCh:
			ds.mu.Lock()
			ip := device.IP.String()
			if net.HardwareAddr(device.MAC).String() == net.HardwareAddr(host.MAC).String() {
				panic(fmt.Sprintf("SELF-POISONED DEVICE:%s %s", device.IP, net.HardwareAddr(host.MAC).String()))
			}
			mac := net.HardwareAddr(device.MAC).String()
			hash := createDeviceHash(ip, mac)

			if existing, ok := ds.Devices[hash]; ok {
				if len(existing.IP) == 0 || !existing.IP.Equal(device.IP) {
					ds.Devices[hash].IP = device.IP
					existing.IP = device.IP
				}

				if existing.Blocked {
					if err := cleanDeviceForwardBlock(existing); err != nil {
						log.Printf("err cleaning device block state %s", err.Error())
					}
					if err := setDeviceForwardBlock(existing, true); err != nil {
						log.Printf("err blocking device", err.Error())
					}
				}

				if existing.UpRateLimit > 0 {
					rate := strconv.FormatFloat(existing.UpRateLimit, 'f', -1, 64) + "kbit"
					addRateLimit(e.Host.Interface, existing.IP.String(), "up", rate)
				}
				if existing.DownRateLimit > 0 {
					rate := strconv.FormatFloat(existing.DownRateLimit, 'f', -1, 64) + "kbit"
					addRateLimit(e.Host.Interface, existing.IP.String(), "down", rate)
				}

				existing.lastSeen = time.Now()
				existing.Reachable = true
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

func persist(devices DeviceMap, stores map[StoreTypes]Store, path, runHash string, host Device, ctx context.Context, errChan chan error) {
	writeTotals := func(totalSent, totalRecv string) error {
		fileData, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		var lines [][]byte
		if len(fileData) > 0 {
			lines = bytes.Split(bytes.TrimSuffix(fileData, []byte("\n")), []byte("\n"))
		}
		if len(lines) > 1 {
			lines[1] = []byte(fmt.Sprintf("TotalUp: %s, TotalDown: %s", totalSent, totalRecv))
		}

		out := append(bytes.Join(lines, []byte("\n")), '\n') // NOTE: posix expects a file terminated with \n
		return os.WriteFile(path, out, 0644)
	}

	writeLine := func(out []byte, lines [][]byte, key, data string) ([]byte, error) {
		prefix := []byte("Key: " + key + ",")

		found := false
		for i := range lines {
			if i < 2 {
				continue
			}
			if bytes.HasPrefix(lines[i], prefix) {
				lines[i] = []byte(data)
				found = true
				break
			}
		}
		if !found {
			lines = append(lines, []byte(data))
		}

		out = append(bytes.Join(lines, []byte("\n")), '\n')
		return out, nil
	}

	writeHashLine := func(hashLine []byte) error {
		return os.WriteFile(path, hashLine, 0644)
	}
	// TODO: read total up and down for all
	fileData, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		errChan <- err
	}

	var lines [][]byte
	if len(fileData) > 0 {
		lines = bytes.Split(bytes.TrimSuffix(fileData, []byte("\n")), []byte("\n")) // NOTE: again respecting posix with TrimSuffix
	}

	if len(lines) > 2 {
		prevHashParts := bytes.Split(lines[0], []byte("="))
		var prevHash []byte
		if len(prevHashParts) > 1 {
			prevHash = prevHashParts[1]
			if len(prevHash) != 0 {
				if runHash != string(prevHash) {
					st := store.Load()
					if st != nil {
						panic("how did you manage to even do this ?")
					}
					tempStore := []FileStore{}
					for i := range lines {
						// skip the first two lines
						if i < 2 {
							continue
						}
						parts := bytes.Split(lines[i], []byte(","))

						var key []byte
						n := len(parts)
						if n > 0 {
							key = bytes.Split(parts[0], []byte(" "))[1]
						}

						var totalDown int64 = 0
						var totalUp int64 = 0
						sublices := bytes.SplitN(bytes.TrimSpace(parts[n-1]), []byte(": "), 2)
						if len(sublices) == 2 {
							totalDown, err = expandTotals(sublices[1])
							if err != nil {
								panic(err)
							}
						}
						sublices = bytes.SplitN(bytes.TrimSpace(parts[n-2]), []byte(": "), 2)
						if len(sublices) == 2 {
							totalUp, err = expandTotals(sublices[1])
							if err != nil {
								panic(err)
							}
						}

						if len(key) > 0 {
							d := FileStore{
								key:       string(key),
								totalDown: totalDown,
								totalUp:   totalUp,
							}
							tempStore = append(tempStore, d)
						}
					}
					devices.mu.Lock()
					for k := range devices.Devices {
						for _, td := range tempStore {
							if td.key == k {
								devices.Devices[k].BytesReceived = td.totalDown
								devices.Devices[k].BytesSent = td.totalUp
							}
						}
					}
					devices.mu.Unlock()

					store.Store(&tempStore)
				}
			} else {
				out := []byte(fmt.Sprintf("hash=%s", runHash))
				err := writeHashLine([]byte(out))
				if err != nil {
					errChan <- err
				}
			}
		}
	} else {
		out := []byte(fmt.Sprintf("hash=%s", runHash))
		err := writeHashLine([]byte(out))
		if err != nil {
			errChan <- err
		}
	}

	thrshold := time.Second * 80
	ticker := time.NewTicker(thrshold)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var out []byte
			fileData, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				errChan <- err
			}

			var lines [][]byte
			if len(fileData) > 0 {
				lines = bytes.Split(bytes.TrimSuffix(fileData, []byte("\n")), []byte("\n"))
			}

			devices.mu.RLock()
			for k, d := range devices.Devices {
				devUsageUp, devUsageDown := fmtTotals(d.BytesSent, d.BytesReceived)
				fmtedString := fmt.Sprintf("Key: %s, Name: %s, Mac: %s, Ip: %s, totalUp: %s, totalDown: %s", k, d.Name, net.HardwareAddr(d.MAC).String(), d.IP.String(), devUsageUp, devUsageDown)
				for k, s := range stores {
					if s == nil {
						log.Println("Can't write to: %s", k)
						continue
					}
					if err := s.write(d); err != nil {
						errChan <- err
					}
				}

				out, err = writeLine(out, lines, k, fmtedString)
				if err != nil {
					errChan <- err
				}
			}
			err = os.WriteFile(path, out, 0644)
			if err != nil {
				errChan <- err
			}
			devUsageUp, devUsageDown := fmtTotals(*devices.TotalSent, *devices.TotalRecieved)
			err = writeTotals(devUsageUp, devUsageDown)
			if err != nil {
				errChan <- err
			}
			devices.mu.RUnlock()
		}
	}
}

func arpSendRequests(host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	ip := host.IP.Mask(host.Mask.Mask).To4()
	maxSub := maxSubnet(host)
	sendRequestLoop := func() error {
		for {
			if ip.Equal(net.IP(maxSub)) {
				break
			}

			if ip.Equal(host.IP) {
				incrementIP(ip)
				continue
			}

			// NOTE: check
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
			if err != nil {
				return err
			}

			incrementIP(ip)
		}
		return nil
	}
	log.Printf("Max Subnet: %s\n", net.IP(maxSub).String())
	log.Printf("IP: %s\n", ip.String())
	log.Println("interfa", host.Interface)
	sendRequestLoop()
	tk := time.NewTicker(time.Second * 80)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			ip = host.IP.Mask(host.Mask.Mask).To4()
			err := sendRequestLoop()
			if err != nil {
				errChan <- err
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

			if srcIP.Equal(net.ParseIP("192.168.1.1")) {
				// normal path
				if gateWay.Load() == nil {
					gateWay.Store(&gateway{ip: srcIP, mac: srcMAC})
					fmt.Println("found gateway" + fmt.Sprintf("%s %s", srcIP.String(), srcMAC.String()))
					// gateway change path
				} else {
					currGw := gateWay.Load()
					if !bytes.Equal(currGw.mac, srcMAC) {
						currGw.mac = srcMAC
						gateWay.Store(currGw)
					}
				}
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
	val, ok := ouiMap[prefix]

	if ok {
		return val
	}
	return "Unknown"
}

func loadVendors() error {
	var err error
	count := 0
	ouiOnce.Do(func() {
		scanner := bufio.NewScanner(strings.NewReader(ouiData))
		for scanner.Scan() {
			count++
			if scanner.Err() != nil {
				err = scanner.Err()
				return
			}
			line := scanner.Text()
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ouiMap[strings.ToUpper(parts[0])] = strings.Join(parts[1:], " ")
			}
		}
	})
	return err
}

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

// NOTE: we take both the ip and the mac adds but we just discard ip
// this is just a shortcut so we don't have to change the function call everywhere
func createDeviceHash(_ string, mac string) string {
	hash := sha256.New()
	_, err := hash.Write([]byte(mac))
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

func expandTotals(total []byte) (int64, error) {
	fields := bytes.Fields(total)
	if len(fields) < 2 {
		return 0, nil // device under 1 kB writes an empty total
	}
	value, err := strconv.ParseFloat(string(fields[0]), 64)
	if err != nil {
		return 0, err
	}
	units := map[string]int64{"kb": kb, "mb": mb, "gb": gb, "tb": tb}
	return int64(value * float64(units[string(fields[1])])), nil
}

func fmtTotals(sent, recv int64) (string, string) {
	totalUp, totalDown := "0 kb", "0 kb"
	units := [4]int{kb, mb, gb, tb}
	for i, u := range units {
		if sent >= int64(u) {
			f := float64(sent) / float64(u)
			totalUp = fmt.Sprintf("%.2f %s", f, unitStr[i])
		}

		if recv >= int64(u) {
			f := float64(recv) / float64(u)
			totalDown = fmt.Sprintf("%.2f %s", f, unitStr[i])
		}
	}
	return totalUp, totalDown
}

func (d *Device) tick(totalSent, totalRecieved *int64) (*int64, *int64) {
	if totalSent == nil {
		totalSent = new(int64)
	}
	if totalRecieved == nil {
		totalRecieved = new(int64)
	}
	var bytesSentNew int64 = 0
	var bytesReceivedNew int64 = 0
	now := time.Now()

	if d.lastMeasure.IsZero() {
		bytesSentNew = d.BytesSent
		bytesReceivedNew = d.BytesReceived
		d.lastMeasure = now
	} else {
		elapsed := now.Sub(d.lastMeasure).Seconds()
		if elapsed > 0.001 {
			bytesSentNew = d.BytesSent - d.prevBytesSent
			bytesReceivedNew = d.BytesReceived - d.prevBytesRecv
			d.UpRate = float64(bytesSentNew) / elapsed
			d.DownRate = float64(bytesReceivedNew) / elapsed
		}
	}
	*totalSent += bytesSentNew
	*totalRecieved += bytesReceivedNew
	d.prevBytesSent = d.BytesSent
	d.prevBytesRecv = d.BytesReceived
	d.lastMeasure = now
	return totalSent, totalRecieved
}

func (d Device) String() string {
	return fmt.Sprintf("Name: %s, IP: %s, MAC: %s, Interface: %s, Reachable: %t, Mask: %s, UpRate: %.2f, DownRate: %.2f", d.Name,
		d.IP.String(), net.HardwareAddr(d.MAC).String(), d.Interface, d.Reachable, d.Mask.MaskIP.String(), d.UpRate, d.DownRate)
}

func Gateway() (net.IP, net.HardwareAddr, bool) {
	gw := gateWay.Load()
	if gw == nil {
		return nil, nil, false
	}
	return gw.ip, gw.mac, true
}

// TODO: this should log errors to fs
func restore(host, d *Device) {
	handle, err := pcap.OpenLive(host.Interface, 1600, true, 1000*time.Millisecond)
	if err != nil {
		panic("Error opening device: " + err.Error())
	}
	defer handle.Close()
	gw := gateWay.Load()
	if gw == nil {
		return
	}

	log.Printf("sending restore path to Name: %s, IP: %s", d.Name, d.IP.String())
	arpSendOperation(
		net.HardwareAddr(gw.mac),
		net.HardwareAddr(d.MAC),
		net.HardwareAddr(gw.mac),
		net.HardwareAddr(d.MAC),
		gw.ip.To4(),
		d.IP.To4(),
		layers.ARPRequest,
		handle,
	)
}

func (e *Engine) Shutdown() {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	shutdown(e)
	for _, d := range e.Devices.Devices {
		st := e.Stores[DBSTORE]
		err := st.write(d)
		if err != nil {
			log.Printf("error saving device to db %s, %s", d.Name, d.MAC)
		}
		if !e.Host.IP.Equal(d.IP) {
			restore(&e.Host, d)
		}
	}
}

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

func (e *Engine) GetDeviceById(ip string) *Device {
	e.Devices.mu.RLock()
	defer e.Devices.mu.RUnlock()
	for _, d := range e.Devices.Devices {
		if d.IP.Equal(net.ParseIP(ip)) {
			return d
		}
	}
	return nil
}
func (e *Engine) RateLimitDevice(ip string, filter string, bitRateF float64) error {
	// panic(fmt.Sprintf("rate limit not implemented for %s, filter: %s, rate: %f", ip, filter, bitRateF))
	if bitRateF == 0.0 {
		return removeRateLimit(e.Host.Interface, ip, filter)
	}
	rate := strconv.FormatFloat(bitRateF, 'f', -1, 64) + "kbit"
	d := e.GetDeviceById(ip)
	switch filter {
	case "up":
		e.Devices.mu.Lock()
		d.UpRateLimit = bitRateF
		e.Devices.mu.Unlock()
		return addRateLimit(e.Host.Interface, ip, filter, rate)
	case "down":
		e.Devices.mu.Lock()
		d.DownRateLimit = bitRateF
		e.Devices.mu.Unlock()
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
