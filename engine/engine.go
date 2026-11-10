package engine

import (
	"bufio"
	"context"
	"fmt"
	"log"
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
)

//// TODO:
// [] on start start at zero values and don't restore devcie or session data
// [] add a load_from_prev to load prev session data into current session
// [] store prev session data alone so you don't keep storing so many data
// [] send total (curr + prev to the ui) if prev is loaded
// [] make save function that saves current session (without the prev session data ) to db
// [] make clear funciton that will prune the current session data (make sure it's guarded)
// [] change loading of the prev session data to only be at the start of the app // so you don't get the device data from db from device chanel after clearing it
// [] getDeviceName look first for the name in the db
// [x] add file loggin // NOTE: now all calls to log."printFunc"() go to that file, if you need to print just use fmt

//go:embed data/ieee-oui.txt
var ouiData string
var (
	ouiOnce sync.Once
	ouiMap  = make(map[string]string)
)

var gateWay atomic.Pointer[gateway]

var startTime time.Time

type StoreTypes string

const (
	DBSTORE   StoreTypes = "db"
	FILESTORE StoreTypes = "file"
)

var hostIfacesIp []net.IP

type Engine struct {
	Devices    Devices
	Host       Device
	Stores     map[StoreTypes]Store
	cancelFunc context.CancelFunc
	done       chan struct{}
	loaded     DeviceMap
	prevLoaded bool
	day        string
	dayMu      sync.Mutex
}

func (e *Engine) Shutdown() {
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	if e.done != nil {
		select {
		case <-e.done:
		case <-time.After(2 * time.Second):
		}
	}

	shutdown(e)

	if e.Devices.mu == nil {
		return
	}

	e.Devices.mu.RLock()
	devices := DevicesSnapshot(e.Devices.Devices) // safe copy, fixes the map race
	for _, d := range devices {
		fmt.Println(d.IP.String(), d.Blocked)
	}
	e.Devices.mu.RUnlock()

	restore := func(handle *pcap.Handle, gw *gateway, d *Device) {
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
	// one write handle instead of one per device
	if gw := gateWay.Load(); gw != nil && e.Host.Interface != "" {
		if handle, err := pcap.OpenLive(e.Host.Interface, 1600, true, 1000*time.Millisecond); err == nil {
			for i := range devices {
				if d := &devices[i]; !e.Host.IP.Equal(d.IP) && len(d.IP) > 0 && len(d.MAC) > 0 {
					restore(handle, gw, d)
				}
			}
			handle.Close()
		} else {
			log.Println("restore: could not open write handle:", err)
		}
	}

	// persistance
	if err := e.SaveCurrent(); err != nil {
		log.Println("error saving devices to db:", err)
	}
}

// DevicesSnapshot returns a locked, safe copy of the live device map for
// callers outside the engine package (the UI); the free DevicesSnapshot above
// does the copying and must be called while holding the devices lock.
func (e *Engine) DevicesSnapshot() []Device {
	if e.Devices.mu == nil {
		return nil
	}
	e.Devices.mu.RLock()
	defer e.Devices.mu.RUnlock()
	return DevicesSnapshot(e.Devices.Devices)
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
	err := cleanDeviceForwardBlock(d)
	if err != nil {
		return err
	}
	err = setDeviceForwardBlock(d, true)
	e.Devices.mu.Unlock()
	return err
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

// RateLimitDevice applies or clears one direction's cap, in kbit, for the
// device at ip. The tc layer is the syscall side; the value is also recorded
// on the Device so persist() saves it and the next run's deviceCh hook
// re-applies it. The device lookup is ip based because that is what the UI
// holds; ds.Devices is keyed by mac under the hood.
func (e *Engine) RateLimitDevice(ip string, filter string, bitRateF float64) error {
	switch filter {
	case "up", "down":
	default:
		return fmt.Errorf("unknown rate filter %q", filter)
	}
	if bitRateF == 0.0 {
		if err := removeRateLimit(e.Host.Interface, ip, filter); err != nil {
			return err
		}
		return e.recordDeviceLimit(ip, filter, 0)
	}
	rate := strconv.FormatFloat(bitRateF, 'f', -1, 64) + "kbit"
	if err := addRateLimit(e.Host.Interface, ip, filter, rate); err != nil {
		return err
	}
	return e.recordDeviceLimit(ip, filter, bitRateF)
}

// recordDeviceLimit stores the cap the tc layer just applied, so persist()
// saves it and the next run re-applies it when the device resurfaces. Zero
// clears. The lock mirrors how every other Devices map writer handles it.
func (e *Engine) recordDeviceLimit(ip, filter string, rate float64) error {
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()
	for _, d := range e.Devices.Devices {
		if d.IP.String() == ip {
			if filter == "up" {
				d.UpRateLimit = rate
			} else {
				d.DownRateLimit = rate
			}
			return nil
		}
	}
	return fmt.Errorf("no device with ip %s to record rate limit", ip)
}

func (e *Engine) CleanDeviceBlock(d *Device) error {
	d.Blocked = false
	return cleanDeviceForwardBlock(d)
}

func (e *Engine) UnblockDevice(d *Device) error {
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()
	return setDeviceForwardBlock(d, false)
}

func (e *Engine) Clear() error {
	// save current first to db then prune everything
	e.SaveCurrent()
	loaded := e.loadFromStore()
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()

	gwIP, gwMac, _ := Gateway()
	var gwDevice Device
	for _, d := range e.Devices.Devices {
		if d.IP.Equal(gwIP) {
			gwDevice = *d
		}
	}

	ds := make(DeviceMap)
	e.Devices.Devices = ds
	*e.Devices.TotalRecieved = 0
	*e.Devices.TotalSent = 0

	e.Host.BytesSent, e.Host.BytesReceived = 0, 0
	e.Host.prevBytesSent, e.Host.prevBytesRecv = 0, 0
	gwDevice.BytesSent, gwDevice.BytesReceived = 0, 0
	gwDevice.prevBytesSent, gwDevice.prevBytesRecv = 0, 0

	e.loaded = loaded
	e.prevLoaded = false

	e.Devices.Devices[createDeviceHash("", net.HardwareAddr(e.Host.MAC).String())] = &e.Host
	e.Devices.Devices[createDeviceHash("", gwMac.String())] = &gwDevice

	return nil
}

func (e *Engine) SaveCurrent() error {
	e.dayMu.Lock()
	defer e.dayMu.Unlock()

	e.Devices.mu.RLock()
	list := DevicesSnapshot(e.Devices.Devices)
	up, down := *e.Devices.TotalSent, *e.Devices.TotalRecieved
	e.Devices.mu.RUnlock()

	st := e.Stores[DBSTORE]
	if st == nil {
		return nil
	}
	if err := st.writeAll(list); err != nil {
		return err
	}
	st.writeSession(up, down, startTime)

	gw, _, _ := Gateway()
	today := time.Now().Format("2006-01-02")
	if today != e.day {
		if err := st.saveDay(list, up, down, e.day, e.Host.IP.String(), gw.String()); err != nil {
			return err
		}
		e.day = today
	}
	return st.saveDay(list, up, down, e.day, e.Host.IP.String(), gw.String())
}

func (e *Engine) Days() []string {
	if st := e.Stores[DBSTORE]; st != nil {
		return st.days()
	}
	return nil
}

func (e *Engine) Day(day string) (DaySnapshot, bool) {
	if st := e.Stores[DBSTORE]; st != nil {
		return st.day(day)
	}
	return DaySnapshot{}, false
}

func (e *Engine) loadFromStore() DeviceMap {
	e.Devices.mu.Lock()
	defer e.Devices.mu.Unlock()

	st := e.Stores[DBSTORE]
	stored := st.loadAll()

	res := make(DeviceMap)
	for _, d := range stored {
		// always set to false until we get it from the devChan
		d.Reachable = false
		res[createDeviceHash("", net.HardwareAddr(d.MAC).String())] = d
	}
	return res
}

func (e *Engine) LoadPrevSession() {
	e.Devices.mu.RLock()
	if e.prevLoaded || len(e.loaded) == 0 {
		e.Devices.mu.RUnlock()
		return
	}
	list := DevicesSnapshot(e.Devices.Devices)
	prev := e.loaded
	e.Devices.mu.RUnlock()

	merged := make(DeviceMap, len(prev))
	for key, p := range prev {
		d := *p
		merged[key] = &d
	}

	for _, src := range list {
		key := createDeviceHash("", net.HardwareAddr(src.MAC).String())
		dst, ok := merged[key]
		if ok {
			e.syncDevices(&src, dst)
		}
	}

	e.Devices.mu.Lock()
	e.Devices.Devices = merged
	e.prevLoaded = true
	e.Devices.mu.Unlock()
}

// NOTE: don't have a good name for it
// it just combines usage and handles controls
func (e *Engine) syncDevices(src, dst *Device) *Device {
	// @accumulate usage and get saved name
	src.BytesSent = dst.BytesSent + src.BytesSent
	src.BytesReceived = dst.BytesReceived + src.BytesReceived
	src.Name = dst.Name
	//

	// @restore controls
	if !src.Blocked && dst.Blocked {
		src.Blocked = true
	}

	if src.UpRateLimit == 0 {
		src.UpRateLimit = dst.UpRateLimit
	}

	if src.DownRateLimit == 0 {
		src.DownRateLimit = dst.DownRateLimit
	}
	// in this block when removeing a rate limit
	if src.Blocked {
		e.CleanDeviceBlock(dst)
		e.CleanDeviceBlock(src)

		e.BlockDevice(src)
	}

	if src.UpRateLimit > 0 {
		e.RateLimitDevice(dst.IP.String(), "up", 0)
		e.RateLimitDevice(src.IP.String(), "up", 0)

		e.RateLimitDevice(src.IP.String(), "up", dst.UpRateLimit)
	}
	if src.DownRateLimit > 0 {
		e.RateLimitDevice(dst.IP.String(), "down", 0)
		e.RateLimitDevice(src.IP.String(), "down", 0)

		e.RateLimitDevice(src.IP.String(), "down", dst.DownRateLimit)
	}

	*dst = *src
	return dst
}

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
	key := createDeviceHash("", mac.String())

	if _, ok := e.Devices.Devices[key]; !ok {
		log.Printf("Failed to find device with key: (%s) to change it's name", key)
		return
	}
	e.Devices.Devices[key].Name = capitalize(newName)
	e.Devices.mu.Unlock()

	st := e.Stores[DBSTORE]
	if st != nil {
		st.write(e.Devices.Devices[key])
	}
}

func (e *Engine) Setup() {
	getHost := func() Device {
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
	e.Host = getHost()
	e.Devices = Devices{
		Devices:       make(DeviceMap),
		TotalSent:     new(int64),
		TotalRecieved: new(int64),
		mu:            &sync.RWMutex{},
	}
	e.Devices.Devices[createDeviceHash("", net.HardwareAddr(e.Host.MAC).String())] = &e.Host

	if e.Host.Reachable == false {
		panic("No active interface found")
	}

	loadVendors := func() error {
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
	if err := loadVendors(); err != nil {
		log.Println("Error loading vendors:", err)
	}

	ifaces := []string{e.Host.Interface, e.Host.IfaceFriendly}
	if err := setup_platform(ifaces, e.Host); err != nil {
		panic("couldn't setup the platform layer, err :" + err.Error())
	}

	dataDir, err := os.UserCacheDir()
	if err != nil {
		log.Printf("Error finding user cache dir %s", err.Error())
	}
	appCacheDir := filepath.Join(dataDir, "fmmon")
	if err := os.MkdirAll(appCacheDir, 0755); err != nil {
		log.Printf("Error creating app cache directory: %s", err.Error())
	}
	logPath := filepath.Join(appCacheDir, "fmmon.log")
	f, _ := os.Open(logPath)
	log.SetOutput(f)
	sqliteDbPath := filepath.Join(appCacheDir, "fmmon.db")

	dbs := &DatabaseStore{}
	e.Stores = make(map[StoreTypes]Store)
	if err := dbs.init(sqliteDbPath); err != nil {
		log.Printf("Error opening database store: %s", err.Error())
	} else {
		e.Stores[DBSTORE] = dbs
	}

	startTime = time.Now()
	e.day = startTime.Format("2006-01-02")

	loaded := e.loadFromStore()
	e.Devices.mu.Lock()
	e.loaded = loaded
	e.Devices.mu.Unlock()

	// TODO: remove
	for k, v := range loaded {
		fmt.Println(k, v.Blocked)
	}
}

// 1. setup rcv loop //listens for replys from the send loop but we set it up first so we don't miss any replys // device chanel
// 2. setup send loop // send arp requests to all available ips on the network
// 3. setup poison loop // send forged replys to spoof
// 4. setup measure loop // measure rate up and down
func (e *Engine) Start() {
	handle, err := pcap.OpenLive(e.Host.Interface, 1600, true, 1000*time.Millisecond)
	if err != nil {
		panic("Error opening device: " + err.Error())
	}
	defer handle.Close()

	errChan := make(chan error)
	deviceCh := make(chan *Device)
	nameChan := make(chan nameCh)
	e.done = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.cancelFunc = cancel

	// start goroutines
	go arpRecieve(deviceCh, e.Host, handle, ctx, errChan)
	go arpSendRequests(e.Host, handle, ctx, errChan)
	go arpSendForgedReplys(&e.Devices, e.Host, handle, ctx, errChan)
	//
	go relay(&e.Devices, e.Host, ctx, errChan)
	go persist(&e.Devices, e.Stores, e.Host, ctx, errChan)
	//
	timer := time.Minute * 2
	ticker := time.NewTicker(timer)
	dayTicker := time.NewTicker(10 * time.Minute)
	defer dayTicker.Stop()
	// interception
	for {
		select {
		case <-ctx.Done():
			close(e.done)
			return
		case err := <-errChan:
			log.Println("Error: ", err)
		case <-ticker.C: // timer (2 mints)
			e.Devices.mu.Lock()
			for _, d := range e.Devices.Devices {
				if d.lastSeen.Add(timer).Before(time.Now()) {
					if !d.Blocked {
						d.Reachable = false
					}
				}
			}
			e.Devices.mu.Unlock()
		case <-dayTicker.C:
			e.dayMu.Lock()
			changed := time.Now().Format("2006-01-02") != e.day
			e.dayMu.Unlock()
			if changed {
				if err := e.SaveCurrent(); err != nil {
					log.Println("day rollover:", err)
				}
			}
		case name := <-nameChan:
			e.Devices.mu.Lock()
			hash := createDeviceHash(name.ip, name.mac)
			dv, ok := e.Devices.Devices[hash]
			if ok {
				// TODO: actually do this
				dv.Name = name.name
				dv.Vendor = name.name
			}
			e.Devices.mu.Unlock()
		// TODO: clean this up
		case device := <-deviceCh:
			e.Devices.mu.Lock()
			if net.HardwareAddr(device.MAC).String() == net.HardwareAddr(e.Host.MAC).String() {
				panic(fmt.Sprintf("SELF-POISONED DEVICE:%s %s", device.IP, net.HardwareAddr(e.Host.MAC).String()))
			}

			hash := createDeviceHash(device.IP.String(), net.HardwareAddr(device.MAC).String())
			if existing, ok := e.Devices.Devices[hash]; ok {
				if !existing.IP.Equal(device.IP) {
					existing.IP = device.IP
				}
				existing.lastSeen = time.Now()
				existing.Reachable = true
			} else {
				e.Devices.Devices[hash] = device
				go getDeviceName(nameChan, device.IP.String(), net.HardwareAddr(device.MAC).String(), e.loaded)
			}
			e.Devices.mu.Unlock()
		}
	}
}

func arpRecieve(deviceCh chan *Device, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
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

			if gateWay.Load() == nil {
				if srcIP.Equal(net.ParseIP("192.168.1.1")) {
					gateWay.Store(&gateway{ip: srcIP, mac: srcMAC})
					fmt.Println("found gateway" + fmt.Sprintf("%s %s", srcIP.String(), srcMAC.String()))
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

func arpSendRequests(host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
	maxSubnet := func(host Device) []byte {
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
	ip := host.IP.Mask(host.Mask.Mask).To4()
	maxSub := maxSubnet(host)

	incrementIP := func(ip net.IP) {
		for i := len(ip) - 1; i >= 0; i-- {
			ip[i]++
			if ip[i] > 0 {
				break
			}
		}
	}
	sendRequestLoop := func() error {
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

func arpSendForgedReplys(devices *Devices, host Device, handle *pcap.Handle, ctx context.Context, errChan chan error) {
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
			list := DevicesSnapshot(devices.Devices)
			devices.mu.RUnlock()

			isLocalIp := func(ip net.IP) bool {
				for _, hostIfaceIp := range hostIfacesIp {
					if hostIfaceIp.Equal(ip) {
						return true
					}
				}
				return false
			}
			for _, device := range list {
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
		}
	}

}

func persist(devices *Devices, stores map[StoreTypes]Store, host Device, ctx context.Context, errChan chan error) {
	thrshold := time.Second * 80
	ticker := time.NewTicker(thrshold)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			devices.mu.RLock()
			list := DevicesSnapshot(devices.Devices)
			devices.mu.RUnlock()
			for k, s := range stores {
				if s == nil {
					log.Println("Can't write to: %s", k)
					continue
				}
				if err := s.writeAll(list); err != nil {
					errChan <- err
				}
			}
		}
	}
}

// // @Seciton Helpers
//
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
func Gateway() (net.IP, net.HardwareAddr, bool) {
	gw := gateWay.Load()
	if gw == nil {
		return nil, nil, false
	}
	return gw.ip, gw.mac, true
}

func DevicesSnapshot(devices DeviceMap) []Device {
	if devices == nil {
		return nil
	}
	out := make([]Device, 0, len(devices))
	for _, d := range devices {
		out = append(out, *d)
	}
	return out
}

// TODO: remove for production
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

func getDeviceName(nameChan chan nameCh, ip string, mac string, loaded DeviceMap) {
	getVendor := func(mac string) string {
		prefix := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))[:6]
		val, ok := ouiMap[prefix]

		if ok {
			return val
		}
		return "Unknown"
	}
	var name string
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		name = strings.TrimSuffix(names[0], ".")
	}
	name = getVendor(mac)
	if name == "" {
		name = "Unknown"

	}
	v, ok := loaded[createDeviceHash("", mac)]
	if ok {
		name = v.Name
	}
	nameChan <- nameCh{name: name, ip: ip, mac: mac}
}
