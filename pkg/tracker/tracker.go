package tracker

import (
	"fmt"
	"log"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/saif/spoofer/pkg/network"
	"github.com/saif/spoofer/pkg/scanner"
)

type Tracker struct {
	handle     *pcap.Handle
	iface      *net.Interface
	localIP    net.IP
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr

	devices   map[string]*network.Device
	devicesMu sync.RWMutex

	totalDown      int64
	totalUp        int64
	startTime      time.Time
	newDeviceCount int

	DiscoveredDevices []scanner.DiscoveredDevice
	DevicesSelected   bool
	onDevicesSelected func([]scanner.DiscoveredDevice)

	stopCh   chan struct{}
	wg       sync.WaitGroup
	Headless bool
}

func New(ifaceName string, localIP, gatewayIP net.IP, gatewayMAC net.HardwareAddr) (*Tracker, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface lookup: %w", err)
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("pcap open: %w", err)
	}

	return &Tracker{
		handle:     handle,
		iface:      iface,
		localIP:    localIP,
		gatewayIP:  gatewayIP,
		gatewayMAC: gatewayMAC,
		devices:    make(map[string]*network.Device),
		startTime:  time.Now(),
		stopCh:     make(chan struct{}),
	}, nil
}

func (t *Tracker) Close() {
	t.handle.Close()
}

func (t *Tracker) AddDevice(ip net.IP, mac net.HardwareAddr, hostname string) {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()

	key := ip.String()
	if _, exists := t.devices[key]; exists {
		return
	}

	t.devices[key] = &network.Device{
		IP:       ip,
		MAC:      mac,
		Hostname: hostname,
	}
}

func (t *Tracker) RemoveDevice(ip net.IP) {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()
	delete(t.devices, ip.String())
}

func (t *Tracker) GetDevices() []*network.Device {
	t.devicesMu.RLock()
	defer t.devicesMu.RUnlock()

	result := make([]*network.Device, 0, len(t.devices))
	for _, d := range t.devices {
		cp := *d
		result = append(result, &cp)
	}

	slices.SortStableFunc(result, func(a, b *network.Device) int {
		ipA := a.IP.To4()
		ipB := b.IP.To4()
		for i := 0; i < 4; i++ {
			if ipA[i] < ipB[i] {
				return -1
			}
			if ipA[i] > ipB[i] {
				return 1
			}
		}
		return 0
	})

	return result
}

func (t *Tracker) GetDevice(ip net.IP) *network.Device {
	t.devicesMu.RLock()
	defer t.devicesMu.RUnlock()
	return t.devices[ip.String()]
}

func (t *Tracker) SetCap(ip net.IP, down, up int64) {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()
	if d, ok := t.devices[ip.String()]; ok {
		d.CapDown = down
		d.CapUp = up
	}
}

func (t *Tracker) SetBlocked(ip net.IP, blocked bool) {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()
	if d, ok := t.devices[ip.String()]; ok {
		d.Blocked = blocked
	}
}

func (t *Tracker) SetRateLimit(ip net.IP, downBps, upBps float64) {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()
	if d, ok := t.devices[ip.String()]; ok {
		d.RateLimitDown = downBps
		d.RateLimitUp = upBps
		d.TokensDown = 0
		d.TokensUp = 0
		d.TokenRefillAtDown = time.Now()
		d.TokenRefillAtUp = time.Now()
	}
}

func (t *Tracker) TotalDown() int64 { return t.totalDown }
func (t *Tracker) TotalUp() int64   { return t.totalUp }
func (t *Tracker) StartTime() time.Time { return t.startTime }
func (t *Tracker) Uptime() time.Duration { return time.Since(t.startTime) }

func (t *Tracker) ComputeRates() {
	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()

	now := time.Now()
	for _, d := range t.devices {
		if d.PrevTime.IsZero() {
			d.RateDown = 0
			d.RateUp = 0
			d.PrevBytesDown = d.Traffic.BytesDown
			d.PrevBytesUp = d.Traffic.BytesUp
			d.PrevTime = now
			continue
		}

		elapsed := now.Sub(d.PrevTime).Seconds()
		if elapsed > 0 {
			d.RateDown = float64(d.Traffic.BytesDown-d.PrevBytesDown) / elapsed
			d.RateUp = float64(d.Traffic.BytesUp-d.PrevBytesUp) / elapsed
		} else {
			d.RateDown = 0
			d.RateUp = 0
		}

		d.PrevBytesDown = d.Traffic.BytesDown
		d.PrevBytesUp = d.Traffic.BytesUp
		d.PrevTime = now
	}
}

func (t *Tracker) Start() error {
	err := t.handle.SetBPFFilter("ip")
	if err != nil {
		return fmt.Errorf("set bpf filter: %w", err)
	}

	packetSource := gopacket.NewPacketSource(t.handle, t.handle.LinkType())

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			select {
			case <-t.stopCh:
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					continue
				}
				t.processPacket(packet)
			}
		}
	}()

	return nil
}

func (t *Tracker) StartPeriodicRescan(ifaceName string, interval time.Duration, onNew func(ip net.IP, mac net.HardwareAddr, hostname string)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				t.rescan(ifaceName, onNew)
			case <-t.stopCh:
				return
			}
		}
	}()
}

func (t *Tracker) rescan(ifaceName string, onNew func(ip net.IP, mac net.HardwareAddr, hostname string)) {
	devices, err := scanner.ARPScan(ifaceName, 5*time.Second)
	if err != nil {
		log.Printf("rescan error: %v", err)
		return
	}

	t.devicesMu.Lock()
	existing := make(map[string]bool, len(t.devices))
	for k := range t.devices {
		existing[k] = true
	}
	t.devicesMu.Unlock()

	for _, d := range devices {
		key := d.IP.String()
		t.devicesMu.RLock()
		_, exists := t.devices[key]
		t.devicesMu.RUnlock()
		if exists {
			continue
		}

		hostname := scanner.ResolveHostname(d.IP)
		t.AddDevice(d.IP, d.MAC, hostname)
		if onNew != nil {
			onNew(d.IP, d.MAC, hostname)
		}
		t.newDeviceCount++
		log.Printf("new device discovered: %s (%s)", d.IP, d.MAC)
	}
}

func (t *Tracker) SetDiscoveredDevices(devices []scanner.DiscoveredDevice) {
	t.devicesMu.Lock()
	t.DiscoveredDevices = devices
	t.devicesMu.Unlock()
}

func (t *Tracker) SetOnDevicesSelected(fn func([]scanner.DiscoveredDevice)) {
	t.onDevicesSelected = fn
}

func (t *Tracker) ConfirmDevices(selected []scanner.DiscoveredDevice) {
	if t.onDevicesSelected != nil {
		t.onDevicesSelected(selected)
	}
	t.devicesMu.Lock()
	t.DevicesSelected = true
	t.devicesMu.Unlock()
}

func (t *Tracker) SetGatewayMAC(mac net.HardwareAddr) {
	t.devicesMu.Lock()
	t.gatewayMAC = mac
	t.devicesMu.Unlock()
}

func (t *Tracker) Stop() {
	close(t.stopCh)
	t.wg.Wait()
}

func (t *Tracker) processPacket(packet gopacket.Packet) {
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}
	eth := ethLayer.(*layers.Ethernet)

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	packetLen := int64(len(packet.Data()))
	srcMAC := eth.SrcMAC
	srcIP := ip.SrcIP
	dstIP := ip.DstIP

	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()

	if t.gatewayMAC == nil {
		return
	}

	isForwarded := srcMAC.String() == t.iface.HardwareAddr.String()
	if isForwarded {
		return
	}

	isFromGateway := srcMAC.String() == t.gatewayMAC.String()

	if isFromGateway {
		dstKey := dstIP.String()
		dev, ok := t.devices[dstKey]
		if !ok {
			return
		}
		if dev.Blocked || (dev.CapDown > 0 && dev.Traffic.BytesDown+packetLen > dev.CapDown) {
			return
		}
		if dev.RateLimitDown > 0 && !allowToken(&dev.TokensDown, &dev.TokenRefillAtDown, dev.RateLimitDown, float64(packetLen)) {
			return
		}
		dev.Traffic.BytesDown += packetLen
		dev.Traffic.PacketsDown++
		dev.Traffic.LastSeen = time.Now()
		t.totalDown += packetLen
		if dstIP.Equal(t.localIP) {
			return
		}
		t.forwardPacket(packet.Data(), dev.MAC, t.iface.HardwareAddr)
		return
	}

	srcKey := srcIP.String()
	dev, ok := t.devices[srcKey]
	if !ok {
		return
	}
	if dev.Blocked || (dev.CapUp > 0 && dev.Traffic.BytesUp+packetLen > dev.CapUp) {
		return
	}
	if dev.RateLimitUp > 0 && !allowToken(&dev.TokensUp, &dev.TokenRefillAtUp, dev.RateLimitUp, float64(packetLen)) {
		return
	}
	dev.Traffic.BytesUp += packetLen
	dev.Traffic.PacketsUp++
	dev.Traffic.LastSeen = time.Now()
	t.totalUp += packetLen
	if srcIP.Equal(t.localIP) {
		return
	}
	t.forwardPacket(packet.Data(), t.gatewayMAC, t.iface.HardwareAddr)
}

func (t *Tracker) forwardPacket(data []byte, newDstMAC, newSrcMAC net.HardwareAddr) {
	if len(data) < 14 {
		return
	}
	if len(data) > 1514 {
		return
	}
	frame := make([]byte, len(data))
	copy(frame, data)
	copy(frame[0:6], newDstMAC)
	copy(frame[6:12], newSrcMAC)

	err := t.handle.WritePacketData(frame)
	if err != nil {
		log.Printf("forward error: %v", err)
	}
}

func allowToken(tokens *float64, lastRefill *time.Time, rateBps, needed float64) bool {
	now := time.Now()
	elapsed := now.Sub(*lastRefill).Seconds()
	if elapsed > 0 {
		*tokens += elapsed * rateBps
		if *tokens > rateBps {
			*tokens = rateBps
		}
		*lastRefill = now
	}
	if needed > *tokens {
		return false
	}
	*tokens -= needed
	return true
}
