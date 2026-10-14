//go:build windows

package engine

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/windows"
)

func cleanDeviceForwardBlock(d *Device) error { return nil }

func setup(ifaces []string, host Device) error {
	state := GetNetworkForwardState(ifaces)
	log.Println("state", state)
	if state != FORWARD_ACCEPT {
		err := SetNetworkForwardState(ifaces, FORWARD_ACCEPT)
		if err != nil {
			panic(err)
		}
		if GetNetworkForwardState(ifaces) != FORWARD_ACCEPT {
			panic(fmt.Errorf("couldn't enable forwarding state :(%s) for dev (%s)", state, host.Interface))
		}
	}

	TeardownLimiter(host.Interface)
	err := InitLimiter(host.Interface)
	if err != nil {
		return err
	}
	return nil
}
func EnsureNetRawCap() (bool, string) {
	return true, ""
}

func setDeviceForwardBlock(d *Device, block bool) error {
	return nil
}

var dllHandle *windows.LazyDLL

func tcCommand(args ...string) error {
	return nil
}

func tcDeleteFilter(iface, filterHandle, side, ip string) error {
	return nil
}

func tcChangeUpRate(iface, ip, upRate, upClass string) error {
	return nil
}

func tcChangeDownRate(iface, ip, downRate, downClass string) error {
	return nil
}

func tcAddUpload(iface, victimIP, upRate, upClass string) error {
	return nil
}

func tcAddDownload(iface, victimIP, downRate, downClass string) error {
	return nil
}

func TeardownLimiter(iface string) {
	// No-op on Windows.
}

func InitLimiter(iface string) error {
	return nil
}

func loadDll() {
	if dllHandle == nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	}
}

func getMaxFrameLen() int {
	return math.MaxInt
}

func SetNetworkForwardState(iface []string, state forwardState) error {
	loadDll()
	row, err := getIfaceRow(iface)
	if err != nil {
		return err
	}
	row.SitePrefixLength = 0
	if state == FORWARD_ACCEPT {
		if row.ForwardingEnabled == 0 {
			row.ForwardingEnabled = 1
		}
	} else if state == FORWARD_DROP {
		if row.ForwardingEnabled == 1 {
			row.ForwardingEnabled = 0
		}
	} else {
		return nil
	}

	log.Printf("ForwardingEnabled: %d", row.ForwardingEnabled)
	setIpInterfaceEntry := dllHandle.NewProc("SetIpInterfaceEntry")
	ret, _, _ := setIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return fmt.Errorf("SetIpInterfaceEntry failed with code: %d", ret)
	}
	return nil
}

func getIfaceRow(iface []string) (windows.MibIpInterfaceRow, error) {
	loadDll()
	ifi, err := net.InterfaceByName(iface[1])
	if err != nil {
		return windows.MibIpInterfaceRow{}, err
	}

	row := windows.MibIpInterfaceRow{
		Family:         windows.AF_INET,
		InterfaceIndex: uint32(ifi.Index),
	}

	getIpInterfaceEntry := dllHandle.NewProc("GetIpInterfaceEntry")
	ret, _, _ := getIpInterfaceEntry.Call(uintptr(unsafe.Pointer(&row)))
	if ret != 0 {
		return windows.MibIpInterfaceRow{}, fmt.Errorf("GetIpInterfaceEntry failed for %q (index %d): code %d", iface[1], ifi.Index, ret)
	}
	return row, nil
}

func GetNetworkForwardState(iface []string) forwardState {
	loadDll()

	row, err := getIfaceRow(iface)
	if err != nil {
		panic("err: " + err.Error())

	}
	switch row.ForwardingEnabled {
	case 0:
		return FORWARD_DROP
	case 1:
		return FORWARD_ACCEPT
	}
	return ""
}

// Relay act as a router on windows so it forwards the traffic through the machine to the victim
// and alos counts the bytes sent and received along side rates.
func Relay(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	// Own handle: a pcap handle may only be read by one goroutine, and ArpRCV
	// already owns the one opened in Start.
	inactive, err := pcap.NewInactiveHandle(host.Interface)
	if err != nil {
		return
	}
	defer inactive.CleanUp()
	// NOTE : I am experimenting with diffrenet settings since i don't know alot about them
	//
	if err := inactive.SetSnapLen(65536); err != nil {
		return
	}
	if err := inactive.SetBufferSize(32 * 1024 * 1024); err != nil { // 32MB ring
		return
	}
	if err := inactive.SetPromisc(true); err != nil {
		return
	}
	if err := inactive.SetTimeout(50 * time.Millisecond); err != nil {
		return
	}
	if err := inactive.SetImmediateMode(false); err != nil {
		return
	}
	if err := inactive.SetPromisc(true); err != nil {
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
	ticker := time.NewTicker(time.Second * 1)
	var prevTick int
	var newtTick int
	for {
		if newtTick == math.MaxInt-1 {
			newtTick, prevTick = 0, 0
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newtTick++
		case packet, ok := <-packetsCh:
			if !ok {
				return

			}
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
			if len(packet.Data()) > getMaxFrameLen() {
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

			var srcDev, dstDev *Device
			var nextHop net.HardwareAddr

			bytes := int64(ip4.Length)

			devices.mu.Lock()
			for _, d := range devices.Devices {
				shouldTick := false
				if d.IP.Equal(dst) {
					dstDev = d
					d.BytesReceived += bytes
					shouldTick = true
				}
				if d.IP.Equal(src) {
					srcDev = d
					d.BytesSent += bytes
					shouldTick = true
				}
				if newtTick > prevTick {
					if shouldTick {
						d.tick()
						prevTick++
					}
				}
			}
			devices.mu.Unlock()

			// internet/LAN -> victim: deliver straight to the victim.
			if dstDev != nil {
				if dstDev.Blocked {
					continue
				}
				nextHop = net.HardwareAddr(dstDev.MAC)
			}

			// victim -> internet: hand it back to the real gateway.
			if srcDev != nil {
				if srcDev.Blocked {
					continue
				}
				gw := gateWay.Load()
				if gw == nil {
					continue
				}
				nextHop = net.HardwareAddr(gw.mac)
			}

			if nextHop == nil || nextHop.String() == hostMAC.String() {
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
}

func addRateLimit(iface, victimIP, rateType, rate string) error { return nil }
func removeRateLimit(iface, victimIP, upRate string) error      { return nil }
