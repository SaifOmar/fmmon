//go:build windows

package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/sys/windows"
)

func EnsureNetRawCap() (bool, string) {
	return true, ""
}

func setDeviceForwardBlock(ip net.IP, block bool) error {
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

func SetNetworkForwardState(iface []string, state forwardState) error {
	row, err := getIfaceRow(iface)
	if err != nil {
		panic(err)
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
	if dllHandle != nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	}

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

func Relay(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	// Own handle: a pcap handle may only be read by one goroutine, and ArpRCV
	// already owns the one opened in Start.
	handle, err := pcap.OpenLive(host.Interface, 1600, true, time.Second)
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
		if err := handle.WritePacketData(data); err != nil {
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
func GetNetworkForwardState(iface []string) forwardState {
	if dllHandle == nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	}

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
