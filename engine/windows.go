//go:build windows

package engine

import (
	// "context"
	"fmt"
	"log"
	"net"
	// "time"
	"unsafe"

	// "github.com/gopacket/gopacket"
	// "github.com/gopacket/gopacket/layers"
	// "github.com/gopacket/gopacket/pcap"
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
	if dllHandle == nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	} else {
		return fmt.Errorf("iphlpapi.dll not found")
	}
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
	if dllHandle == nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	} else {
		return windows.MibIpInterfaceRow{}, fmt.Errorf("iphlpapi.dll not found")
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

func GetNetworkForwardState(iface []string) forwardState {
	if dllHandle == nil {
		dllHandle = windows.NewLazySystemDLL("iphlpapi.dll")
	} else {
		return ""
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
