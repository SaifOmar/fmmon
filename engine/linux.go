//go:build linux

package engine

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"math/rand/v2"
	"strconv"
	"time"

	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// a map of ip to tc class numbers, and whether a filter is installed on each
var tcClasses map[string]map[string]map[string]bool

func getTcClass(ip string) (map[string]map[string]bool, bool) {
	if classNumber, ok := tcClasses[ip]; ok {
		return classNumber, true
	}
	return nil, false
}

// filterHandle derives the u32 handle from a class id: the minor after "1:".
func filterHandle(classID string) string {
	return "800::" + strings.TrimPrefix(classID, "1:")
}

// Both directions are allocated at once, one minor apart: down gets rnd, up
// gets rnd+1. The bool is whether a filter is installed on that class, so both
// start false.
func generateTcClasses(ip string) map[string]map[string]bool {
	if clsNmb, ok := getTcClass(ip); ok {
		return clsNmb
	}

	for {
		rnd := rand.IntN(999) + 1
		if rnd >= 999 {
			continue
		}

		classNumbers := map[string]map[string]bool{
			"down": {strconv.Itoa(rnd): false},
			"up":   {strconv.Itoa(rnd + 1): false},
		}
		if _, ok := getTcClass(ip); !ok {
			tcClasses[ip] = classNumbers
			return classNumbers
		}
	}
}

func setup(ifaces []string, host Device) error {
	// enable forwarding on ipv4 for this pc
	state := GetNetworkForwardState(ifaces)
	log.Println("state", state)
	if state != FORWARD_ACCEPT {
		err := SetNetworkForwardState(ifaces, FORWARD_ACCEPT)
		if err != nil {
			return err
		}
		if GetNetworkForwardState(ifaces) != FORWARD_ACCEPT {
			return fmt.Errorf("couldn't enable forwarding state :(%s) for dev (%s)", state, host.Interface)
		}
	}

	// remove any previous tc classes  NOTE: this is dev only remove for production when you add a proper cleanup/shutdown
	TeardownLimiter(host.Interface)
	// make tc classes map and init tc
	tcClasses = make(map[string]map[string]map[string]bool)
	err := InitLimiter(host.Interface)
	if err != nil {
		return err
	}
	return nil
}

const grantCapHelper = "/usr/local/bin/fmmon-grant-cap"

// needsNetRaw reports whether the packet socket pcap needs is still refused.
// An AF_PACKET/SOCK_RAW socket is exactly what libpcap opens under the hood,
// so this is the same check the engine would fail on, without the engine.
func needsNetRaw() bool {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0)
	if err != nil {
		return errors.Is(err, syscall.EPERM)
	}
	syscall.Close(fd)
	return false
}

func getMaxFrameLen() int {
	return 1500 + 14
}

// ensureNetRawCap makes sure this process is running with CAP_NET_RAW.
//
// The capability lives on the binary as a file capability, which only the
// kernel applies at exec time. So the grant itself is useless until the
// process runs again: on a successful grant we replace ourselves with syscall.Exec
// instead of starting a second copy, keeping one PID, one window and one engine.
//
// pkexec exit codes: 126 the dialog was dismissed, 127 authorization refused.
func EnsureNetRawCap() (bool, string) {
	if !needsNetRaw() {
		return true, ""
	}

	exe, err := os.Executable()
	if err != nil {
		return false, fmt.Sprintf("cannot locate the running binary: %v", err)
	}
	self, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return false, fmt.Sprintf("cannot resolve %s: %v", exe, err)
	}

	cmd := exec.Command("pkexec", grantCapHelper, self)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err == nil {
		if execErr := syscall.Exec(self, os.Args, os.Environ()); execErr != nil {
			return false, fmt.Sprintf("restarting with the new capability failed: %v", execErr)
		}
	}

	switch err := err.(type) {
	case *exec.ExitError:
		if err.ExitCode() == 126 {
			return false, "Permission to read network packets was cancelled. Run fmmon again and approve the password prompt to continue."
		}
		return false, fmt.Sprintf("Permission denied for %s (pkexec exit %d).\n%s", self, err.ExitCode(), strings.TrimSpace(string(out)))
	case *exec.Error:
		return false, fmt.Sprintf("pkexec could not be started: %v", err)
	default:
		return false, fmt.Sprintf("requesting packet capture permission failed: %v", err)
	}
}

func cleanDeviceForwardBlock(d *Device) error {
	sides := []string{"-s", "-d"}
	args := []string{"FORWARD", "", d.IP.String(), "-j", "DROP"}
	cn := 0
outer:
	for {
		for _, side := range sides {
			args[1] = side
			rule, present := areIptablesRulesPresent(d, args...)
			if cn == len(sides) {
				break outer
			}
			if !present {
				cn++
				continue
			}
			cn = 0
			args[1] = rule
			err := exec.Command("iptables", append([]string{"-D"}, args...)...).Run()
			if err != nil {
				log.Printf("Error deleting iptables rule for device: %s, %v", d.IP.String(), err)
				return fmt.Errorf("Error deleting iptables rule: %v", err)
			}
		}
	}

	d.Blocked = false
	return nil
}

func areIptablesRulesPresent(d *Device, args ...string) (string, bool) {
	// check if any of the two rules exist if so present if true
	return args[1], exec.Command("iptables", append([]string{"-C"}, args...)...).Run() == nil
}

func setDeviceForwardBlock(d *Device, block bool) error {
	sides := []string{"-s", "-d"}
	args := []string{"FORWARD", "", d.IP.String(), "-j", "DROP"}
	for _, side := range sides {
		args[1] = side
		rule, present := areIptablesRulesPresent(d, args...)
		if present && block {
			if !d.Blocked {
				log.Printf("Mismatch: device state is not blocked while a rule is found: %s, device: %s", rule, d.IP.String())
			}
			return errors.New("Device already blocked: rule already exists")
		}
		if !present && !block {
			if d.Blocked {
				log.Printf("Mismatch: device state is blocked while no rule is found: %s, device: %s", rule, d.IP.String())
			}
			return errors.New("Device already unblocked: no rulse found")
		} else {
			switch block {
			case true:
				err := exec.Command("iptables", append([]string{"-I"}, args...)...).Run()
				if err != nil {
					return fmt.Errorf("Error adding iptables rule: %s %v", args[1], err)
				}
			case false:
				err := exec.Command("iptables", append([]string{"-D"}, args...)...).Run()
				if err != nil {
					return fmt.Errorf("Error deleting iptables rule: %s %v", args[1], err)
				}
			}
		}
	}
	d.Blocked = block
	return nil
}

func tcCommand(args ...string) error {
	var err error
	cmd := exec.Command("tc", args...)
	err = cmd.Run()
	return err
}

func tcDeleteFilter(iface, filterClass, side, ip string) error {
	return tcCommand(
		"filter", "del", "dev", iface, "protocol",
		"ip", "parent", "1:", "prio", "1",
		"handle", filterHandle(filterClass), "u32", "match", "ip", side, ip+"/32",
	)
}

func tcChangeUpRate(iface, ip, upRate, class string) error {
	err := tcDeleteFilter(iface, class, "src", ip)
	if err != nil {
		return err
	}
	return tcAddUpload(iface, ip, upRate, class)
}

func tcChangeDownRate(iface, ip, downRate, class string) error {
	err := tcDeleteFilter(iface, class, "dst", ip)
	if err != nil {
		return err
	}
	return tcAddDownload(iface, ip, downRate, class)
}

func tcAddUpload(iface, victimIP, upRate, upClass string) error {
	err := tcCommand(
		"class", "replace",
		"dev", iface,
		"parent", "1:",
		"classid", "1:"+upClass,
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
		"handle", filterHandle(upClass),
		"u32", "match", "ip", "src", victimIP+"/32",
		"flowid", "1:"+upClass,
	)
}

func tcAddDownload(iface, victimIP, downRate, downClass string) error {
	err := tcCommand(
		"class", "replace",
		"dev", iface,
		"parent", "1:",
		"classid", "1:"+downClass,
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
		"handle", filterHandle(downClass),
		"u32", "match", "ip", "dst", victimIP+"/32",
		"flowid", "1:"+downClass,
	)
}

func markTcClassUnused(victimIP, rateType, class string) {
	classes, ok := getTcClass(victimIP)
	if !ok {
		return
	}
	byClass, ok := classes[rateType]
	if !ok {
		return
	}
	byClass[class] = false
	for _, dirs := range classes {
		for _, inUse := range dirs {
			if inUse {
				return
			}
		}
	}
	delete(tcClasses, victimIP)
}

func removeRateLimit(iface, victimIP, rateType string) error {
	classes, ok := getTcClass(victimIP)
	if !ok {
		return nil
	}
	byClass, ok := classes[rateType]
	if !ok {
		return nil
	}
	var arg string
	switch rateType {
	case "up":
		arg = "src"
	case "down":
		arg = "dst"
	default:
		return errors.New("invalid rate type")
	}
	for class, inUse := range byClass {
		if !inUse {
			continue
		}
		if err := tcDeleteFilter(iface, class, arg, victimIP); err != nil {
			return err
		}
		markTcClassUnused(victimIP, rateType, class)
		return nil
	}
	return nil
}

func addRateLimit(iface, victimIP, rateType, rate string) error {
	classes, ok := getTcClass(victimIP)
	if !ok {
		classes = generateTcClasses(victimIP)
	}
	byClass, ok := classes[rateType]
	if !ok {
		return errors.New("invalid rate type")
	}

	// One class per direction, so the first entry is the one.
	var class string
	var inUse bool
	for c, u := range byClass {
		class, inUse = c, u
		break
	}

	var err error
	switch rateType {
	case "up":
		if inUse {
			err = tcChangeUpRate(iface, victimIP, rate, class)
		} else {
			err = tcAddUpload(iface, victimIP, rate, class)
		}
	case "down":
		if inUse {
			err = tcChangeDownRate(iface, victimIP, rate, class)
		} else {
			err = tcAddDownload(iface, victimIP, rate, class)
		}
	default:
		return errors.New("invalid rate type")
	}
	if err != nil {
		return err
	}
	byClass[class] = true
	return nil
}

func TeardownLimiter(iface string) {
	err := tcCommand("qdisc", "del", "dev", iface, "root")
	if err != nil {
		fmt.Println("Error deleting tc qdisc:", err)
	}
}

func InitLimiter(iface string) error {
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

func SetNetworkForwardState(face []string, state forwardState) error {
	iface := face[0]
	cmd := exec.Command("iptables", "-A", "FORWARD", "-i", iface, "-j", string(state))
	_, err := cmd.Output()
	if err != nil {
		return err
	}
	return nil
}

func deleteIptablesIfaceRule(iface string, state string) error {
	cmd := exec.Command("iptables", "-D", "FORWARD", "-i", iface, "-j", state)
	_, err := cmd.Output()
	if err != nil {
		return err
	}
	return nil
}

func GetNetworkForwardState(face []string) forwardState {
	iface := face[0]
	var state forwardState
	cmd := exec.Command("iptables", "-S", "FORWARD")
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting iptables state:", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(out))

	var policyState forwardState
	var iFaceState forwardState
	var stateList []forwardState

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
			stateList = append(stateList, iFaceState)
		}
	}
	if len(stateList) > 1 {
		for i, iFaceState := range stateList {
			if len(stateList)-1 == i {
				break
			}
			err := deleteIptablesIfaceRule(iface, string(iFaceState))
			if err != nil {
				log.Println("Error deleting iptables rule:", err)
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

// Relay is a no-op on Linux. The kernel already relays the poisoned traffic:
// ip_forward plus the FORWARD rule installed in Start forward frames back out
// the same interface, so no userspace forwarder is needed. The goroutine
// exists only to count the bytes sent and received along side rates.
func Relay(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	// Own handle: a pcap handle may only be read by one goroutine, and ArpRCV
	// already owns the one opened in Start.
	inactive, err := pcap.NewInactiveHandle(host.Interface)
	if err != nil {
		return
	}
	defer inactive.CleanUp()

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
