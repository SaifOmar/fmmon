//go:build linux

package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

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

func setDeviceForwardBlock(ip net.IP, block bool) error {
	for _, side := range []string{"-s", "-d"} {
		args := []string{"FORWARD", side, ip.String(), "-j", "DROP"}
		present := exec.Command("iptables", append([]string{"-C"}, args...)...).Run() == nil
		if block && !present {
			if err := exec.Command("iptables", append([]string{"-I"}, args...)...).Run(); err != nil {
				return err
			}
		}
		if !block && present {
			if err := exec.Command("iptables", append([]string{"-D"}, args...)...).Run(); err != nil {
				return err
			}
		}
	}
	return nil
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

// Relay is a no-op on Linux. The kernel already relays the poisoned traffic:
// ip_forward plus the FORWARD rule installed in Start forward frames back out
// the same interface, so no userspace forwarder is needed. The goroutine
// exists only to keep the lifecycle identical across platforms.
func Relay(devices DeviceMap, host Device, ctx context.Context, errChan chan error) {
	<-ctx.Done()
}
