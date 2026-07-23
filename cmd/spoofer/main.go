package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/urfave/cli/v2"

	"github.com/saif/spoofer/pkg/arpspoof"
	"github.com/saif/spoofer/pkg/network"
	"github.com/saif/spoofer/pkg/scanner"
	"github.com/saif/spoofer/pkg/tracker"
)

func main() {
	app := &cli.App{
		Name:    "spoofer",
		Usage:   "Per-device bandwidth tracker with ARP MITM",
		Version: "0.1.0",
		DefaultCommand: "track",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List network interfaces and their stats",
				Action: func(cCtx *cli.Context) error {
					return cmdList()
				},
			},
			{
				Name:  "scan",
				Usage: "Discover devices on the local network",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "iface", Usage: "Network interface"},
					&cli.DurationFlag{Name: "timeout", Value: 5 * time.Second, Usage: "Scan timeout"},
				},
				Action: func(cCtx *cli.Context) error {
					return cmdScan(cCtx.String("iface"), cCtx.Duration("timeout"))
				},
			},
			{
				Name:  "track",
				Usage: "Start per-device bandwidth tracking",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "iface", Usage: "Network interface"},
					&cli.StringFlag{Name: "gateway", Usage: "Gateway IP (auto-detected if omitted)"},
					&cli.BoolFlag{Name: "headless", Usage: "Run without TUI (for headless/scripting)"},
				},
				Action: func(cCtx *cli.Context) error {
					return cmdTrack(cCtx.String("iface"), cCtx.String("gateway"), cCtx.Bool("headless"))
				},
			},
			{
				Name:  "history",
				Usage: "Show saved bandwidth usage history",
				Action: func(cCtx *cli.Context) error {
					return cmdHistory()
				},
			},
			{
				Name:  "cap",
				Usage: "Set bandwidth cap for a device",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "target", Required: true, Usage: "Target IP"},
					&cli.StringFlag{Name: "down", Usage: "Download cap (e.g. 50MB, 1GB)"},
					&cli.StringFlag{Name: "up", Usage: "Upload cap (e.g. 10MB, 500MB)"},
				},
				Action: func(cCtx *cli.Context) error {
					return cmdCap(cCtx.String("target"), cCtx.String("down"), cCtx.String("up"))
				},
			},
			{
				Name:  "block",
				Usage: "Block a device from internet access",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "target", Required: true, Usage: "Target IP"},
				},
				Action: func(cCtx *cli.Context) error {
					return cmdBlock(cCtx.String("target"))
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func cmdList() error {
	ifaces, err := network.ListInterfaces()
	if err != nil {
		return err
	}

	fmt.Printf("%-12s %-18s %-16s %s\n", "Interface", "MAC", "IPs", "Status")
	fmt.Println("------")
	for _, iface := range ifaces {
		status := "down"
		if iface.IsUp {
			status = "up"
		}
		if iface.IsLoopback {
			status = "loopback"
		}
		ips := ""
		for i, ip := range iface.IPs {
			if i > 0 {
				ips += ", "
			}
			ips += ip.String()
		}
		fmt.Printf("%-12s %-18s %-16s %s\n", iface.Name, iface.MAC.String(), ips, status)
	}
	return nil
}

func cmdScan(ifaceName string, timeout time.Duration) error {
	if err := network.CheckAdminPrivileges(); err != nil {
		return err
	}

	if ifaceName == "" {
		iface, err := network.PickDefaultInterface()
		if err != nil {
			return fmt.Errorf("no interface specified and auto-detect failed: %w", err)
		}
		ifaceName = iface.Name
	}

	fmt.Printf("Scanning on %s (timeout: %v)...\n", ifaceName, timeout)

	devices, err := scanner.ARPScan(ifaceName, timeout)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	fmt.Printf("\n%-18s %-18s %s\n", "IP", "MAC", "Hostname")
	fmt.Println("---")

	var ips []net.IP
	for _, d := range devices {
		ips = append(ips, d.IP)
	}
	hostnames := scanner.ResolveHostnames(ips)

	for _, d := range devices {
		hostname := hostnames[d.IP.String()]
		fmt.Printf("%-18s %-18s %s\n", d.IP.String(), d.MAC.String(), hostname)
	}
	fmt.Printf("\n%d device(s) found\n", len(devices))
	return nil
}

func cmdTrack(ifaceName, gatewayStr string, headless bool) error {
	if err := network.CheckAdminPrivileges(); err != nil {
		return err
	}

	if ifaceName == "" {
		if headless {
			iface, err := network.PickDefaultInterface()
			if err != nil {
				return fmt.Errorf("no interface: %w", err)
			}
			ifaceName = iface.Name
		} else {
			var err error
			ifaceName, err = runInterfacePicker()
			if err != nil {
				return err
			}
		}
	}

	iface, err := network.SelectInterface(ifaceName)
	if err != nil {
		return err
	}

	var localIP net.IP
	if len(iface.IPs) > 0 {
		localIP = iface.IPs[0]
	}
	if localIP == nil {
		return fmt.Errorf("no IPv4 on interface %s", ifaceName)
	}

	var gatewayIP net.IP
	if gatewayStr != "" {
		gatewayIP = net.ParseIP(gatewayStr)
		if gatewayIP == nil {
			return fmt.Errorf("invalid gateway IP: %s", gatewayStr)
		}
	} else {
		gw, err := network.GetGateway()
		if err != nil {
			return fmt.Errorf("auto-detect gateway: %w (specify --gateway)", err)
		}
		gatewayIP = gw
	}

	spoofer, err := arpspoof.New(ifaceName, localIP, gatewayIP)
	if err != nil {
		return fmt.Errorf("arpspoof init: %w", err)
	}
	defer spoofer.Close()

	tr, err := tracker.New(ifaceName, localIP, gatewayIP, nil)
	if err != nil {
		return fmt.Errorf("tracker init: %w", err)
	}
	tr.Headless = headless
	defer tr.Close()

	err = tr.MergeHistory()
	if err != nil {
		log.Printf("warning: could not load history: %v", err)
	}

	err = tr.Start()
	if err != nil {
		return fmt.Errorf("tracker start: %w", err)
	}
	defer tr.Stop()
	defer spoofer.Stop()
	defer spoofer.RestoreAll()

	tr.SetOnNewDevice(func(ip net.IP, mac net.HardwareAddr, hostname string) {
		err := spoofer.Poison(ip)
		if err != nil {
			log.Printf("warn: could not poison %s: %v", ip, err)
			return
		}
		spoofer.StartContinuousPoison(ip)
	})

	go func() {
		err := spoofer.ResolveGatewayMAC()
		if err != nil {
			log.Printf("error: could not resolve gateway MAC: %v", err)
			return
		}
		tr.SetGatewayMAC(spoofer.GatewayMAC())

		hostname := scanner.ResolveHostname(localIP)
		if hostname == "" {
			hostname = "me"
		}
		tr.AddDevice(localIP, iface.MAC, hostname)

		devices, err := scanner.ARPScan(ifaceName, 5*time.Second)
		if err != nil {
			log.Printf("error: initial scan failed: %v", err)
			tr.StartPeriodicRescan(ifaceName, 30*time.Second)
			return
		}

		for _, d := range devices {
			hostname := scanner.ResolveHostname(d.IP)
			tr.AddDevice(d.IP, d.MAC, hostname)
			tr.NotifyNewDevice(d.IP, d.MAC, hostname)
		}

		tr.StartPeriodicRescan(ifaceName, 30*time.Second)
	}()

	return tr.RunDisplay()
}

type ifacePickerModel struct {
	ifaces    []network.InterfaceInfo
	valid     []int
	cursor    int
	selected  string
	quitting  bool
}

func (m ifacePickerModel) Init() tea.Cmd { return nil }

func (m ifacePickerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
			return m, nil
		case "down", "j":
			if m.cursor < len(m.valid)-1 {
				m.cursor++
			}
			return m, nil
		case "enter":
			m.selected = m.ifaces[m.valid[m.cursor]].Name
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m ifacePickerModel) View() string {
	var b strings.Builder
	b.WriteString("Available interfaces:\n\n")
	for i, idx := range m.valid {
		iface := m.ifaces[idx]
		ipStr := ""
		if len(iface.IPs) > 0 {
			ipStr = iface.IPs[0].String()
		}
		cursor := "  "
		if i == m.cursor {
			cursor = "▸ "
		}
		line := fmt.Sprintf("%s%-10s  %-17s  %-15s  up", cursor, iface.Name, iface.MAC.String(), ipStr)
		if i == m.cursor {
			b.WriteString("\033[7m" + line + "\033[0m\n")
		} else {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString("\n↑/↓ navigate  enter select  q quit\n")
	return b.String()
}

func runInterfacePicker() (string, error) {
	ifaces, err := network.ListInterfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}

	valid := make([]int, 0)
	for i, iface := range ifaces {
		if iface.IsUp && !iface.IsLoopback && len(iface.IPs) > 0 {
			valid = append(valid, i)
		}
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no suitable interface found")
	}

	m := ifacePickerModel{ifaces: ifaces, valid: valid}
	p := tea.NewProgram(m)
	result, err := p.Run()
	if err != nil {
		return "", err
	}

	final := result.(ifacePickerModel)
	if final.selected == "" {
		return "", fmt.Errorf("quit")
	}
	return final.selected, nil
}

func cmdHistory() error {
	history, err := tracker.LoadHistory()
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}

	if len(history) == 0 {
		fmt.Println("No history found.")
		return nil
	}

	fmt.Printf("%-18s %-18s %-12s %-12s %s\n", "IP", "MAC", "Down", "Up", "Last Seen")
	fmt.Println("---")
	for _, h := range history {
		lastSeen := "-"
		if !h.LastSeen.IsZero() {
			lastSeen = h.LastSeen.Format("2006-01-02 15:04")
		}
		fmt.Printf("%-18s %-18s %-12s %-12s %s\n", h.IP, h.MAC, bytesHuman(h.BytesDown), bytesHuman(h.BytesUp), lastSeen)
	}
	return nil
}

func cmdCap(target, downStr, upStr string) error {
	var down, up int64
	if downStr != "" {
		var err error
		down, err = tracker.ParseCapSize(downStr)
		if err != nil {
			return fmt.Errorf("invalid down cap: %w", err)
		}
	}
	if upStr != "" {
		var err error
		up, err = tracker.ParseCapSize(upStr)
		if err != nil {
			return fmt.Errorf("invalid up cap: %w", err)
		}
	}
	fmt.Printf("Cap for %s: down=%s (%d bytes) up=%s (%d bytes) (requires running 'track' to take effect)\n", target, downStr, down, upStr, up)
	return nil
}

func cmdBlock(target string) error {
	fmt.Printf("Blocked %s (requires running 'track' to take effect)\n", target)
	return nil
}

func bytesHuman(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.1f KB", float64(b)/1024)
}
