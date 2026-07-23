package tracker

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/saif/spoofer/pkg/network"
	"github.com/saif/spoofer/pkg/scanner"
)

type tickMsg time.Time

type scanDoneMsg struct {
	devices []scanner.DiscoveredDevice
	err     error
}

type state int

const (
	stateTable state = iota
	stateCapDown
	stateCapUp
	stateRateDown
	stateRateUp
)

type displayModel struct {
	tracker      *Tracker
	table        table.Model
	quitting     bool
	err          error
	state        state
	capDevice    *network.Device
	capDownVal   int64
	rateDownVal  float64
	ti           textinput.Model
	sortedDevices []*network.Device
	feedback     string
	feedbackTime time.Time

	scanning bool
	width     int
}

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#D4A574"))
	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A08C7A"))
	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7A6B5D"))
	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E07060"))
	okStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#C4A96A"))
	tableStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#4A3F35"))
)

func bytesHuman(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	return fmt.Sprintf("%.1f KB", float64(b)/1024)
}

func totalBytesHuman(b int64) string {
	if b < 1024 {
		return fmt.Sprintf("%d B", b)
	}
	if b < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	}
	if b < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
}

func deviceName(d *network.Device) string {
	if d.Hostname != "" {
		return d.Hostname
	}
	return d.IP.String()
}

func rateHuman(bps float64) string {
	return fmt.Sprintf("%.1f KB/s", bps/1024)
}

func (t *Tracker) RunDisplay() error {
	stat, _ := os.Stdin.Stat()
	isTTY := (stat.Mode() & os.ModeCharDevice) != 0

	if t.Headless || !isTTY {
		return t.runHeadless()
	}
	return t.runTTY()
}

func (t *Tracker) runHeadless() error {
	fmt.Printf("Tracking %d devices. Press Ctrl+C to stop.\n", len(t.GetDevices()))
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			t.ComputeRates()
			t.printStatus()
		case <-t.stopCh:
			return nil
		}
	}
}

func (t *Tracker) printStatus() {
	devices := t.GetDevices()
	uptime := t.Uptime()

	fmt.Print("\033[H\033[2J")
	fmt.Printf("spoofer — %s (%s devices, session %s)\n", t.localIP, fmt.Sprintf("%d", len(devices)), formatDuration(uptime))
	fmt.Println(strings.Repeat("─", 116))
	fmt.Printf("%-22s %-15s %-17s %-9s %-9s %-12s %-12s\n", "Device", "IP", "MAC", "Rate↓", "Rate↑", "Total↓", "Total↑")
	fmt.Println(strings.Repeat("─", 116))

	for _, d := range devices {
		name := deviceName(d)
		status := ""
		if d.Blocked {
			status = " [B]"
		} else if d.CapDown > 0 || d.CapUp > 0 {
			status = " [C]"
		}
		if d.RateLimitDown > 0 || d.RateLimitUp > 0 {
			if d.RateLimitDown > 0 && d.RateLimitUp > 0 {
				status += " [R]"
			} else if d.RateLimitDown > 0 {
				status += " [R↓]"
			} else {
				status += " [R↑]"
			}
		}
		fmt.Printf("%-22s %-15s %-17s %-9s %-9s %-12s %-12s\n",
			name+status, d.IP.String(), d.MAC.String(),
			rateHuman(d.RateDown), rateHuman(d.RateUp),
			bytesHuman(d.Traffic.BytesDown), bytesHuman(d.Traffic.BytesUp))
	}

	fmt.Println(strings.Repeat("─", 116))
	fmt.Printf("%-22s %-15s %-17s %-9s %-9s %-12s %-12s\n",
		"TOTAL", "", "", "", "", totalBytesHuman(t.totalDown), totalBytesHuman(t.totalUp))
	fmt.Println()
}

func (t *Tracker) runTTY() error {
	ti := textinput.New()
	ti.Placeholder = "0"
	ti.CharLimit = 20
	ti.Width = 20

	m := displayModel{
		tracker: t,
		table: table.New(
			table.WithColumns(responsiveColumns(76)),
			table.WithFocused(true),
			table.WithHeight(20),
		),
		ti: ti,
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#4A3F35")).
		BorderBottom(true).
		Bold(true).
		Padding(0).
		Foreground(lipgloss.Color("#C4B8A8"))
	s.Cell = s.Cell.
		Padding(0).
		Foreground(lipgloss.Color("#B8A99A"))
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("#F0D08C")).
		Background(lipgloss.Color("#3A3228")).
		Bold(false)
	m.table.SetStyles(s)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}

func responsiveColumns(innerWidth int) []table.Column {
	const (
		rateMin   = 9
		totalMin  = 11
		deviceMin = 8
	)
	fixed := rateMin*2 + totalMin*2
	remaining := innerWidth - fixed
	if remaining < deviceMin*3 {
		remaining = deviceMin * 3
	}
	return []table.Column{
		{Title: "Device", Width: remaining * 3 / 7},
		{Title: "IP", Width: remaining * 2 / 7},
		{Title: "MAC", Width: remaining * 2 / 7},
		{Title: "Rate↓", Width: rateMin},
		{Title: "Rate↑", Width: rateMin},
		{Title: "Total↓", Width: totalMin},
		{Title: "Total↑", Width: totalMin},
	}
}

func (m displayModel) Init() tea.Cmd {
	return tea.Every(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m displayModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case stateTable:
			return m.updateTable(msg)
		case stateCapDown:
			return m.updateCapDown(msg)
		case stateCapUp:
			return m.updateCapUp(msg)
		case stateRateDown:
			return m.updateRateDown(msg)
		case stateRateUp:
			return m.updateRateUp(msg)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		inner := msg.Width - 2
		cols := responsiveColumns(inner)
		m.table.SetColumns(cols)
		m.table.SetWidth(inner)
		h := msg.Height - 8
		if h < 5 {
			h = 5
		}
		if h > 30 {
			h = 30
		}
		m.table.SetHeight(h)
		return m, nil

	case tickMsg:
		m.tracker.ComputeRates()
		m.sortedDevices = m.tracker.GetDevices()
		rows := m.buildRows()
		m.table.SetRows(rows)
		if m.err != nil {
			m.err = nil
		}
		return m, tea.Every(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		})

	case scanDoneMsg:
		m.scanning = false
		if msg.err != nil {
			m.err = msg.err
			return m, nil
		}
		if len(msg.devices) == 0 {
			m.feedback = "no new devices found"
			m.feedbackTime = time.Now().Add(2 * time.Second)
			return m, nil
		}
		for _, d := range msg.devices {
			hostname := scanner.ResolveHostname(d.IP)
			m.tracker.AddDevice(d.IP, d.MAC, hostname)
			m.tracker.NotifyNewDevice(d.IP, d.MAC, hostname)
		}
		m.feedback = fmt.Sprintf("%d new device(s) discovered", len(msg.devices))
		m.feedbackTime = time.Now().Add(2 * time.Second)
		return m, nil
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m displayModel) updateTable(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		m.tracker.Stop()
		return m, tea.Quit
	case "s":
		err := m.tracker.Save()
		if err != nil {
			m.err = err
		}
		return m, nil
	case "b":
		row := m.table.Cursor()
		if row >= 0 && row < len(m.sortedDevices) {
			dev := m.sortedDevices[row]
			m.tracker.SetBlocked(dev.IP, !dev.Blocked)
			m.feedback = fmt.Sprintf("toggled block for %s (%s)", dev.Hostname, dev.IP)
			m.feedbackTime = time.Now().Add(2 * time.Second)
		}
		return m, nil
	case "l":
		row := m.table.Cursor()
		if row >= 0 && row < len(m.sortedDevices) {
			m.capDevice = m.sortedDevices[row]
			m.capDownVal = 0
			m.state = stateCapDown
			m.ti.SetValue("")
			m.ti.Placeholder = "0 (unlimited)"
			m.ti.Focus()
			return m, textinput.Blink
		}
		return m, nil
	case "r":
		row := m.table.Cursor()
		if row >= 0 && row < len(m.sortedDevices) {
			m.capDevice = m.sortedDevices[row]
			m.rateDownVal = 0
			m.state = stateRateDown
			m.ti.SetValue("")
			m.ti.Placeholder = "0 (unlimited)"
			m.ti.Focus()
			return m, textinput.Blink
		}
		return m, nil
	case "d":
		m.scanning = true
		p := m.tracker
		return m, func() tea.Msg {
			devices, err := scanner.ARPScan(p.ifaceName, 5*time.Second)
			if err != nil {
				return scanDoneMsg{err: err}
			}

			existing := make(map[string]bool)
			for _, d := range p.GetDevices() {
				existing[d.IP.String()] = true
			}
			var newDevices []scanner.DiscoveredDevice
			for _, d := range devices {
				if !existing[d.IP.String()] {
					newDevices = append(newDevices, d)
				}
			}
			return scanDoneMsg{devices: newDevices}
		}
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m displayModel) updateCapDown(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		valStr := strings.TrimSpace(m.ti.Value())
		if valStr == "" {
			valStr = "0"
		}
		val, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			m.err = fmt.Errorf("invalid number: %s", valStr)
			m.state = stateTable
			return m, nil
		}
		m.capDownVal = val
		m.state = stateCapUp
		m.ti.SetValue("")
		m.ti.Placeholder = "0 (unlimited)"
		m.ti.Focus()
		return m, textinput.Blink
	case "esc":
		m.state = stateTable
		return m, nil
	}

	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m displayModel) updateCapUp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		valStr := strings.TrimSpace(m.ti.Value())
		if valStr == "" {
			valStr = "0"
		}
		val, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			m.err = fmt.Errorf("invalid number: %s", valStr)
			m.state = stateTable
			return m, nil
		}
		if m.capDevice != nil {
			m.tracker.SetCap(m.capDevice.IP, m.capDownVal*1024*1024, val*1024*1024)
			m.feedback = fmt.Sprintf("capped %s (%s): down=%dMB up=%dMB",
				m.capDevice.Hostname, m.capDevice.IP, m.capDownVal, val)
			m.feedbackTime = time.Now().Add(2 * time.Second)
		}
		m.state = stateTable
		return m, nil
	case "esc":
		m.state = stateTable
		return m, nil
	}

	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m displayModel) updateRateDown(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		valStr := strings.TrimSpace(m.ti.Value())
		if valStr == "" {
			valStr = "0"
		}
		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			m.err = fmt.Errorf("invalid number: %s", valStr)
			m.state = stateTable
			return m, nil
		}
		m.rateDownVal = val
		m.state = stateRateUp
		m.ti.SetValue("")
		m.ti.Placeholder = "0 (unlimited)"
		m.ti.Focus()
		return m, textinput.Blink
	case "esc":
		m.state = stateTable
		return m, nil
	}

	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m displayModel) updateRateUp(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		valStr := strings.TrimSpace(m.ti.Value())
		if valStr == "" {
			valStr = "0"
		}
		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			m.err = fmt.Errorf("invalid number: %s", valStr)
			m.state = stateTable
			return m, nil
		}
		if m.capDevice != nil {
			m.tracker.SetRateLimit(m.capDevice.IP, m.rateDownVal*1024, val*1024)
			downStr := rateHuman(m.rateDownVal * 1024)
			upStr := rateHuman(val * 1024)
			m.feedback = fmt.Sprintf("rate limited %s (%s): down=%s up=%s",
				m.capDevice.Hostname, m.capDevice.IP, downStr, upStr)
			m.feedbackTime = time.Now().Add(2 * time.Second)
		}
		m.state = stateTable
		return m, nil
	case "esc":
		m.state = stateTable
		return m, nil
	}

	var cmd tea.Cmd
	m.ti, cmd = m.ti.Update(msg)
	return m, cmd
}

func (m displayModel) buildRows() []table.Row {
	rows := make([]table.Row, 0, len(m.sortedDevices)+2)

	for _, d := range m.sortedDevices {
		name := deviceName(d)
		status := ""
		if d.Blocked {
			status = " [B]"
		} else if d.CapDown > 0 || d.CapUp > 0 {
			status = " [C]"
		}
		if d.RateLimitDown > 0 || d.RateLimitUp > 0 {
			if d.RateLimitDown > 0 && d.RateLimitUp > 0 {
				status += " [R]"
			} else if d.RateLimitDown > 0 {
				status += " [R↓]"
			} else {
				status += " [R↑]"
			}
		}

		rateDown := rateHuman(d.RateDown)
		rateUp := rateHuman(d.RateUp)

		rows = append(rows, table.Row{
			name + status,
			d.IP.String(),
			d.MAC.String(),
			rateDown,
			rateUp,
			bytesHuman(d.Traffic.BytesDown),
			bytesHuman(d.Traffic.BytesUp),
		})
	}

	rows = append(rows, table.Row{"", "", "", "", "", "", ""})

	rows = append(rows, table.Row{
		"TOTAL",
		fmt.Sprintf("%d devices", len(m.sortedDevices)),
		"",
		"",
		"",
		totalBytesHuman(m.tracker.TotalDown()),
		totalBytesHuman(m.tracker.TotalUp()),
	})

	return rows
}

func (m displayModel) View() string {
	if m.quitting {
		return "Restoring ARP tables...\n"
	}

	var b strings.Builder
	b.WriteString(headerStyle.Render(" spoofer — Per-Device Bandwidth Tracker "))
	b.WriteString("\n\n")

	uptime := m.tracker.Uptime()
	b.WriteString(infoStyle.Render(fmt.Sprintf(" Session: %s  ", formatDuration(uptime))))

	if m.scanning {
		b.WriteString(infoStyle.Render(" Scanning..."))
	}

	if !m.feedbackTime.IsZero() && time.Now().Before(m.feedbackTime) {
		b.WriteString(okStyle.Render(fmt.Sprintf(" %s", m.feedback)))
	} else {
		m.feedback = ""
	}

	if m.err != nil {
		b.WriteString(errorStyle.Render(fmt.Sprintf(" Error: %v", m.err)))
	}
	b.WriteString("\n\n")

	if m.state == stateCapDown || m.state == stateCapUp {
		prompt := "Down cap (MB, 0 = unlimited):"
		if m.state == stateCapUp {
			prompt = "Up cap (MB, 0 = unlimited):"
		}
		b.WriteString(helpStyle.Render(fmt.Sprintf(" %s (%s)", prompt, m.capDevice.IP.String())))
		b.WriteString("\n ")
		b.WriteString(m.ti.View())
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [enter] confirm  [esc] cancel"))
	} else if m.state == stateRateDown || m.state == stateRateUp {
		prompt := "Down rate limit (KB/s, 0 = unlimited):"
		if m.state == stateRateUp {
			prompt = "Up rate limit (KB/s, 0 = unlimited):"
		}
		b.WriteString(helpStyle.Render(fmt.Sprintf(" %s (%s)", prompt, m.capDevice.IP.String())))
		b.WriteString("\n ")
		b.WriteString(m.ti.View())
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [enter] confirm  [esc] cancel"))
	} else if len(m.sortedDevices) == 0 {
		b.WriteString(infoStyle.Render(" Scanning network..."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" Discovering devices via ARP"))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render(" [q] quit"))
	} else {
		b.WriteString(tableStyle.Render(m.table.View()))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [↑/↓] select  [b] block  [l] cap  [r] rate limit  [d] discover  [s] save  [q] quit"))
	}

	return b.String()
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60

	if h > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", h, m, s)
	}
	return fmt.Sprintf("%02dm %02ds", m, s)
}
