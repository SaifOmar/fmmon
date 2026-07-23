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

type state int

const (
	stateTable state = iota
	stateSelect
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

	selectionCursor int
	selectionSet    map[int]bool
}

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00ff00"))
	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#aaaaaa"))
	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666"))
	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#ff0000"))
	okStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00ff00"))
	tableStyle = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("#333333"))
)

func bytesHuman(b int64) string {
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

func rateHuman(bps float64) string {
	if bps < 1 {
		return "0"
	}
	if bps < 1024 {
		return fmt.Sprintf("%.0f B/s", bps)
	}
	if bps < 1024*1024 {
		return fmt.Sprintf("%.1f KB/s", bps/1024)
	}
	return fmt.Sprintf("%.1f MB/s", bps/(1024*1024))
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
		hostname := d.Hostname
		if hostname == "" {
			hostname = "?"
		}
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
			hostname+status, d.IP.String(), d.MAC.String(),
			rateHuman(d.RateDown), rateHuman(d.RateUp),
			bytesHuman(d.Traffic.BytesDown), bytesHuman(d.Traffic.BytesUp))
	}

	fmt.Println(strings.Repeat("─", 116))
	fmt.Printf("%-22s %-15s %-17s %-9s %-9s %-12s %-12s\n",
		"TOTAL", "", "", "", "", bytesHuman(t.totalDown), bytesHuman(t.totalUp))
	fmt.Println()
}

func (t *Tracker) runTTY() error {
	columns := []table.Column{
		{Title: "Device", Width: 22},
		{Title: "IP", Width: 15},
		{Title: "MAC", Width: 17},
		{Title: "Rate↓", Width: 9},
		{Title: "Rate↑", Width: 9},
		{Title: "Total↓", Width: 12},
		{Title: "Total↑", Width: 12},
	}

	ti := textinput.New()
	ti.Placeholder = "0"
	ti.CharLimit = 20
	ti.Width = 20

	m := displayModel{
		tracker: t,
		table: table.New(
			table.WithColumns(columns),
			table.WithFocused(true),
			table.WithHeight(20),
		),
		ti:            ti,
		selectionSet:  make(map[int]bool),
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("#ffffff")).
		Background(lipgloss.Color("#005500")).
		Bold(false)
	m.table.SetStyles(s)

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
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
		case stateSelect:
			return m.handleSelectionKey(msg)
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

	case tickMsg:
		if len(m.tracker.DiscoveredDevices) > 0 && !m.tracker.DevicesSelected {
			if m.state != stateSelect {
				m.state = stateSelect
				m.selectionCursor = 0
				m.selectionSet = make(map[int]bool)
				for i := range m.tracker.DiscoveredDevices {
					m.selectionSet[i] = true
				}
			}
		} else if m.state == stateSelect {
			m.state = stateTable
		}

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
	}

	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m displayModel) handleSelectionKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	devices := m.tracker.DiscoveredDevices
	if len(devices) == 0 {
		m.state = stateTable
		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		m.tracker.Stop()
		return m, tea.Quit
	case "up", "k":
		if m.selectionCursor > 0 {
			m.selectionCursor--
		}
		return m, nil
	case "down", "j":
		if m.selectionCursor < len(devices)-1 {
			m.selectionCursor++
		}
		return m, nil
	case " ", "x":
		idx := m.selectionCursor
		if m.selectionSet[idx] {
			delete(m.selectionSet, idx)
		} else {
			m.selectionSet[idx] = true
		}
		return m, nil
	case "enter":
		selected := make([]scanner.DiscoveredDevice, 0, len(m.selectionSet))
		for i, d := range devices {
			if m.selectionSet[i] {
				selected = append(selected, d)
			}
		}
		m.tracker.ConfirmDevices(selected)
		return m, nil
	}

	return m, nil
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
		hostname := d.Hostname
		if hostname == "" {
			hostname = "?"
		}
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
			hostname + status,
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
		bytesHuman(m.tracker.TotalDown()),
		bytesHuman(m.tracker.TotalUp()),
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
	} else if m.state == stateSelect {
		devices := m.tracker.DiscoveredDevices
		b.WriteString(infoStyle.Render(" Select devices to track:"))
		b.WriteString("\n\n")
		for i, d := range devices {
			cursor := "  "
			if i == m.selectionCursor {
				cursor = "▸ "
			}
			check := " "
			if m.selectionSet[i] {
				check = "●"
			}
			hostname := scanner.ResolveHostname(d.IP)
			if hostname == "" {
				hostname = "?"
			}
			line := fmt.Sprintf("%s[%s] %-18s %-17s %s", cursor, check, d.IP.String(), d.MAC.String(), hostname)
			if i == m.selectionCursor {
				b.WriteString(headerStyle.Render(line))
			} else {
				b.WriteString(line)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
		b.WriteString(helpStyle.Render(" [↑/↓] navigate  [space] toggle  [enter] confirm  [q] quit"))
	} else if len(m.sortedDevices) == 0 {
		b.WriteString(infoStyle.Render(" Scanning network..."))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" Discovering devices via ARP (up to 5s)"))
		b.WriteString("\n")
		b.WriteString(helpStyle.Render(" [q] quit"))
	} else {
		b.WriteString(tableStyle.Render(m.table.View()))
		b.WriteString("\n\n")
		b.WriteString(helpStyle.Render(" [↑/↓] select  [b] block  [l] cap  [r] rate limit  [s] save  [q] quit"))

		newCount := m.tracker.newDeviceCount
		if newCount > 0 {
			b.WriteString("\n")
			b.WriteString(okStyle.Render(fmt.Sprintf(" %d new device(s) discovered", newCount)))
		}
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
