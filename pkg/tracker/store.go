package tracker

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/saif/spoofer/pkg/network"
)

type persistedDevice struct {
	IP          string    `json:"ip"`
	MAC         string    `json:"mac"`
	Hostname    string    `json:"hostname,omitempty"`
	BytesDown   int64     `json:"bytes_down"`
	BytesUp     int64     `json:"bytes_up"`
	PacketsDown int64     `json:"packets_down"`
	PacketsUp   int64     `json:"packets_up"`
	LastSeen    time.Time `json:"last_seen"`
}

type persistedData struct {
	Version   int               `json:"version"`
	UpdatedAt time.Time         `json:"updated_at"`
	Devices   []persistedDevice `json:"devices"`
}

func storePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".spoofer")
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	return filepath.Join(dir, "traffic.json"), nil
}

func (t *Tracker) Save() error {
	path, err := storePath()
	if err != nil {
		return err
	}

	t.devicesMu.RLock()
	devices := make([]persistedDevice, 0, len(t.devices))
	for _, d := range t.devices {
		devices = append(devices, persistedDevice{
			IP:          d.IP.String(),
			MAC:         d.MAC.String(),
			Hostname:    d.Hostname,
			BytesDown:   d.Traffic.BytesDown,
			BytesUp:     d.Traffic.BytesUp,
			PacketsDown: d.Traffic.PacketsDown,
			PacketsUp:   d.Traffic.PacketsUp,
			LastSeen:    d.Traffic.LastSeen,
		})
	}
	t.devicesMu.RUnlock()

	data := persistedData{
		Version:   1,
		UpdatedAt: time.Now(),
		Devices:   devices,
	}

	payload, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	err = os.WriteFile(path, payload, 0644)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}

func LoadHistory() (map[string]*persistedDevice, error) {
	path, err := storePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*persistedDevice), nil
		}
		return nil, fmt.Errorf("read file: %w", err)
	}

	var pd persistedData
	err = json.Unmarshal(data, &pd)
	if err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	result := make(map[string]*persistedDevice)
	for i := range pd.Devices {
		result[pd.Devices[i].IP] = &pd.Devices[i]
	}
	return result, nil
}

func (t *Tracker) MergeHistory() error {
	history, err := LoadHistory()
	if err != nil {
		return err
	}

	t.devicesMu.Lock()
	defer t.devicesMu.Unlock()

	for ipStr, h := range history {
		if _, exists := t.devices[ipStr]; !exists {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			mac, err := net.ParseMAC(h.MAC)
			if err != nil {
				continue
			}
			t.devices[ipStr] = &network.Device{
				IP:       ip,
				MAC:      mac,
				Hostname: h.Hostname,
				Traffic: network.TrafficCounters{
					BytesDown:   h.BytesDown,
					BytesUp:     h.BytesUp,
					PacketsDown: h.PacketsDown,
					PacketsUp:   h.PacketsUp,
					LastSeen:    h.LastSeen,
				},
			}
		}
	}
	return nil
}
