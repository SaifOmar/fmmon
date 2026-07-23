package tracker

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestPersistedDeviceRoundtrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	original := persistedDevice{
		IP:          "192.168.1.10",
		MAC:         "aa:bb:cc:dd:ee:ff",
		Hostname:    "test-device",
		BytesDown:   1024000,
		BytesUp:     512000,
		PacketsDown: 1000,
		PacketsUp:   500,
		LastSeen:    now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded persistedDevice
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.IP != original.IP {
		t.Errorf("IP = %q, want %q", decoded.IP, original.IP)
	}
	if decoded.MAC != original.MAC {
		t.Errorf("MAC = %q, want %q", decoded.MAC, original.MAC)
	}
	if decoded.Hostname != original.Hostname {
		t.Errorf("Hostname = %q, want %q", decoded.Hostname, original.Hostname)
	}
	if decoded.BytesDown != original.BytesDown {
		t.Errorf("BytesDown = %d, want %d", decoded.BytesDown, original.BytesDown)
	}
	if decoded.BytesUp != original.BytesUp {
		t.Errorf("BytesUp = %d, want %d", decoded.BytesUp, original.BytesUp)
	}
	if decoded.PacketsDown != original.PacketsDown {
		t.Errorf("PacketsDown = %d, want %d", decoded.PacketsDown, original.PacketsDown)
	}
	if decoded.PacketsUp != original.PacketsUp {
		t.Errorf("PacketsUp = %d, want %d", decoded.PacketsUp, original.PacketsUp)
	}
	if !decoded.LastSeen.Equal(original.LastSeen) {
		t.Errorf("LastSeen = %v, want %v", decoded.LastSeen, original.LastSeen)
	}
}

func TestPersistedDevice_EmptyHostnameOmitted(t *testing.T) {
	d := persistedDevice{
		IP:  "10.0.0.1",
		MAC: "11:22:33:44:55:66",
	}

	data, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)

	if _, exists := decoded["hostname"]; exists {
		t.Error("hostname should be omitted when empty")
	}
}

func TestPersistedDevice_MACValidation(t *testing.T) {
	d := persistedDevice{
		IP:  "192.168.1.1",
		MAC: "aa:bb:cc:dd:ee:ff",
	}

	data, _ := json.Marshal(d)
	var decoded persistedDevice
	json.Unmarshal(data, &decoded)

	_, err := net.ParseMAC(decoded.MAC)
	if err != nil {
		t.Errorf("MAC %q is not parseable: %v", decoded.MAC, err)
	}
}
