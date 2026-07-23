package tracker

import (
	"net"
	"testing"
	"time"

	"github.com/saif/spoofer/pkg/network"
	"github.com/saif/spoofer/pkg/scanner"
)

func newTestTracker() *Tracker {
	return &Tracker{
		devices:   make(map[string]*network.Device),
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func TestAddDevice(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("192.168.1.42")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	tr.AddDevice(ip, mac, "test-device")

	dev := tr.GetDevice(ip)
	if dev == nil {
		t.Fatal("device not found after AddDevice")
	}
	if !dev.IP.Equal(ip) {
		t.Errorf("IP = %s, want %s", dev.IP, ip)
	}
	if dev.MAC.String() != mac.String() {
		t.Errorf("MAC = %s, want %s", dev.MAC, mac)
	}
	if dev.Hostname != "test-device" {
		t.Errorf("Hostname = %q, want %q", dev.Hostname, "test-device")
	}
}

func TestAddDevice_Duplicate(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("192.168.1.10")
	mac1, _ := net.ParseMAC("aa:bb:cc:dd:ee:01")
	mac2, _ := net.ParseMAC("aa:bb:cc:dd:ee:02")

	tr.AddDevice(ip, mac1, "first")
	tr.AddDevice(ip, mac2, "second")

	dev := tr.GetDevice(ip)
	if dev.MAC.String() != mac1.String() {
		t.Errorf("MAC should remain %s, got %s", mac1, dev.MAC)
	}
	if dev.Hostname != "first" {
		t.Errorf("Hostname should remain %q, got %q", "first", dev.Hostname)
	}
}

func TestRemoveDevice(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.5")
	mac, _ := net.ParseMAC("11:22:33:44:55:66")

	tr.AddDevice(ip, mac, "removable")
	tr.RemoveDevice(ip)

	if dev := tr.GetDevice(ip); dev != nil {
		t.Error("device still exists after RemoveDevice")
	}
}

func TestGetDevices_Sorted(t *testing.T) {
	tr := newTestTracker()
	tr.AddDevice(net.ParseIP("192.168.1.10"), nil, "")
	tr.AddDevice(net.ParseIP("192.168.1.2"), nil, "")
	tr.AddDevice(net.ParseIP("192.168.1.1"), nil, "")
	tr.AddDevice(net.ParseIP("192.168.1.100"), nil, "")

	devices := tr.GetDevices()
	if len(devices) != 4 {
		t.Fatalf("expected 4 devices, got %d", len(devices))
	}

	expected := []string{"192.168.1.1", "192.168.1.2", "192.168.1.10", "192.168.1.100"}
	for i, d := range devices {
		if d.IP.String() != expected[i] {
			t.Errorf("position %d: got %s, want %s", i, d.IP, expected[i])
		}
	}
}

func TestGetDevices_Copy(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("192.168.1.1")
	tr.AddDevice(ip, nil, "original")

	devices := tr.GetDevices()
	devices[0].Hostname = "modified"

	original := tr.GetDevice(ip)
	if original.Hostname != "original" {
		t.Errorf("GetDevices should return copies; hostname = %q", original.Hostname)
	}
}

func TestSetCap(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.1")
	tr.AddDevice(ip, nil, "")

	tr.SetCap(ip, 1000, 2000)

	dev := tr.GetDevice(ip)
	if dev.CapDown != 1000 {
		t.Errorf("CapDown = %d, want 1000", dev.CapDown)
	}
	if dev.CapUp != 2000 {
		t.Errorf("CapUp = %d, want 2000", dev.CapUp)
	}
}

func TestSetCap_UnknownDevice(t *testing.T) {
	tr := newTestTracker()
	tr.SetCap(net.ParseIP("10.0.0.99"), 100, 200)
}

func TestSetBlocked(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.2")
	tr.AddDevice(ip, nil, "")

	tr.SetBlocked(ip, true)
	if dev := tr.GetDevice(ip); !dev.Blocked {
		t.Error("device should be blocked")
	}

	tr.SetBlocked(ip, false)
	if dev := tr.GetDevice(ip); dev.Blocked {
		t.Error("device should be unblocked")
	}
}

func TestSetRateLimit(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.3")
	tr.AddDevice(ip, nil, "")

	tr.SetRateLimit(ip, 1024, 2048)

	dev := tr.GetDevice(ip)
	if dev.RateLimitDown != 1024 {
		t.Errorf("RateLimitDown = %f, want 1024", dev.RateLimitDown)
	}
	if dev.RateLimitUp != 2048 {
		t.Errorf("RateLimitUp = %f, want 2048", dev.RateLimitUp)
	}
	if dev.TokensDown != 0 || dev.TokensUp != 0 {
		t.Error("tokens should be reset to 0")
	}
}

func TestSetRateLimit_InitializesSeparateRefillTimes(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.4")
	tr.AddDevice(ip, nil, "")

	tr.SetRateLimit(ip, 1024, 2048)

	dev := tr.GetDevice(ip)
	if dev.TokenRefillAtDown.IsZero() {
		t.Fatal("down refill time should be set")
	}
	if dev.TokenRefillAtUp.IsZero() {
		t.Fatal("up refill time should be set")
	}
}

func TestComputeRates_Initial(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.1")
	tr.AddDevice(ip, nil, "")

	tr.ComputeRates()

	dev := tr.GetDevice(ip)
	if dev.RateDown != 0 {
		t.Errorf("initial RateDown should be 0, got %f", dev.RateDown)
	}
	if dev.RateUp != 0 {
		t.Errorf("initial RateUp should be 0, got %f", dev.RateUp)
	}
}

func TestComputeRates_WithTraffic(t *testing.T) {
	tr := newTestTracker()
	ip := net.ParseIP("10.0.0.1")
	tr.AddDevice(ip, nil, "")

	dev := tr.GetDevice(ip)
	now := time.Now()
	dev.PrevTime = now.Add(-2 * time.Second)
	dev.PrevBytesDown = 0
	dev.PrevBytesUp = 0
	dev.Traffic.BytesDown = 2000
	dev.Traffic.BytesUp = 1000

	tr.ComputeRates()

	dev = tr.GetDevice(ip)
	closeEnough := func(got, want float64) bool {
		return got > want*0.9 && got < want*1.1
	}
	if !closeEnough(dev.RateDown, 1000) {
		t.Errorf("RateDown ~= %f, want ~1000", dev.RateDown)
	}
	if !closeEnough(dev.RateUp, 500) {
		t.Errorf("RateUp ~= %f, want ~500", dev.RateUp)
	}
}

func TestTotalUpDown(t *testing.T) {
	tr := newTestTracker()
	tr.totalDown = 1000
	tr.totalUp = 500

	if tr.TotalDown() != 1000 {
		t.Errorf("TotalDown = %d, want 1000", tr.TotalDown())
	}
	if tr.TotalUp() != 500 {
		t.Errorf("TotalUp = %d, want 500", tr.TotalUp())
	}
}

func TestUptime(t *testing.T) {
	tr := newTestTracker()
	tr.startTime = time.Now().Add(-5 * time.Second)

	uptime := tr.Uptime()
	if uptime < 4*time.Second || uptime > 6*time.Second {
		t.Errorf("Uptime = %v, want ~5s", uptime)
	}
}

func TestConfirmDevices(t *testing.T) {
	tr := newTestTracker()

	called := false
	tr.SetOnDevicesSelected(func(d []scanner.DiscoveredDevice) {
		called = true
	})

	tr.ConfirmDevices(nil)

	if !called {
		t.Error("onDevicesSelected callback not called")
	}
	if !tr.DevicesSelected {
		t.Error("DevicesSelected should be true after ConfirmDevices")
	}
}

func TestSetGatewayMAC(t *testing.T) {
	tr := newTestTracker()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")

	tr.SetGatewayMAC(mac)

	tr.devicesMu.RLock()
	if tr.gatewayMAC.String() != mac.String() {
		t.Errorf("gatewayMAC = %s, want %s", tr.gatewayMAC, mac)
	}
	tr.devicesMu.RUnlock()
}

func TestAllowToken_NoTokens_ReturnsFalse(t *testing.T) {
	tokens := 0.0
	refill := time.Now()

	got := allowToken(&tokens, &refill, 1000, 1)
	if got {
		t.Error("expected false when tokens=0 and no time elapsed")
	}
}

func TestAllowToken_WithTokens_ReturnsTrue(t *testing.T) {
	tokens := 1000.0
	refill := time.Now()

	got := allowToken(&tokens, &refill, 1000, 500)
	if !got {
		t.Fatal("expected true when tokens >= needed")
	}
	if tokens != 500 {
		t.Errorf("remaining tokens = %f, want 500", tokens)
	}
}

func TestAllowToken_BurstCapped(t *testing.T) {
	tokens := 0.0
	refill := time.Now().Add(-2 * time.Second)

	got := allowToken(&tokens, &refill, 1000, 1000)
	if !got {
		t.Fatal("expected true with burst accumulation")
	}
	if tokens != 0 {
		t.Errorf("remaining tokens = %f, want 0 (burst capped at rate)", tokens)
	}
}

func TestAllowToken_ExactFit(t *testing.T) {
	tokens := 1000.0
	refill := time.Now()

	got := allowToken(&tokens, &refill, 1000, 1000)
	if !got {
		t.Error("expected true when tokens == needed")
	}
	if tokens != 0 {
		t.Errorf("remaining tokens = %f, want 0", tokens)
	}
}

func TestAllowToken_NotEnough(t *testing.T) {
	tokens := 100.0
	refill := time.Now()

	got := allowToken(&tokens, &refill, 1000, 500)
	if got {
		t.Error("expected false when tokens < needed")
	}
}

func TestAllowToken_RefillsOverTime(t *testing.T) {
	tokens := 0.0
	refill := time.Now().Add(-1 * time.Second)

	allowToken(&tokens, &refill, 1000, 0)

	if tokens < 900 || tokens > 1100 {
		t.Errorf("tokens after 1s refill = %f, want ~1000", tokens)
	}
}
