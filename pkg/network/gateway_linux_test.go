//go:build linux

package network

import (
	"net"
	"testing"
)

func TestParseHexIP_Zero(t *testing.T) {
	ip, err := parseHexIP("00000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := net.IP{0, 0, 0, 0}
	if !ip.Equal(want) {
		t.Errorf("got %s, want %s", ip, want)
	}
}

func TestParseHexIP_AllOnes(t *testing.T) {
	ip, err := parseHexIP("FFFFFFFF")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := net.IP{255, 255, 255, 255}
	if !ip.Equal(want) {
		t.Errorf("got %s, want %s", ip, want)
	}
}

func TestParseHexIP_InvalidLength(t *testing.T) {
	_, err := parseHexIP("C0A8")
	if err == nil {
		t.Error("expected error for short hex")
	}
}

func TestParseHexIP_InvalidHex(t *testing.T) {
	_, err := parseHexIP("ZZZZZZZZ")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestParseHexIP_Empty(t *testing.T) {
	_, err := parseHexIP("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseHexIP_LittleEndianRoundtrip(t *testing.T) {
	ip, err := parseHexIP("01000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := net.IP{0, 0, 0, 1}
	if !ip.Equal(want) {
		t.Errorf("got %s, want %s", ip, want)
	}
}
