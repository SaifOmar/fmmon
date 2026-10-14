package engine

import (
	"net"
	"time"
)

type forwardState string

// call this FORWARD like a decent human being
const (
	FORWARD_ACCEPT forwardState = "ACCEPT"
	FORWARD_REJECT forwardState = "REJECT"
	FORWARD_DROP   forwardState = "DROP"
)

type Mask struct {
	MaskIP net.IP     `json:"maskIp"`
	Mask   net.IPMask `json:"mask"`
}

type Device struct {
	Name          string    `json:"name"`
	IP            net.IP    `json:"ip"`
	MAC           []byte    `json:"mac"`
	Interface     string    `json:"interface"`
	Reachable     bool      `json:"reachable"`
	Mask          Mask      `json:"mask"`
	lastMeasure   time.Time `json:"-"`
	BytesSent     int64     `json:"bytesSent"`
	BytesReceived int64     `json:"bytesReceived"`
	prevBytesSent int64     `json:"-"`
	prevBytesRecv int64     `json:"-"`
	UpRate        float64   `json:"upRate"`
	DownRate      float64   `json:"downRate"`
	UpClass       string    `json:"upClass"`
	DownClass     string    `json:"downClass"`
	UpRateLimit   float64   `json:"upRateLimit"`
	DownRateLimit float64   `json:"downRateLimit"`
	Blocked       bool      `json:"blocked"`
	lastSeen      time.Time `json:"-"`             //for reachable polling
	IfaceFriendly string    `json:"ifaceFriendly"` // for windows
}
