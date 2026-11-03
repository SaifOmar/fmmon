package engine

import (
	"net"
	"sync"
	"time"
)

type forwardState string

type nameCh struct {
	name string
	ip   string
	mac  string
}

const (
	kb = 1024
	mb = kb * 1024
	gb = mb * 1024
	tb = gb * 1024
)

var unitStr = [4]string{"kb", " mb", "gb", "tb"}

// TODO:
// 1. gracefull shutdowns
// 2. make logs
// 3. persistant data
// 4. windows port

type DeviceMap struct {
	Devices       map[string]*Device
	TotalSent     *int64
	TotalRecieved *int64
	mu            *sync.RWMutex
}
type gateway struct {
	ip  net.IP
	mac net.HardwareAddr
}

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
	Vendor        string    `json:"vendor"`
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
