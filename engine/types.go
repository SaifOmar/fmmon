package engine

import (
	"fmt"
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
// 1. gracefull shutdowns [x]
// 2. make logs []
// 3. persistant data [x]
// 4. windows port [-]

type Devices struct {
	Devices       DeviceMap
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
	UpRateLimit   float64   `json:"upRateLimit"`
	DownRateLimit float64   `json:"downRateLimit"`
	Blocked       bool      `json:"blocked"`
	lastSeen      time.Time `json:"-"`             //for reachable polling
	IfaceFriendly string    `json:"ifaceFriendly"` // for windows
}

type DeviceMap map[string]*Device

type PreviousSession struct {
	id        int
	devices   map[string]Device
	totalUp   int64
	totalDown int64
}

func (d Device) String() string {
	return fmt.Sprintf("Name: %s, IP: %s, MAC: %s, Interface: %s, Reachable: %t, Mask: %s, UpRate: %.2f, DownRate: %.2f", d.Name,
		d.IP.String(), net.HardwareAddr(d.MAC).String(), d.Interface, d.Reachable, d.Mask.MaskIP.String(), d.UpRate, d.DownRate)
}

func (d *Device) tick(totalSent, totalRecieved *int64) (*int64, *int64) {
	if totalSent == nil {
		totalSent = new(int64)
	}
	if totalRecieved == nil {
		totalRecieved = new(int64)
	}
	var bytesSentNew int64 = 0
	var bytesReceivedNew int64 = 0
	now := time.Now()

	if d.lastMeasure.IsZero() {
		bytesSentNew = d.BytesSent
		bytesReceivedNew = d.BytesReceived
		d.lastMeasure = now
	} else {
		elapsed := now.Sub(d.lastMeasure).Seconds()
		if elapsed > 0.001 {
			bytesSentNew = d.BytesSent - d.prevBytesSent
			bytesReceivedNew = d.BytesReceived - d.prevBytesRecv
			d.UpRate = float64(bytesSentNew) / elapsed
			d.DownRate = float64(bytesReceivedNew) / elapsed
		}
	}
	*totalSent += bytesSentNew
	*totalRecieved += bytesReceivedNew
	d.prevBytesSent = d.BytesSent
	d.prevBytesRecv = d.BytesReceived
	d.lastMeasure = now
	return totalSent, totalRecieved
}
