package network

import (
	"net"
	"time"
)

type Direction int

const (
	DirectionDown Direction = iota
	DirectionUp
)

type TrafficCounters struct {
	BytesDown   int64
	BytesUp     int64
	PacketsDown int64
	PacketsUp   int64
	LastSeen    time.Time
}

type Device struct {
	IP            net.IP
	MAC           net.HardwareAddr
	Hostname      string
	IsGateway     bool
	IsLocal       bool
	Traffic       TrafficCounters
	CapDown       int64
	CapUp         int64
	Blocked       bool
	RateDown      float64
	RateUp        float64
	PrevBytesDown int64
	PrevBytesUp   int64
	PrevTime      time.Time
	RateLimitDown     float64
	RateLimitUp       float64
	TokensDown        float64
	TokensUp          float64
	TokenRefillAtDown time.Time
	TokenRefillAtUp   time.Time
}

type InterfaceInfo struct {
	Name       string
	MAC        net.HardwareAddr
	IPs        []net.IP
	IsUp       bool
	IsLoopback bool
	MTU        int
	Flags      net.Flags
}
