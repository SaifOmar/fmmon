package engine

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Store interface {
	init(path string) error
	write(d *Device) error
	writeAll(devices []Device) error
	loadAll() []*Device
	writeSession(totalUp, totalDown int64, startTime time.Time)
	find(string) *Device
	saveDay(devices []Device, up, down int64, day, hostIP, gwIP string) error
	days() []string
	day(day string) (DaySnapshot, bool)
}

// @File
type FileStore struct {
	key string

	totalDown int64
	totalUp   int64
}

func (f *FileStore) init(path string) error {
	return nil
}
func (f *FileStore) find(path string) *Device {
	return nil
}

func (f *FileStore) write(d *Device) error {
	return nil
}
func (f *FileStore) writeAll(devices []Device) error {
	return nil
}
func (f *FileStore) loadAll() []*Device {
	return nil
}

func (f *FileStore) writeSession(totalUp, totalDown int64, startTime time.Time) {}

func (f *FileStore) saveDay([]Device, int64, int64, string, string, string) error { return nil }
func (f *FileStore) days() []string                                               { return nil }
func (f *FileStore) day(string) (DaySnapshot, bool)                               { return DaySnapshot{}, false }

// @Db
type DatabaseStore struct {
	DB *gorm.DB
	mu sync.Mutex
}

func (d *DatabaseStore) write(dev *Device) error {
	devSnapShot := toSnapshot(*dev)
	fmt.Printf("saving device to db: %s", dev.Name)
	d.DB.Save(&devSnapShot)
	return nil
}

// TODO: // increment values where possible
// bytes /sent/received .. etc
func (d *DatabaseStore) writeAll(devices []Device) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		for i := range devices {
			snap := toSnapshot(devices[i])
			if err := tx.Save(&snap).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *DatabaseStore) writeSession(totalUp, totalDown int64, startTime time.Time) {
	session := Session{}
	session.Started_At = startTime
	session.TotalDown = totalDown
	session.TotalUp = totalUp
	session.Ended_At = time.Now()
	d.DB.Create(&session)
}

func (d *DatabaseStore) saveDay(devs []Device, up, down int64, day, hostIP, gwIP string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	var snap DaySnapshot
	d.DB.Where("day = ?", day).Limit(1).Find(&snap)

	var prev DaySnapshot
	d.DB.Where("day < ?", day).Order("day desc").Limit(1).Find(&prev)
	hasPrev := prev.Day != ""
	if snap.Day == "" {
		snap = DaySnapshot{Day: day}
		if hasPrev {
			snap.LastTotalUp, snap.LastTotalDown = prev.LastTotalUp, prev.LastTotalDown
		}
	}
	snap.SavedAt = time.Now()

	if up >= snap.LastTotalUp {
		snap.TotalUp += up - snap.LastTotalUp
	}
	snap.LastTotalUp = up
	if down >= snap.LastTotalDown {
		snap.TotalDown += down - snap.LastTotalDown
	}
	snap.LastTotalDown = down

	idx := make(map[string]int, len(snap.Devices))
	for i := range snap.Devices {
		idx[snap.Devices[i].MAC] = i
	}
	for _, dev := range devs {
		mac := net.HardwareAddr(dev.MAC).String()
		if _, ok := idx[mac]; !ok {
			dd := DayDevice{MAC: mac}
			if hasPrev {
				for _, p := range prev.Devices {
					if p.MAC == mac {
						dd.LastSent, dd.LastRecv = p.LastSent, p.LastRecv
						break
					}
				}
			}
			idx[mac] = len(snap.Devices)
			snap.Devices = append(snap.Devices, dd)
		}
	}

	for _, dev := range devs {
		mac := net.HardwareAddr(dev.MAC).String()
		dd := &snap.Devices[idx[mac]]
		dd.Name, dd.IP, dd.Vendor = dev.Name, dev.IP.String(), dev.Vendor
		dd.Role = ""
		if dd.IP == hostIP {
			dd.Role = "host"
		} else if dd.IP == gwIP {
			dd.Role = "gateway"
		}
		dd.Reachable, dd.Blocked = dev.Reachable, dev.Blocked
		dd.UpRate, dd.DownRate = dev.UpRate, dev.DownRate
		dd.UpLimit, dd.DownLimit = dev.UpRateLimit, dev.DownRateLimit
		if dev.BytesSent >= dd.LastSent {
			dd.BytesSent += dev.BytesSent - dd.LastSent
		}
		dd.LastSent = dev.BytesSent
		if dev.BytesReceived >= dd.LastRecv {
			dd.BytesRecv += dev.BytesReceived - dd.LastRecv
		}
		dd.LastRecv = dev.BytesReceived
	}

	return d.DB.Save(&snap).Error
}

func (d *DatabaseStore) days() []string {
	var out []string
	d.DB.Model(&DaySnapshot{}).Order("day desc").Pluck("day", &out)
	return out
}

func (d *DatabaseStore) day(day string) (DaySnapshot, bool) {
	var snap DaySnapshot
	if d.DB.Where("day = ?", day).First(&snap).Error != nil {
		return snap, false
	}
	return snap, true
}

func (d *DatabaseStore) loadAll() []*Device {
	var snapshots []DeviceSnapShot

	result := d.DB.Find(&snapshots)
	if result.Error != nil {
		return nil
	}

	devices := make([]*Device, 0, len(snapshots))

	for _, snapshot := range snapshots {
		devices = append(devices, fromSnapshot(snapshot))
	}

	return devices
}

func (d *DatabaseStore) init(path string) error {
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	d.DB = db
	if err := db.AutoMigrate(&DeviceSnapShot{}, &Session{}, &DaySnapshot{}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (d *DatabaseStore) find(key string) *Device {
	dev := &Device{}
	res := d.DB.Where("id = ?", key).First(dev)
	if res.Error != nil {
		return nil
	}
	return dev
}

type Session struct {
	Started_At time.Time `json:"startedAt"`
	Ended_At   time.Time `json:"endedAt"`

	TotalUp   int64
	TotalDown int64
}

type DaySnapshot struct {
	Day           string `gorm:"primaryKey"`
	SavedAt       time.Time
	TotalUp       int64
	TotalDown     int64
	LastTotalUp   int64
	LastTotalDown int64
	Devices       []DayDevice `gorm:"serializer:json"`
}

type DayDevice struct {
	Name      string
	IP        string
	MAC       string
	Vendor    string
	Role      string
	Reachable bool
	Blocked   bool
	BytesSent int64
	BytesRecv int64
	LastSent  int64
	LastRecv  int64
	UpRate    float64
	DownRate  float64
	UpLimit   float64
	DownLimit float64
}

type DeviceSnapShot struct {
	/////////////////
	// @Gorm Specific
	/////////////////
	ID        string    `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	/////////////////

	Name          string    `json:"name" gorm:"column:name;null"`
	Vendor        string    `json:"vendor" gorm:"column:vendor;null"`
	IP            string    `json:"ip" gorm:"column:ip;not null"`
	MAC           string    `json:"mac" gorm:"column:mac;not null;uniqueIndex"`
	Interface     string    `json:"interface" gorm:"column:interface"`
	Reachable     bool      `json:"reachable" gorm:"column:reachable;not null;default:false"`
	lastMeasure   time.Time `json:"-" gorm:"last_measure"`
	BytesSent     int64     `json:"bytesSent" gorm:"column:bytes_sent;not null;default:0"`
	BytesReceived int64     `json:"bytesReceived" gorm:"column:bytes_received;not null;default:0"`
	prevBytesSent int64     `json:"-" gorm:"prev_bytes_sent"`
	prevBytesRecv int64     `json:"-" gorm:"prev_bytes_recv"`
	UpRate        float64   `json:"upRate" gorm:"column:up_rate;not null;default:0"`
	DownRate      float64   `json:"downRate" gorm:"column:down_rate;not null;default:0"`
	UpRateLimit   float64   `json:"upRateLimit" gorm:"column:up_rate_limit;not null;default:0"`
	DownRateLimit float64   `json:"downRateLimit" gorm:"column:down_rate_limit;not null;default:0"`
	Blocked       bool      `json:"blocked" gorm:"column:blocked;not null;default:false"`
	lastSeen      time.Time `json:"-" gorm:"last_seen"`
	IfaceFriendly string    `json:"ifaceFriendly" gorm:"column:iface_friendly"`
}

func fromSnapshot(d DeviceSnapShot) *Device {
	mac, _ := net.ParseMAC(d.MAC)
	return &Device{
		Name:          d.Name,
		Vendor:        d.Vendor,
		IP:            net.ParseIP(d.IP).To4(),
		MAC:           []byte(mac),
		Interface:     d.Interface,
		Reachable:     d.Reachable,
		lastMeasure:   d.lastMeasure,
		BytesSent:     d.BytesSent,
		BytesReceived: d.BytesReceived,
		prevBytesSent: d.prevBytesSent,
		prevBytesRecv: d.prevBytesRecv,
		UpRate:        d.UpRate,
		DownRate:      d.DownRate,
		UpRateLimit:   d.UpRateLimit,
		DownRateLimit: d.DownRateLimit,
		Blocked:       d.Blocked,
		lastSeen:      d.lastSeen,
		IfaceFriendly: d.IfaceFriendly,
	}
}

func toSnapshot(d Device) DeviceSnapShot {
	strinMac := net.HardwareAddr(d.MAC).String()
	return DeviceSnapShot{
		ID:            createDeviceHash("", strinMac),
		Name:          d.Name,
		Vendor:        d.Vendor,
		IP:            d.IP.String(),
		MAC:           strinMac,
		Interface:     d.Interface,
		Reachable:     d.Reachable,
		lastMeasure:   d.lastMeasure,
		BytesSent:     d.BytesSent,
		BytesReceived: d.BytesReceived,
		prevBytesSent: d.prevBytesSent,
		prevBytesRecv: d.prevBytesRecv,
		UpRate:        d.UpRate,
		DownRate:      d.DownRate,
		UpRateLimit:   d.UpRateLimit,
		DownRateLimit: d.DownRateLimit,
		Blocked:       d.Blocked,
		lastSeen:      d.lastSeen,
		IfaceFriendly: d.IfaceFriendly,
	}
}
