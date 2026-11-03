package engine

import (
	"fmt"
	"net"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Store interface {
	init(path string) error
	write(d *Device) error
	loadAll() []*Device
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

func (f *FileStore) write(d *Device) error {
	return nil
}
func (f *FileStore) loadAll() []*Device {
	return nil
}

// @Db
type DatabaseStore struct {
	DB *gorm.DB
}

func (d *DatabaseStore) write(dev *Device) error {
	devSnapShot := toSnapshot(*dev)
	fmt.Printf("saving device to db: %s", dev.Name)
	d.DB.Save(&devSnapShot)
	return nil
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
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=busy_timeout(5000)"), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	d.DB = db
	if err := db.AutoMigrate(&DeviceSnapShot{}); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
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
	UpClass       string    `json:"upClass" gorm:"column:up_class"`
	DownClass     string    `json:"downClass" gorm:"column:down_class"`
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
		UpClass:       d.UpClass,
		DownClass:     d.DownClass,
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
		UpClass:       d.UpClass,
		DownClass:     d.DownClass,
		UpRateLimit:   d.UpRateLimit,
		DownRateLimit: d.DownRateLimit,
		Blocked:       d.Blocked,
		lastSeen:      d.lastSeen,
		IfaceFriendly: d.IfaceFriendly,
	}
}
