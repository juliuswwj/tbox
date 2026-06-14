//go:build linux

package l2

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Device is a Linux TAP interface (layer-2). Reads and writes carry raw
// Ethernet frames (opened with IFF_NO_PI, so no 4-byte packet-info prefix).
type Device struct {
	f    *os.File
	name string
}

// Open creates or attaches the named TAP device. The caller brings it up and
// assigns addresses via the netcfg helpers (SetUp/AddAddr/...).
func Open(name string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TAP | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF %q: %w", name, err)
	}
	return &Device{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: ifr.Name()}, nil
}

// Read returns one Ethernet frame.
func (d *Device) Read(p []byte) (int, error) { return d.f.Read(p) }

// Write sends one Ethernet frame.
func (d *Device) Write(p []byte) (int, error) { return d.f.Write(p) }

// Name returns the kernel-assigned interface name.
func (d *Device) Name() string { return d.name }

// Close removes the interface (the kernel drops its addresses and routes).
func (d *Device) Close() error { return d.f.Close() }
