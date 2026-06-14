//go:build !linux

package l2

import (
	"errors"
	"log"
	"net"
)

// errUnsupported is returned by the TAP/netcfg/sysconfig helpers on non-Linux
// platforms. The frame codec, Switch, and UDP endpoint remain available so the
// package still builds for development on other OSes.
var errUnsupported = errors.New("l2: TAP/netcfg is only supported on linux")

// Device is a stub on non-Linux platforms.
type Device struct{}

func Open(string) (*Device, error)          { return nil, errUnsupported }
func (d *Device) Read([]byte) (int, error)  { return 0, errUnsupported }
func (d *Device) Write([]byte) (int, error) { return 0, errUnsupported }
func (d *Device) Name() string              { return "" }
func (d *Device) Close() error              { return nil }

func SetUp(string, int) error                    { return errUnsupported }
func AddAddr(string, string) error               { return errUnsupported }
func AddToBridge(string, string) error           { return errUnsupported }
func AddRoute(string, string) error              { return errUnsupported }
func AddDefaultRoute(string, string) error       { return errUnsupported }
func AddHostRouteViaCurrentGateway(string) error { return errUnsupported }

func EnableIPForward() error { return errUnsupported }

func EnsureMasquerade(string, string) (func() error, error) { return nil, errUnsupported }

// Passthrough is a no-op stub on non-Linux platforms.
type Passthrough struct{}

func NewPassthrough(string, *log.Logger) *Passthrough { return &Passthrough{} }
func (p *Passthrough) OnIPv6(net.IP)                  {}
