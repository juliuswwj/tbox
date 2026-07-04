//go:build !linux

package control

import (
	"errors"

	"github.com/juliuswwj/tbox/internal/l2"
)

func (c *Client) runDHCP(ipDev string, tap *l2.ClientTAP) error {
	return errors.New("DHCP L2 tunnel is only supported on Linux")
}
