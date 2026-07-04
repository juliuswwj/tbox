//go:build gomobiledeps

// This file is never compiled into any real build (the gomobiledeps tag is
// never set). It exists only to keep golang.org/x/mobile in go.mod/go.sum so
// that `gomobile bind` (see `make android`) works without re-running go mod
// tidy. gomobile's generated bindings import golang.org/x/mobile/bind.
package mobile

import (
	_ "golang.org/x/mobile/bind"
)
