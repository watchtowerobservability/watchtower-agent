//go:build !windows

package container

import (
	"context"
	"errors"
	"net"
)

func dialPipe(context.Context, string) (net.Conn, error) {
	return nil, errors.New("named pipes exist only on Windows")
}
