//go:build windows

package container

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

func dialPipe(ctx context.Context, pipe string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipe)
}
