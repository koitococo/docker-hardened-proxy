package proxy

import (
	"context"
	"net"
	"net/http"
)

// NewUnixTransport creates an HTTP transport that dials the upstream Docker unix socket.
func NewUnixTransport(socketPath string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}
}
