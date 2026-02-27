package proxy

import (
	"context"
	"net"
	"net/http"
)

// NewUpstreamTransport creates an HTTP transport that dials the upstream Docker daemon.
// network is "unix" or "tcp", address is the socket path or host:port.
func NewUpstreamTransport(network, address string) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
}
