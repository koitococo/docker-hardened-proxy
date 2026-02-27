package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
)

// NewUpstreamTransport creates an HTTP transport that dials the upstream Docker daemon.
// network is "unix" or "tcp", address is the socket path or host:port.
// If tlsCfg is non-nil, TLS is used on the connection.
func NewUpstreamTransport(network, address string, tlsCfg *tls.Config) *http.Transport {
	t := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	if tlsCfg != nil {
		t.TLSClientConfig = tlsCfg
		// Override DialTLSContext so TLS is applied on our custom dial target,
		// not on the dummy "docker" host the Director sets.
		t.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			rawConn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			// Clone so we can set ServerName per-connection if needed
			cfg := tlsCfg.Clone()
			if cfg.ServerName == "" {
				host, _, _ := net.SplitHostPort(address)
				if host != "" {
					cfg.ServerName = host
				}
			}
			tlsConn := tls.Client(rawConn, cfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		}
		// Clear plain DialContext so the transport only uses DialTLSContext
		t.DialContext = nil
	}
	return t
}
