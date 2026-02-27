package docker

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Client provides the subset of Docker API calls needed by the proxy.
type Client interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerExecInspect(ctx context.Context, execID string) (containertypes.ExecInspect, error)
}

// NewClient creates a Docker client connecting to the specified upstream.
// host should be a Docker-style host string, e.g. "unix:///var/run/docker.sock"
// or "tcp://127.0.0.1:2375".
// If tlsCfg is non-nil, the client uses HTTPS with the given TLS configuration.
func NewClient(host string, tlsCfg *tls.Config) (Client, error) {
	opts := []client.Opt{
		client.WithHost(host),
		client.WithAPIVersionNegotiation(),
	}

	if tlsCfg != nil {
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		}
		opts = append(opts, client.WithHTTPClient(httpClient), client.WithScheme("https"))
	}

	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, err
	}
	return cli, nil
}
