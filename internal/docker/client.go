package docker

import (
	"context"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Client provides the subset of Docker API calls needed by the proxy.
type Client interface {
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	ContainerExecInspect(ctx context.Context, execID string) (containertypes.ExecInspect, error)
}

// NewClient creates a Docker client connecting to the specified unix socket.
func NewClient(socketPath string) (Client, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socketPath),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return cli, nil
}
