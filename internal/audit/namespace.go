package audit

import (
	"context"
	"fmt"

	"github.com/koitococo/docker-hardened-proxy/internal/docker"
)

// CheckContainer verifies that a container belongs to the configured namespace.
func CheckContainer(ctx context.Context, client docker.Client, containerID, namespace string) error {
	info, err := client.ContainerInspect(ctx, containerID)
	if err != nil {
		return fmt.Errorf("inspecting container %s: %w", containerID, err)
	}

	if info.Config == nil || info.Config.Labels == nil {
		return fmt.Errorf("container %s is not managed by this proxy", containerID)
	}

	ns, ok := info.Config.Labels[LabelNamespace]
	if !ok {
		return fmt.Errorf("container %s is not managed by this proxy", containerID)
	}

	if ns != namespace {
		return fmt.Errorf("container %s does not belong to this namespace", containerID)
	}

	return nil
}

// CheckExec resolves an exec ID to its container and verifies namespace ownership.
func CheckExec(ctx context.Context, client docker.Client, execID, namespace string) error {
	execInfo, err := client.ContainerExecInspect(ctx, execID)
	if err != nil {
		return fmt.Errorf("inspecting exec %s: %w", execID, err)
	}

	return CheckContainer(ctx, client, execInfo.ContainerID, namespace)
}
