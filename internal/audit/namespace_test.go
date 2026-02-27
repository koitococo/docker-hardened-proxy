package audit

import (
	"context"
	"fmt"
	"testing"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
)

type mockDockerClient struct {
	containers map[string]types.ContainerJSON
	execs      map[string]containertypes.ExecInspect
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, id string) (types.ContainerJSON, error) {
	c, ok := m.containers[id]
	if !ok {
		return types.ContainerJSON{}, fmt.Errorf("container not found: %s", id)
	}
	return c, nil
}

func (m *mockDockerClient) ContainerExecInspect(_ context.Context, id string) (containertypes.ExecInspect, error) {
	e, ok := m.execs[id]
	if !ok {
		return containertypes.ExecInspect{}, fmt.Errorf("exec not found: %s", id)
	}
	return e, nil
}

func TestCheckContainerOwned(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						LabelNamespace: "testns",
						LabelManagedBy: ManagedByValue,
					},
				},
			},
		},
	}

	err := CheckContainer(context.Background(), client, "abc123", "testns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckContainerWrongNamespace(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						LabelNamespace: "other",
					},
				},
			},
		},
	}

	err := CheckContainer(context.Background(), client, "abc123", "testns")
	if err == nil {
		t.Fatal("expected error for wrong namespace")
	}
}

func TestCheckContainerNotManaged(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{
					Labels: map[string]string{},
				},
			},
		},
	}

	err := CheckContainer(context.Background(), client, "abc123", "testns")
	if err == nil {
		t.Fatal("expected error for unmanaged container")
	}
}

func TestCheckContainerNoLabels(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{},
			},
		},
	}

	err := CheckContainer(context.Background(), client, "abc123", "testns")
	if err == nil {
		t.Fatal("expected error for container with no labels")
	}
}

func TestCheckContainerNotFound(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{},
	}

	err := CheckContainer(context.Background(), client, "missing", "testns")
	if err == nil {
		t.Fatal("expected error for missing container")
	}
}

func TestCheckExec(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						LabelNamespace: "testns",
						LabelManagedBy: ManagedByValue,
					},
				},
			},
		},
		execs: map[string]containertypes.ExecInspect{
			"exec456": {ContainerID: "abc123"},
		},
	}

	err := CheckExec(context.Background(), client, "exec456", "testns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckExecWrongNamespace(t *testing.T) {
	client := &mockDockerClient{
		containers: map[string]types.ContainerJSON{
			"abc123": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						LabelNamespace: "other",
					},
				},
			},
		},
		execs: map[string]containertypes.ExecInspect{
			"exec456": {ContainerID: "abc123"},
		},
	}

	err := CheckExec(context.Background(), client, "exec456", "testns")
	if err == nil {
		t.Fatal("expected error for exec in wrong namespace")
	}
}
