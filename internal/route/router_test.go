package route

import (
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		path         string
		wantKind     EndpointKind
		wantID       string
		wantStripped string
	}{
		// Container create
		{"/containers/create", ContainerCreate, "", "/containers/create"},
		{"/v1.41/containers/create", ContainerCreate, "", "/containers/create"},
		{"/v1.45/containers/create?name=foo", ContainerCreate, "", "/containers/create?name=foo"},

		// Container list
		{"/containers/json", ContainerList, "", "/containers/json"},
		{"/v1.41/containers/json", ContainerList, "", "/containers/json"},

		// Container ops
		{"/containers/abc123/json", ContainerOp, "abc123", "/containers/abc123/json"},
		{"/v1.41/containers/abc123/json", ContainerOp, "abc123", "/containers/abc123/json"},
		{"/containers/abc123/start", ContainerOp, "abc123", "/containers/abc123/start"},
		{"/containers/abc123/stop", ContainerOp, "abc123", "/containers/abc123/stop"},
		{"/containers/abc123/kill", ContainerOp, "abc123", "/containers/abc123/kill"},
		{"/containers/abc123/restart", ContainerOp, "abc123", "/containers/abc123/restart"},
		{"/containers/abc123", ContainerOp, "abc123", "/containers/abc123"},
		{"/v1.41/containers/abc123/attach", ContainerOp, "abc123", "/containers/abc123/attach"},
		{"/v1.41/containers/abc123/logs", ContainerOp, "abc123", "/containers/abc123/logs"},

		// Exec create
		{"/containers/abc123/exec", ExecCreate, "abc123", "/containers/abc123/exec"},
		{"/v1.41/containers/abc123/exec", ExecCreate, "abc123", "/containers/abc123/exec"},

		// Exec ops
		{"/exec/def456/start", ExecOp, "def456", "/exec/def456/start"},
		{"/v1.41/exec/def456/start", ExecOp, "def456", "/exec/def456/start"},
		{"/exec/def456/json", ExecOp, "def456", "/exec/def456/json"},
		{"/exec/def456/resize", ExecOp, "def456", "/exec/def456/resize"},

		// Passthrough (allowlisted)
		{"/images/json", Passthrough, "", "/images/json"},
		{"/v1.41/images/json", Passthrough, "", "/images/json"},
		{"/images/create", Passthrough, "", "/images/create"},
		{"/images/abc123/json", Passthrough, "", "/images/abc123/json"},
		{"/images/abc123/tag", Passthrough, "", "/images/abc123/tag"},
		{"/version", Passthrough, "", "/version"},
		{"/info", Passthrough, "", "/info"},
		{"/_ping", Passthrough, "", "/_ping"},
		{"/", Passthrough, "", "/"},

		// Denied (dangerous endpoints)
		{"/build", Denied, "", "/build"},
		{"/commit", Denied, "", "/commit"},
		{"/events", Denied, "", "/events"},
		{"/volumes/create", Denied, "", "/volumes/create"},
		{"/networks/create", Denied, "", "/networks/create"},
		{"/swarm/init", Denied, "", "/swarm/init"},
		{"/services/create", Denied, "", "/services/create"},
		{"/images/prune", Denied, "", "/images/prune"},
		{"/v1.41/build", Denied, "", "/build"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			info := Parse(tt.path)
			if info.Kind != tt.wantKind {
				t.Errorf("Kind = %v, want %v", info.Kind, tt.wantKind)
			}
			if info.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", info.ID, tt.wantID)
			}
			if info.StrippedPath != tt.wantStripped {
				t.Errorf("StrippedPath = %q, want %q", info.StrippedPath, tt.wantStripped)
			}
		})
	}
}

func TestStripVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/v1.41/containers/json", "/containers/json"},
		{"/v1.45/info", "/info"},
		{"/containers/json", "/containers/json"},
		{"/version", "/version"},
		{"/v1.41", "/v1.41"},
		{"/vfoo/bar", "/vfoo/bar"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripVersion(tt.input)
			if got != tt.want {
				t.Errorf("stripVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEndpointKindString(t *testing.T) {
	tests := []struct {
		kind EndpointKind
		want string
	}{
		{Passthrough, "passthrough"},
		{ContainerCreate, "container_create"},
		{ContainerOp, "container_op"},
		{ContainerList, "container_list"},
		{ExecCreate, "exec_create"},
		{ExecOp, "exec_op"},
		{Denied, "denied"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("%d.String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}
