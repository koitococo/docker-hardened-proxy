package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	control "github.com/moby/buildkit/api/services/control"
	pb "github.com/moby/buildkit/solver/pb"
	"golang.org/x/net/http2"
	"google.golang.org/protobuf/proto"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

type mockDocker struct {
	containers map[string]types.ContainerJSON
	execs      map[string]containertypes.ExecInspect
}

func (m *mockDocker) ContainerInspect(_ context.Context, id string) (types.ContainerJSON, error) {
	c, ok := m.containers[id]
	if !ok {
		return types.ContainerJSON{}, fmt.Errorf("not found: %s", id)
	}
	return c, nil
}

func (m *mockDocker) ContainerExecInspect(_ context.Context, id string) (containertypes.ExecInspect, error) {
	e, ok := m.execs[id]
	if !ok {
		return containertypes.ExecInspect{}, fmt.Errorf("not found: %s", id)
	}
	return e, nil
}

func testCfg() *config.Config {
	return &config.Config{
		Namespace: "testns",
		Upstream:  config.UpstreamConfig{URL: "unix:///var/run/docker.sock", Network: "unix", Address: "/var/run/docker.sock"},
		Audit: config.AuditConfig{
			DenyPrivileged:     true,
			DeniedCapabilities: []string{"ALL", "SYS_ADMIN"},
			BindMounts: config.BindMountsConfig{
				DefaultAction: "deny",
				Rules: []config.BindMountRule{
					{SourcePrefix: "/home/ubuntu", RewritePrefix: "/mnt/home/ubuntu", Action: "allow"},
					{SourcePrefix: "/tmp", Action: "allow"},
				},
			},
			Namespaces: config.NamespacesConfig{
				NetworkMode: config.NamespaceModeConfig{DenyHost: true},
				IPCMode:     config.NamespaceModeConfig{DenyHost: true},
				PIDMode:     config.NamespaceModeConfig{DenyHost: true},
				UTSMode:     config.NamespaceModeConfig{DenyHost: true},
			},
		},
	}
}

// newTestHandler creates a Handler backed by a mock Docker client and a mock upstream.
func newTestHandler(t *testing.T, cfg *config.Config, dc *mockDocker) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Mock upstream: echo back request info
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  r.URL.RawQuery,
			"body":   string(body),
		})
	}))
	t.Cleanup(upstream.Close)

	rp := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = upstream.Listener.Addr().String()
		},
	}

	return &Handler{
		cfg:     cfg,
		reverse: rp,
		docker:  dc,
		logger:  logger,
	}
}

func TestHandlerContainerCreateDenyPrivileged(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerCreateDenyCapability(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine","HostConfig":{"CapAdd":["SYS_ADMIN"]}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerCreateDenyBindMount(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine","HostConfig":{"Binds":["/etc/passwd:/mnt/passwd"]}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerCreateDenyNetworkModeHost(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"host"}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerCreateDenyContainerModeForeign(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"foreign_ctr": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace": "other",
					},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"container:foreign_ctr"}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerCreateAllowContainerModeSameNamespace(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"owned_ctr": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace":  "testns",
						"ltkk.run/managed-by": "docker-hardened-proxy",
					},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	body := `{"Image":"alpine","HostConfig":{"NetworkMode":"container:owned_ctr"}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandlerContainerCreateAllowed(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine"}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Verify labels were injected in forwarded body
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	forwarded := resp["body"].(string)
	var parsed map[string]json.RawMessage
	json.Unmarshal([]byte(forwarded), &parsed)
	var labels map[string]string
	json.Unmarshal(parsed["Labels"], &labels)

	if labels["ltkk.run/namespace"] != "testns" {
		t.Errorf("namespace label = %q", labels["ltkk.run/namespace"])
	}
	if labels["ltkk.run/managed-by"] != "docker-hardened-proxy" {
		t.Errorf("managed-by label = %q", labels["ltkk.run/managed-by"])
	}
}

func TestHandlerContainerCreateBindRewrite(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	body := `{"Image":"alpine","HostConfig":{"Binds":["/home/ubuntu/project:/app"]}}`
	req := httptest.NewRequest("POST", "/v1.41/containers/create", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	forwarded := resp["body"].(string)
	var parsed map[string]json.RawMessage
	json.Unmarshal([]byte(forwarded), &parsed)
	var hc map[string]json.RawMessage
	json.Unmarshal(parsed["HostConfig"], &hc)
	var binds []string
	json.Unmarshal(hc["Binds"], &binds)

	if len(binds) != 1 || binds[0] != "/mnt/home/ubuntu/project:/app" {
		t.Errorf("binds = %v", binds)
	}
}

func TestHandlerContainerOpNamespaceCheck(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"owned": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace":  "testns",
						"ltkk.run/managed-by": "docker-hardened-proxy",
					},
				},
			},
			"foreign": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace": "other",
					},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	// Owned container — should pass
	req := httptest.NewRequest("POST", "/v1.41/containers/owned/start", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("owned start: status = %d, want %d", w.Code, http.StatusOK)
	}

	// Foreign container — should be denied
	req = httptest.NewRequest("POST", "/v1.41/containers/foreign/start", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("foreign start: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerContainerOpDenyUnmanaged(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"unmanaged": {
				Config: &containertypes.Config{
					Labels: map[string]string{},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	req := httptest.NewRequest("GET", "/v1.41/containers/unmanaged/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("unmanaged inspect: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerExecOpNamespaceCheck(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"ctr1": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace": "testns",
					},
				},
			},
		},
		execs: map[string]containertypes.ExecInspect{
			"exec1": {ContainerID: "ctr1"},
			"exec2": {ContainerID: "missing"},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	// Exec for owned container
	req := httptest.NewRequest("POST", "/v1.41/exec/exec1/start", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("owned exec: status = %d, want %d", w.Code, http.StatusOK)
	}

	// Exec for missing container
	req = httptest.NewRequest("POST", "/v1.41/exec/exec2/start", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("missing exec: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerExecCreateDenyPrivileged(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"ctr1": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace": "testns",
					},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	body := `{"Privileged":true,"Cmd":["/bin/sh"]}`
	req := httptest.NewRequest("POST", "/v1.41/containers/ctr1/exec", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("privileged exec: status = %d, want %d; body: %s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestHandlerExecCreateAllowed(t *testing.T) {
	dc := &mockDocker{
		containers: map[string]types.ContainerJSON{
			"ctr1": {
				Config: &containertypes.Config{
					Labels: map[string]string{
						"ltkk.run/namespace": "testns",
					},
				},
			},
		},
	}
	h := newTestHandler(t, testCfg(), dc)

	body := `{"Cmd":["/bin/sh"]}`
	req := httptest.NewRequest("POST", "/v1.41/containers/ctr1/exec", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("normal exec: status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandlerContainerList(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	req := httptest.NewRequest("GET", "/v1.41/containers/json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	// Verify namespace filter was injected
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	query := resp["query"].(string)

	if query == "" {
		t.Fatal("expected query to contain filters")
	}
}

func TestHandlerBuildDenyPolicy(t *testing.T) {
	cfg := testCfg()
	// default policy is "deny" (not set = zero value, but testCfg doesn't set it)
	cfg.Audit.Build.Policy = "deny"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/build?t=myimage", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerBuildAllowPolicy(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/build?t=myimage", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandlerBuildDenyNetworkModeHost(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/build?t=myimage&networkmode=host", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerBuildStripEntitlements(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/build?t=myimage&allow=network.host,security.insecure", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Verify the forwarded query doesn't contain the allow param
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	query := resp["query"].(string)
	if strings.Contains(query, "network.host") || strings.Contains(query, "security.insecure") {
		t.Errorf("forwarded query still contains dangerous entitlements: %s", query)
	}
}

func TestHandlerBuildListPolicy(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "list"
	cfg.Audit.Build.Allowed = []string{"myapp", "registry.example.com/"}
	h := newTestHandler(t, cfg, &mockDocker{})

	// Allowed tag
	req := httptest.NewRequest("POST", "/v1.41/build?t=myapp:v1", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("allowed tag: status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	// Denied tag
	req = httptest.NewRequest("POST", "/v1.41/build?t=other:v1", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied tag: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerBuildMethodNotAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("GET", "/v1.41/build", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlerSessionDenied(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	cfg.Audit.DenyBuildkit = true
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/session", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerSessionAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	cfg.Audit.DenyBuildkit = false
	cfg.Audit.BuildKit.Session.AllowFilesync = true
	cfg.Audit.BuildKit.Session.AllowUpload = true
	done := startBuildKitSessionUpstream(t, cfg)
	h := newTestHandler(t, cfg, &mockDocker{})
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)

	conn, reader, resp := openBuildKitUpgradeConn(t, server, "/session", http.Header{
		"X-Docker-Expose-Session-Grpc-Method": []string{"/moby.filesync.v1.FileSync/DiffCopy"},
	})
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusSwitchingProtocols)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write HTTP/2 preface: %v", err)
	}
	framer := http2.NewFramer(nil, reader)
	frame, err := framer.ReadFrame()
	if err != nil {
		t.Fatalf("read upstream settings: %v", err)
	}
	if _, ok := frame.(*http2.SettingsFrame); !ok {
		t.Fatalf("frame = %T, want *http2.SettingsFrame", frame)
	}
	if err := <-done; err != nil {
		t.Fatalf("mock upstream error: %v", err)
	}
}

func TestHandlerSessionDeniedByHeaders(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Build.Policy = "allow"
	cfg.Audit.DenyBuildkit = false
	cfg.Audit.BuildKit.Session.AllowFilesync = true
	cfg.Audit.BuildKit.Session.AllowUpload = true
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/session", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Add("X-Docker-Expose-Session-Grpc-Method", "/moby.buildkit.secrets.v1.Secrets/GetSecret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerSessionMethodNotAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyBuildkit = false
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest(http.MethodGet, "/session", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	req.Header.Add("X-Docker-Expose-Session-Grpc-Method", "/moby.filesync.v1.FileSync/DiffCopy")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlerSessionRequiresH2CUpgrade(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyBuildkit = false
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest(http.MethodPost, "/session", nil)
	req.Header.Add("X-Docker-Expose-Session-Grpc-Method", "/moby.filesync.v1.FileSync/DiffCopy")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandlerBuildKitControlMethodNotAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyBuildkit = false
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest(http.MethodGet, "/grpc", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "h2c")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandlerBuildKitControlRequiresH2CUpgrade(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyBuildkit = false
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest(http.MethodPost, "/grpc", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestBuildKitControlRequestDeniedMethod(t *testing.T) {
	cfg := testCfg()
	raw := buildBuildKitControlHeadersOnly(t, buildKitControlPruneMethod)

	result, err := auditBuildKitControlRequest(bytes.NewReader(raw), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected denied result")
	}
	if result.Reason != "buildkit control method \"/moby.buildkit.v1.Control/Prune\" is denied by policy" {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestBuildKitControlRequestDeniedUnsafeSolve(t *testing.T) {
	cfg := testCfg()
	payload := mustMarshalProto(t, &control.SolveRequest{Entitlements: []string{"network.host"}})
	raw := buildBuildKitControlUnaryRequest(t, buildKitControlSolveMethod, payload, 0, uint32(len(payload)), 0)

	result, err := auditBuildKitControlRequest(bytes.NewReader(raw), cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Denied {
		t.Fatal("expected denied result")
	}
	if result.Reason != "buildkit solve entitlement \"network.host\" is denied by policy" {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestBuildKitControlRequestAllowed(t *testing.T) {
	cfg := testCfg()
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "safe solve",
			raw: func() []byte {
				payload := mustMarshalProto(t, &control.SolveRequest{Definition: &pb.Definition{Def: [][]byte{mustMarshalProto(t, &pb.Op{Op: &pb.Op_Exec{Exec: &pb.ExecOp{}}})}}})
				return buildBuildKitControlUnaryRequest(t, buildKitControlSolveMethod, payload, 0, uint32(len(payload)), 0)
			}(),
		},
		{
			name: "status",
			raw:  buildBuildKitControlHeadersOnly(t, buildKitControlStatusMethod),
		},
		{
			name: "list workers",
			raw: func() []byte {
				payload := mustMarshalProto(t, &control.ListWorkersRequest{})
				return buildBuildKitControlUnaryRequest(t, buildKitControlListWorkersMethod, payload, 0, uint32(len(payload)), 0)
			}(),
		},
		{
			name: "info",
			raw: func() []byte {
				payload := mustMarshalProto(t, &control.InfoRequest{})
				return buildBuildKitControlUnaryRequest(t, buildKitControlInfoMethod, payload, 0, uint32(len(payload)), 0)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := auditBuildKitControlRequest(bytes.NewReader(tt.raw), cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Denied {
				t.Fatalf("unexpected deny: %s", result.Reason)
			}
		})
	}
}

func mustMarshalProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	payload, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal proto: %v", err)
	}
	return payload
}

func startBuildKitSessionUpstream(t *testing.T, cfg *config.Config) <-chan error {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg.Upstream.Network = "tcp"
	cfg.Upstream.Address = ln.Addr().String()
	t.Cleanup(func() { ln.Close() })

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		defer close(done)
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			done <- err
			return
		}

		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			done <- fmt.Errorf("read request: %w", err)
			return
		}
		if req.Method != http.MethodPost {
			done <- fmt.Errorf("method = %s, want POST", req.Method)
			return
		}
		if req.URL.Path != "/session" {
			done <- fmt.Errorf("path = %s, want /session", req.URL.Path)
			return
		}
		if req.Header.Get("Upgrade") != "h2c" {
			done <- fmt.Errorf("upgrade = %q, want h2c", req.Header.Get("Upgrade"))
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")); err != nil {
			done <- fmt.Errorf("write upgrade response: %w", err)
			return
		}
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(reader, preface); err != nil {
			done <- fmt.Errorf("read client preface: %w", err)
			return
		}
		if string(preface) != http2.ClientPreface {
			done <- fmt.Errorf("preface mismatch: %q", string(preface))
			return
		}
		framer := http2.NewFramer(conn, nil)
		if err := framer.WriteSettings(); err != nil {
			done <- fmt.Errorf("write settings: %w", err)
			return
		}
		done <- nil
	}()

	return done
}

func openBuildKitUpgradeConn(t *testing.T, server *httptest.Server, path string, headers http.Header) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()

	conn, err := net.Dial("tcp", server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("dial server: %v", err)
	}
	reader := bufio.NewReader(conn)
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n", path, server.Listener.Addr().String()); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	for key, values := range headers {
		for _, value := range values {
			if _, err := fmt.Fprintf(conn, "%s: %s\r\n", key, value); err != nil {
				t.Fatalf("write header %s: %v", key, err)
			}
		}
	}
	if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
		t.Fatalf("finish request: %v", err)
	}
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("read upgrade response: %v", err)
	}
	return conn, reader, resp
}

func TestHandlerPullDenyPolicy(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Pull.Policy = "deny"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/images/create?fromImage=alpine", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerPullAllowPolicy(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Pull.Policy = "allow"
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/v1.41/images/create?fromImage=alpine", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestHandlerPullListPolicy(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.Pull.Policy = "list"
	cfg.Audit.Pull.Allowed = []string{"alpine", "docker.io/library/"}
	h := newTestHandler(t, cfg, &mockDocker{})

	// Allowed
	req := httptest.NewRequest("POST", "/v1.41/images/create?fromImage=alpine", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("allowed pull: status = %d, want %d", w.Code, http.StatusOK)
	}

	// Denied
	req = httptest.NewRequest("POST", "/v1.41/images/create?fromImage=evilcorp/evil-image", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("denied pull: status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerPassthrough(t *testing.T) {
	h := newTestHandler(t, testCfg(), &mockDocker{})

	req := httptest.NewRequest("GET", "/v1.41/version", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestHandlerInfoDenied(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyInfo = true
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("GET", "/v1.41/info", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandlerInfoAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.Audit.DenyInfo = false
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("GET", "/v1.41/info", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestExtractImageNameFromPushPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "simple image with version",
			path:     "/v1.52/images/myimage/push",
			expected: "myimage",
		},
		{
			name:     "multi-segment image with version",
			path:     "/v1.52/images/registry.ltkk.run/slxd/operator/push",
			expected: "registry.ltkk.run/slxd/operator",
		},
		{
			name:     "with query string",
			path:     "/v1.52/images/myimage/push?tag=latest",
			expected: "myimage",
		},
		{
			name:     "multi-segment with query",
			path:     "/v1.52/images/registry.ltkk.run/slxd/operator/push?tag=latest",
			expected: "registry.ltkk.run/slxd/operator",
		},
		{
			name:     "without version prefix",
			path:     "/images/myimage/push",
			expected: "myimage",
		},
		{
			name:     "with tag in name",
			path:     "/v1.41/images/myimage:v1/push",
			expected: "myimage:v1",
		},
		{
			name:     "invalid path - no push",
			path:     "/v1.52/images/myimage/tag",
			expected: "",
		},
		{
			name:     "invalid path - too short",
			path:     "/v1.52/images/push",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractImageNameFromPushPath(tt.path)
			if result != tt.expected {
				t.Errorf("extractImageNameFromPushPath(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}
