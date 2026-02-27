package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"

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
	h := newTestHandler(t, cfg, &mockDocker{})

	req := httptest.NewRequest("POST", "/session", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
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
