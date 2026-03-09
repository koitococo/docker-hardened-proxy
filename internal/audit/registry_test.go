package audit

import (
	"encoding/json"
	"testing"

	"github.com/koitococo/docker-hardened-proxy/internal/config"
)

func TestAuditAuth(t *testing.T) {
	tests := []struct {
		name          string
		policy        string
		allowed       []string
		serverAddress string
		wantDenied    bool
		wantReason    string
	}{
		{
			name:       "deny policy blocks all",
			policy:     "deny",
			wantDenied: true,
			wantReason: "registry authentication is denied by policy",
		},
		{
			name:          "allow policy allows all",
			policy:        "allow",
			serverAddress: "https://any.registry.com",
			wantDenied:    false,
		},
		{
			name:          "list policy allows matching prefix",
			policy:        "list",
			allowed:       []string{"https://registry.example.com", "docker.io"},
			serverAddress: "https://registry.example.com/v1/",
			wantDenied:    false,
		},
		{
			name:          "list policy denies non-matching",
			policy:        "list",
			allowed:       []string{"https://registry.example.com"},
			serverAddress: "https://other.registry.com",
			wantDenied:    true,
			wantReason:    "not in allowed list",
		},
		{
			name:       "list policy denies missing serveraddress",
			policy:     "list",
			allowed:    []string{"https://registry.example.com"},
			wantDenied: true,
			wantReason: "serveraddress is required",
		},
		{
			name:       "empty policy defaults to deny",
			policy:     "",
			wantDenied: true,
			wantReason: "denied by default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Audit: config.AuditConfig{
					Registry: config.RegistryConfig{
						Auth:        tt.policy,
						AuthAllowed: tt.allowed,
					},
				},
			}

			authReq := AuthRequest{
				Username:      "testuser",
				Password:      "testpass",
				ServerAddress: tt.serverAddress,
			}
			body, err := json.Marshal(authReq)
			if err != nil {
				t.Fatalf("failed to marshal auth request: %v", err)
			}

			result := AuditAuth(body, cfg)
			if result.Denied != tt.wantDenied {
				t.Errorf("AuditAuth() Denied = %v, want %v", result.Denied, tt.wantDenied)
			}
			if tt.wantReason != "" && !contains(result.Reason, tt.wantReason) {
				t.Errorf("AuditAuth() Reason = %q, want containing %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func TestAuditAuthInvalidJSON(t *testing.T) {
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Registry: config.RegistryConfig{
				Auth:        "list",
				AuthAllowed: []string{"https://registry.example.com"},
			},
		},
	}

	invalidBody := []byte("not valid json")
	result := AuditAuth(invalidBody, cfg)

	if !result.Denied {
		t.Error("AuditAuth() should deny invalid JSON")
	}
	if !contains(result.Reason, "invalid JSON") {
		t.Errorf("AuditAuth() Reason = %q, want containing 'invalid JSON'", result.Reason)
	}
}

func TestAuditPush(t *testing.T) {
	tests := []struct {
		name       string
		policy     string
		allowed    []string
		imageName  string
		wantDenied bool
		wantReason string
	}{
		{
			name:       "deny policy blocks all",
			policy:     "deny",
			wantDenied: true,
			wantReason: "image push is denied by policy",
		},
		{
			name:       "allow policy allows all",
			policy:     "allow",
			imageName:  "any/image:latest",
			wantDenied: false,
		},
		{
			name:       "list policy allows matching prefix",
			policy:     "list",
			allowed:    []string{"registry.example.com/myapp/", "myregistry.com/"},
			imageName:  "registry.example.com/myapp/backend:v1.0",
			wantDenied: false,
		},
		{
			name:       "list policy denies non-matching",
			policy:     "list",
			allowed:    []string{"registry.example.com/myapp/"},
			imageName:  "other.registry.com/image",
			wantDenied: true,
			wantReason: "not in allowed list",
		},
		{
			name:       "list policy denies missing name",
			policy:     "list",
			allowed:    []string{"registry.example.com/"},
			wantDenied: true,
			wantReason: "name parameter is required",
		},
		{
			name:       "empty policy defaults to deny",
			policy:     "",
			wantDenied: true,
			wantReason: "denied by default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Audit: config.AuditConfig{
					Registry: config.RegistryConfig{
						Push:        tt.policy,
						PushAllowed: tt.allowed,
					},
				},
			}

			result := AuditPush(tt.imageName, cfg)
			if result.Denied != tt.wantDenied {
				t.Errorf("AuditPush() Denied = %v, want %v", result.Denied, tt.wantDenied)
			}
			if tt.wantReason != "" && !contains(result.Reason, tt.wantReason) {
				t.Errorf("AuditPush() Reason = %q, want containing %q", result.Reason, tt.wantReason)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
