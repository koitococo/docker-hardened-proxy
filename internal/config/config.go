package config

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listeners ListenersConfig `yaml:"listeners"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Namespace string          `yaml:"namespace"`
	Audit     AuditConfig     `yaml:"audit"`
	Logging   LoggingConfig   `yaml:"logging"`
}

type ListenersConfig struct {
	TCP  *TCPListenerConfig  `yaml:"tcp,omitempty"`
	Unix *UnixListenerConfig `yaml:"unix,omitempty"`
}

type TCPListenerConfig struct {
	Address string `yaml:"address"`
}

type UnixListenerConfig struct {
	Path string      `yaml:"path"`
	Mode os.FileMode `yaml:"mode"`
}

type UpstreamConfig struct {
	URL string `yaml:"url"`
	// Parsed fields (not from YAML)
	Network string `yaml:"-"` // "unix" or "tcp"
	Address string `yaml:"-"` // socket path or host:port
}

type AuditConfig struct {
	DenyPrivileged     bool               `yaml:"deny_privileged"`
	DeniedCapabilities []string           `yaml:"denied_capabilities"`
	BindMounts         BindMountsConfig   `yaml:"bind_mounts"`
	Namespaces         NamespacesConfig   `yaml:"namespaces"`
}

type BindMountsConfig struct {
	DefaultAction string          `yaml:"default_action"`
	Rules         []BindMountRule `yaml:"rules"`
}

type BindMountRule struct {
	SourcePrefix  string `yaml:"source_prefix"`
	RewritePrefix string `yaml:"rewrite_prefix,omitempty"`
	Action        string `yaml:"action"`
}

type NamespacesConfig struct {
	NetworkMode NamespaceModeConfig `yaml:"network_mode"`
	IPCMode     NamespaceModeConfig `yaml:"ipc_mode"`
	PIDMode     NamespaceModeConfig `yaml:"pid_mode"`
	UTSMode     NamespaceModeConfig `yaml:"uts_mode"`
}

type NamespaceModeConfig struct {
	DenyHost bool `yaml:"deny_host"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listeners.TCP == nil && c.Listeners.Unix == nil {
		return fmt.Errorf("at least one listener (tcp or unix) must be configured")
	}
	if c.Upstream.URL == "" {
		return fmt.Errorf("upstream.url is required")
	}
	u, err := url.Parse(c.Upstream.URL)
	if err != nil {
		return fmt.Errorf("upstream.url is invalid: %w", err)
	}
	switch u.Scheme {
	case "unix":
		c.Upstream.Network = "unix"
		c.Upstream.Address = u.Path
		if c.Upstream.Address == "" {
			return fmt.Errorf("upstream.url unix:// requires a path")
		}
	case "tcp":
		c.Upstream.Network = "tcp"
		c.Upstream.Address = u.Host
		if c.Upstream.Address == "" {
			return fmt.Errorf("upstream.url tcp:// requires host:port")
		}
	default:
		return fmt.Errorf("upstream.url scheme must be unix:// or tcp://, got %q", u.Scheme)
	}
	if c.Namespace == "" {
		c.Namespace = "default"
	}
	action := c.Audit.BindMounts.DefaultAction
	if action != "" && action != "allow" && action != "deny" {
		return fmt.Errorf("audit.bind_mounts.default_action must be 'allow' or 'deny', got %q", action)
	}
	if action == "" {
		c.Audit.BindMounts.DefaultAction = "deny"
	}
	for i, rule := range c.Audit.BindMounts.Rules {
		if rule.SourcePrefix == "" {
			return fmt.Errorf("audit.bind_mounts.rules[%d].source_prefix is required", i)
		}
		if rule.Action != "allow" && rule.Action != "deny" {
			return fmt.Errorf("audit.bind_mounts.rules[%d].action must be 'allow' or 'deny', got %q", i, rule.Action)
		}
	}
	level := c.Logging.Level
	if level == "" {
		c.Logging.Level = "info"
	}
	format := c.Logging.Format
	if format == "" {
		c.Logging.Format = "json"
	}
	return nil
}
