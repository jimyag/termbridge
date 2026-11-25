package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func exampleConfig() config {
	return config{
		Connections: map[string]connection{
			"bastion": {
				Type:            "jumpserver",
				URL:             "https://jump.example.com/api/v1",
				AccessKeyID:     "test-id",
				AccessKeySecret: "test-secret",
			},
			"relay": {
				Type: "ssh",
				User: "operator",
				Via: &endpoint{
					Connection: "bastion",
					Asset:      "gateway",
					Account:    "operator",
				},
			},
			"office": {
				Type:    "pty",
				User:    "operator",
				Command: []string{"remote-login"},
				Via: &endpoint{
					Connection: "relay",
					Host:       "relay-host",
				},
			},
			"cluster": {
				Type:      "kubectl",
				Context:   "fixture",
				Namespace: "diagnostics",
				Container: "main",
				Via: &endpoint{
					Connection: "office",
					Host:       "cluster-admin",
				},
			},
			"containers": {
				Type:    "docker",
				Context: "fixture",
				User:    "1000",
				Via: &endpoint{
					Connection: "office",
					Host:       "docker-admin",
				},
			},
			"direct": {
				Type: "ssh",
				User: "operator",
			},
		},
		Allow: map[string][]endpoint{
			"bastion": {{
				Asset:   "gateway",
				Account: "operator",
			}},
			"relay":      {{Host: "relay-*"}},
			"office":     {{Host: "node-*"}},
			"cluster":    {{Pod: "app-*"}},
			"containers": {{Container: "worker-*"}},
			"direct":     {{Host: "*.example.com"}},
		},
	}
}

func TestNamedConnections(t *testing.T) {
	cfg := exampleConfig()
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		input endpoint
		count int
	}{
		{endpoint{
			Connection: "direct",
			Host:       "worker.example.com",
		}, 1},
		{endpoint{
			Connection: "bastion",
			Asset:      "gateway",
			Account:    "operator",
		}, 1},
		{endpoint{
			Connection: "relay",
			Host:       "relay-2",
		}, 2},
		{endpoint{
			Connection: "office",
			Host:       "node-1234",
		}, 3},
		{endpoint{
			Connection: "cluster",
			Pod:        "app-2",
		}, 4},
		{endpoint{
			Connection: "containers",
			Container:  "worker-2",
		}, 4},
	} {
		route, _, err := cfg.resolve(tc.input)
		if err != nil || len(route) != tc.count {
			t.Fatalf("%s: count=%d error=%v", tc.input.Connection, len(route), err)
		}
		if tc.input.Connection == "office" {
			if route[0].JumpConfig.AccessKeyID != "test-id" || route[1].SSH.Destination != "operator@relay-host" || route[2].PTY != "operator@node-1234" {
				t.Fatal("incorrect connection expansion")
			}
		}
	}
	route, _, err := cfg.resolve(endpoint{
		Connection: "cluster",
		Pod:        "app-2",
	})
	if err != nil || !reflect.DeepEqual(route[3].Kubectl, &kubectlStep{
		Context:   "fixture",
		Namespace: "diagnostics",
		Pod:       "app-2",
		Container: "main",
	}) {
		t.Fatalf("defaults: %v", err)
	}
}

func TestDestinationAccess(t *testing.T) {
	cfg := exampleConfig()
	for _, input := range []endpoint{
		{
			Connection: "missing",
			Host:       "worker.example.com",
		},
		{
			Connection: "direct",
			Host:       "other.invalid",
		},
		{
			Connection: "direct",
			Host:       "-flag",
		},
		{
			Connection: "direct",
			Host:       "worker.example.com",
			User:       "root",
		},
		{
			Connection: "direct",
			Host:       "worker.example.com",
			Port:       2222,
		},
		{
			Connection: "direct",
			Host:       "worker.example.com",
			Asset:      "gateway",
		},
		{
			Connection: "cluster",
			Pod:        "app-1",
			Namespace:  "other",
		},
		{
			Connection: "cluster",
			Pod:        "app-1",
			Container:  "sidecar",
		},
		{
			Connection: "containers",
			Container:  "worker-1",
			User:       "0",
		},
		{
			Connection: "containers",
			Container:  "-flag",
		},
		{
			Connection: "containers",
			Container:  "worker-1",
			User:       ":1000",
		},
	} {
		if _, _, err := cfg.resolve(input); err == nil {
			t.Fatalf("accepted forbidden destination %+v", input)
		}
	}
}

func TestInvalidConnections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*config)
	}{
		{"missing predecessor", func(c *config) {
			x := c.Connections["office"]
			x.Via = &endpoint{
				Connection: "missing",
				Host:       "gateway",
			}
			c.Connections["office"] = x
		}},
		{"cycle", func(c *config) {
			x := c.Connections["relay"]
			x.Via = &endpoint{
				Connection: "office",
				Host:       "node-1",
			}
			c.Connections["relay"] = x
		}},
		{"wildcard predecessor", func(c *config) {
			x := c.Connections["office"]
			x.Via = &endpoint{
				Connection: "relay",
				Host:       "relay-*",
			}
			c.Connections["office"] = x
		}},
		{"wrong predecessor fields", func(c *config) {
			x := c.Connections["office"]
			x.Via = &endpoint{
				Connection: "relay",
				Pod:        "app-1",
			}
			c.Connections["office"] = x
		}},
		{"nested bastion", func(c *config) {
			x := c.Connections["bastion"]
			x.Via = &endpoint{
				Connection: "direct",
				Host:       "gateway.example.com",
			}
			c.Connections["bastion"] = x
		}},
		{"missing credential", func(c *config) { x := c.Connections["bastion"]; x.AccessKeySecret = ""; c.Connections["bastion"] = x }},
		{"empty wrapper", func(c *config) { x := c.Connections["office"]; x.Command = nil; c.Connections["office"] = x }},
		{"NUL argument", func(c *config) {
			x := c.Connections["office"]
			x.Command = []string{"remote-login", string(rune(0))}
			c.Connections["office"] = x
		}},
		{"unknown authorization", func(c *config) { c.Allow["missing"] = []endpoint{{Host: "node-1"}} }},
		{"wildcard Pod container", func(c *config) {
			c.Allow["cluster"] = []endpoint{{
				Pod:       "app-1",
				Container: "main-*",
			}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exampleConfig()
			tc.change(&cfg)
			if err := cfg.validate(); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"valid.yaml", "connections:\n  direct:\n    type: ssh\n    user: operator\nallow:\n  direct:\n    - host: '*.example.com'\n", true},
		{"valid.json", `{"connections":{"direct":{"type":"ssh"}},"allow":{"direct":[{"host":"worker.example.com"}]}}`, true},
		{"wrong-type.json", `{"connections":{"direct":{"type":"ssh","access_key_secret":"private-value"}}}`, false},
		{"unknown-via.json", `{"connections":{"direct":{"type":"ssh"},"nested":{"type":"ssh","via":{"connection":"direct","host":"relay","typo":true}}}}`, false},
		{"unknown-field.yaml", "connections:\n  direct:\n    type: ssh\n    typo: private-value\n", false},
		{"duplicate.yaml", "connections:\n  direct:\n    type: ssh\n  direct:\n    type: pty\n", false},
		{"multiple.yaml", "connections: {}\n---\nconnections: {}\n", false},
		{"multiple.json", `{"connections":{}} {}`, false},
		{"old.json", `{"allow":[{"ssh":{"destination":"worker.example.com"}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfig(path)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t error=%v", tc.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "private-value") {
				t.Fatal("credential value leaked in error")
			}
		})
	}
}

func TestRejectsOversizedRouteBeforeConnect(t *testing.T) {
	route := make([]step, 24)
	for i := range route {
		route[i] = step{SSH: &sshStep{Destination: "operator@127.0.0.1"}}
	}
	link, err := startRoute(t.Context(), nil, route, "fixture")
	if link != nil {
		link.close()
	}
	if err == nil || !strings.Contains(err.Error(), "route command exceeds") {
		t.Fatalf("size bound: %v", err)
	}
}

func TestCredentialConfigPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(exampleConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("expected credential permission rejection, got %v", err)
	}
}
