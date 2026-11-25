package termbridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type config struct {
	Connections map[string]connection `json:"connections"`
	Allow       map[string][]endpoint `json:"allow"`
	Logging     loggingConfig         `json:"logging,omitempty"`
}

type loggingConfig struct {
	File string `json:"file,omitempty"`
}

type endpoint struct {
	Connection string `json:"connection" jsonschema:"Name of a configured connection"`
	Host       string `json:"host,omitempty"`
	Asset      string `json:"asset,omitempty"`
	Account    string `json:"account,omitempty"`
	User       string `json:"user,omitempty"`
	Port       int    `json:"port,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Pod        string `json:"pod,omitempty"`
	Container  string `json:"container,omitempty"`
}

type connection struct {
	Type            string    `json:"type"`
	Via             *endpoint `json:"via,omitempty"`
	User            string    `json:"user,omitempty"`
	Port            int       `json:"port,omitempty"`
	KnownHosts      string    `json:"known_hosts,omitempty"`
	IdentityFile    string    `json:"identity_file,omitempty"`
	Command         []string  `json:"command,omitempty"`
	URL             string    `json:"url,omitempty"`
	Org             string    `json:"org,omitempty"`
	AccessKeyID     string    `json:"access_key_id,omitempty"`
	AccessKeySecret string    `json:"access_key_secret,omitempty"`
	Context         string    `json:"context,omitempty"`
	Namespace       string    `json:"namespace,omitempty"`
	Container       string    `json:"container,omitempty"`
}

func (c *connection) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	var kind string
	if err := json.Unmarshal(fields["type"], &kind); err != nil {
		return errors.New("connection requires a type")
	}
	allowed := map[string]string{
		"ssh":        "user port known_hosts identity_file",
		"pty":        "user command",
		"jumpserver": "url org access_key_id access_key_secret known_hosts",
		"kubectl":    "context namespace container",
		"docker":     "context user",
	}
	keys, ok := allowed[kind]
	if !ok {
		return errors.New("unknown connection type")
	}
	for key := range fields {
		if !slices.Contains(strings.Fields("type via "+keys), key) {
			return fmt.Errorf("field %q is not valid for %s", key, kind)
		}
	}
	type plain connection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode((*plain)(c))
}

func loadConfig(path string) (config, error) {
	var cfg config
	file, err := os.Open(path)
	if err != nil {
		return cfg, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		var document any
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&document); err != nil {
			return cfg, errors.New("invalid YAML configuration")
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return cfg, errors.New("config requires one document")
		}
		data, err = json.Marshal(document)
		if err != nil {
			return cfg, errors.New("invalid YAML configuration")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("config requires one JSON object")
	}
	for name, item := range cfg.Connections {
		if item.Via == nil {
			for _, value := range []*string{&item.KnownHosts, &item.IdentityFile} {
				if *value != "" && !filepath.IsAbs(*value) {
					*value, err = filepath.Abs(filepath.Join(filepath.Dir(path), *value))
					if err != nil {
						return cfg, err
					}
				}
			}
		}
		cfg.Connections[name] = item
	}
	if cfg.Logging.File != "" && !filepath.IsAbs(cfg.Logging.File) {
		cfg.Logging.File, err = filepath.Abs(filepath.Join(filepath.Dir(path), cfg.Logging.File))
		if err != nil {
			return cfg, fmt.Errorf("resolve audit log path: %w", err)
		}
	}
	if cfg.Logging.File != "" {
		logInfo, err := os.Stat(cfg.Logging.File)
		if err != nil && !os.IsNotExist(err) {
			return cfg, fmt.Errorf("inspect audit log: %w", err)
		}
		if err == nil {
			configInfo, err := file.Stat()
			if err != nil {
				return cfg, err
			}
			if os.SameFile(configInfo, logInfo) {
				return cfg, errors.New("audit log must differ from the configuration file")
			}
		}
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	for _, item := range cfg.Connections {
		if item.Type == "jumpserver" {
			info, err := file.Stat()
			if err != nil {
				return cfg, err
			}
			if info.Mode().Perm()&0077 != 0 {
				return cfg, errors.New("configuration with credentials requires file permissions 0600")
			}
		}
	}
	return cfg, nil
}

func (c config) validate() error {
	if len(c.Connections) == 0 {
		return errors.New("config requires named connections")
	}
	for name, item := range c.Connections {
		if !targetName.MatchString(name) {
			return errors.New("invalid connection name")
		}
		switch item.Type {
		case "ssh":
			if item.Port < 0 || item.Port > 65535 || (item.User != "" && !targetName.MatchString(item.User)) {
				return fmt.Errorf("connection %q has invalid SSH settings", name)
			}
			if !printable(item.KnownHosts) || !printable(item.IdentityFile) {
				return errors.New("invalid SSH file path")
			}
		case "pty":
			if len(item.Command) == 0 || strings.TrimSpace(item.Command[0]) == "" {
				return fmt.Errorf("connection %q requires a command", name)
			}
			if item.User != "" && !targetName.MatchString(item.User) {
				return errors.New("invalid PTY user")
			}
			for _, arg := range item.Command {
				if strings.ContainsRune(arg, '\x00') {
					return errors.New("command arguments cannot contain NUL")
				}
			}
		case "jumpserver":
			u, err := url.Parse(item.URL)
			if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
				return errors.New("JumpServer requires an HTTPS API base URL")
			}
			if item.AccessKeyID == "" || item.AccessKeySecret == "" || !printable(item.AccessKeyID) || !printable(item.AccessKeySecret) || !printable(item.Org) || !printable(item.KnownHosts) {
				return errors.New("invalid JumpServer credentials or settings")
			}
			if item.Via != nil {
				return errors.New("JumpServer must be the first connection")
			}
		case "kubectl":
			if strings.TrimSpace(item.Context) == "" || !printable(item.Context) {
				return errors.New("kubectl requires a context")
			}
		case "docker":
			if strings.TrimSpace(item.Context) == "" || !printable(item.Context) {
				return errors.New("docker requires a context")
			}
			if item.User != "" && !dockerUser.MatchString(item.User) {
				return errors.New("invalid Docker user")
			}
		default:
			return errors.New("unknown connection type")
		}
		// Check each dependency independently, including connections with no public allow rules.
		seen := map[string]bool{name: true}
		parent := item.Via
		for parent != nil {
			if seen[parent.Connection] {
				return errors.New("connection via cycle")
			}
			seen[parent.Connection] = true
			upstream, ok := c.Connections[parent.Connection]
			if !ok {
				return errors.New("unknown via connection")
			}
			if _, err := upstream.prepare(*parent, false); err != nil {
				return fmt.Errorf("via of %q: %w", name, err)
			}
			parent = upstream.Via
		}
	}
	for name, rules := range c.Allow {
		item, ok := c.Connections[name]
		if !ok {
			return errors.New("allow references an unknown connection")
		}
		for _, rule := range rules {
			if rule.Connection != "" && rule.Connection != name {
				return errors.New("allow connection does not match its key")
			}
			if _, err := item.prepare(rule, true); err != nil {
				return fmt.Errorf("allow for %q: %w", name, err)
			}
		}
	}
	return nil
}

type jumpServerConfig struct {
	URL             string `json:"url"`
	Org             string `json:"org,omitempty"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	AccessKeySecret string `json:"access_key_secret,omitempty"`
}

type step struct {
	KnownHosts   string
	IdentityFile string
	PTYCommand   []string
	JumpConfig   *jumpServerConfig

	SSH        *sshStep        `json:"ssh,omitempty"`
	JumpServer *jumpServerStep `json:"jumpserver,omitempty"`
	PTY        string          `json:"pty,omitempty"`
	Kubectl    *kubectlStep    `json:"kubectl_exec,omitempty"`
	Docker     *dockerStep     `json:"docker_exec,omitempty"`
}

type sshStep struct {
	Destination string `json:"destination"`
	Port        int    `json:"port,omitempty"`
}

type jumpServerStep struct {
	Asset   string `json:"asset"`
	Account string `json:"account,omitempty"`
}

type kubectlStep struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

type dockerStep struct {
	Context   string `json:"context"`
	Container string `json:"container"`
	User      string `json:"user"`
}

var (
	targetName  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	destination = regexp.MustCompile(`^[A-Za-z0-9_:\[][A-Za-z0-9_.:@%\[\]-]*$`)
	kubeName    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	dockerUser  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$`)
)

func (s step) validate(index int, hasJumpServer bool) error {
	count := 0
	if s.SSH != nil {
		count++
		if !destination.MatchString(s.SSH.Destination) || s.SSH.Port < 0 || s.SSH.Port > 65535 {
			return errors.New("invalid SSH destination or port")
		}
	}
	if s.JumpServer != nil {
		count++
		if index != 0 || !hasJumpServer {
			return errors.New("JumpServer must be the first step and requires jumpserver settings")
		}
		if strings.TrimSpace(s.JumpServer.Asset) == "" || !printable(s.JumpServer.Asset) || !printable(s.JumpServer.Account) {
			return errors.New("invalid JumpServer asset or account")
		}
	}
	if s.PTY != "" {
		count++
		if !destination.MatchString(s.PTY) {
			return errors.New("invalid pty destination")
		}
	}
	if s.Kubectl != nil {
		count++
		if strings.TrimSpace(s.Kubectl.Context) == "" || !printable(s.Kubectl.Context) ||
			!kubeName.MatchString(s.Kubectl.Namespace) || !kubeName.MatchString(s.Kubectl.Pod) || !kubeName.MatchString(s.Kubectl.Container) {
			return errors.New("kubectl exec requires an explicit context, namespace, pod and container")
		}
	}
	if s.Docker != nil {
		count++
		if strings.TrimSpace(s.Docker.Context) == "" || !printable(s.Docker.Context) ||
			!targetName.MatchString(s.Docker.Container) || !dockerUser.MatchString(s.Docker.User) {
			return errors.New("docker exec requires an explicit context, container and user")
		}
	}
	if count != 1 {
		return errors.New("each step requires exactly one connection type")
	}
	return nil
}

func printable(value string) bool {
	for _, char := range value {
		if char < ' ' || char == '\x7f' {
			return false
		}
	}
	return true
}
