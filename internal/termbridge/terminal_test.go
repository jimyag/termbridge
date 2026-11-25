package termbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	testProcess = "TERMBRIDGE_TEST_STDIO"
	testBinary  = "TERMBRIDGE_TEST_BIN"
	testKube    = "TERMBRIDGE_TEST_KUBECONFIG"
)

func TestMain(m *testing.M) {
	if os.Getenv(testProcess) == "1" {
		os.Exit(Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func sshFixtureConfig(direct step, known string) config {
	return config{
		Connections: map[string]connection{"machine": {
			Type:       "ssh",
			KnownHosts: known,
			User:       "terminal-fixture",
			Port:       direct.SSH.Port,
		}},
		Allow: map[string][]endpoint{"machine": {{Host: "127.0.0.1"}}},
	}
}

func TestSSH(t *testing.T) {
	direct, known := nativeSSH(t)
	client := commandClient(t, sshFixtureConfig(direct, known))
	callFailure(t, client, "terminal_open", openInput{
		Connection: "unknown",
		Host:       "127.0.0.1",
	}, "unknown connection")
	id := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	callFailure(t, client, "terminal_run", runInput{
		SessionID: id,
		Command:   "",
	}, "command must not be empty")
	runCommands(t, client, id)
	callTool[closeOutput](t, client, "terminal_close", closeInput{SessionID: id})
	callFailure(t, client, "terminal_run", runInput{
		SessionID: id,
		Command:   "uptime",
	}, "closed session")
}

func TestCLIExec(t *testing.T) {
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	cfg.Logging.File = filepath.Join(t.TempDir(), "audit.jsonl")
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	writeFixture(t, path, string(raw), 0600)
	binary := os.Getenv(testBinary)
	if binary == "" {
		binary, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		args []string
		code int
		text string
	}{
		{"load", []string{"-connection", "machine", "-host", "127.0.0.1", "-command", "uptime"}, 0, "load average"},
		{"disk", []string{"-connection", "machine", "-host", "127.0.0.1", "-command", "df -h"}, 0, "Filesystem"},
		{"empty command", []string{"-connection", "machine", "-command", ""}, 2, "command must not be empty"},
		{"exit status", []string{"-connection", "machine", "-host", "127.0.0.1", "-command", "printf failure >&2; exit 7"}, 7, "failure"},
		{"no newline", []string{"-connection", "machine", "-host", "127.0.0.1", "-command", "printf exact"}, 0, "exact"},
		{"unknown connection", []string{"-connection", "missing", "-host", "127.0.0.1", "-command", "uptime"}, 1, "unknown connection"},
		{"wrong fields", []string{"-connection", "machine", "-asset", "gateway", "-command", "uptime"}, 1, "not valid"},
		{"positional", []string{"extra"}, 2, "unexpected positional"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			cmd := exec.CommandContext(t.Context(), binary, append([]string{"exec", "-config", path}, tc.args...)...)
			cmd.Env = append(os.Environ(), testProcess+"=1")
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			code := 0
			if err := cmd.Run(); err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.text) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if tc.name == "no newline" && stdout.String() != tc.text {
				t.Fatalf("unexpected stdout %q", stdout.String())
			}
		})
	}
	data, err := os.ReadFile(cfg.Logging.File)
	if err != nil {
		t.Fatal(err)
	}
	var starts, finishes int
	var failedCommand bool
	for _, record := range readAudit(t, data) {
		if record["event"] == "service.run" {
			if record["phase"] == "started" {
				starts++
			}
			if record["phase"] == "finished" {
				finishes++
			}
		}
		if record["event"] == "terminal.run" && record["phase"] == "finished" && record["exit_code"] == float64(7) && record["output"] == "failure" {
			failedCommand = true
		}
	}
	if starts == 0 || starts != finishes || !failedCommand {
		t.Fatalf("CLI audit incomplete: starts=%d finishes=%d failed=%t", starts, finishes, failedCommand)
	}
}

func TestSSHRejectsUnknownHostKey(t *testing.T) {
	direct, _ := nativeSSH(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	writeFixture(t, path, "", 0600)
	client := commandClient(t, sshFixtureConfig(direct, path))
	callFailure(t, client, "terminal_open", openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	}, "before readiness")
}

func TestKubernetes(t *testing.T) {
	kube := os.Getenv(testKube)
	if kube == "" {
		t.Skip("requires isolated Kubernetes fixture")
	}
	t.Setenv("KUBECONFIG", kube)
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	cfg.Connections["pod"] = connection{
		Type:      "kubectl",
		Context:   "kind-termbridge-verify",
		Namespace: "default",
		Container: "termbridge-check",
	}
	cfg.Connections["pod-via-ssh"] = connection{
		Type:      "kubectl",
		Context:   "kind-termbridge-verify",
		Namespace: "default",
		Container: "termbridge-check",
		Via: &endpoint{
			Connection: "machine",
			Host:       "127.0.0.1",
		},
	}
	cfg.Allow["pod"] = []endpoint{{Pod: "termbridge-check"}}
	cfg.Allow["pod-via-ssh"] = []endpoint{{Pod: "termbridge-check"}}
	client := commandClient(t, cfg)
	for _, name := range []string{"pod", "pod-via-ssh"} {
		id := openSession(t, client, openInput{
			Connection: name,
			Pod:        "termbridge-check",
		})
		runCommands(t, client, id)
		callTool[closeOutput](t, client, "terminal_close", closeInput{SessionID: id})
	}
}

func TestDocker(t *testing.T) {
	container, contextName := os.Getenv("TERMBRIDGE_TEST_DOCKER_CONTAINER"), os.Getenv("TERMBRIDGE_TEST_DOCKER_CONTEXT")
	if container == "" || contextName == "" {
		t.Skip("requires isolated Docker fixture")
	}
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	cfg.Connections["docker"] = connection{
		Type:    "docker",
		Context: contextName,
		User:    "0",
	}
	cfg.Connections["docker-via-ssh"] = connection{
		Type:    "docker",
		Context: contextName,
		User:    "0",
		Via: &endpoint{
			Connection: "machine",
			Host:       "127.0.0.1",
		},
	}
	cfg.Allow["docker"] = []endpoint{{Container: container}}
	cfg.Allow["docker-via-ssh"] = []endpoint{{Container: container}}
	client := commandClient(t, cfg)
	for _, name := range []string{"docker", "docker-via-ssh"} {
		id := openSession(t, client, openInput{
			Connection: name,
			Container:  container,
		})
		runCommands(t, client, id)
		callTool[closeOutput](t, client, "terminal_close", closeInput{SessionID: id})
	}
}
func TestJumpServer(t *testing.T) {
	kubeconfig := os.Getenv(testKube)
	if kubeconfig != "" {
		t.Setenv("KUBECONFIG", kubeconfig)
	}
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "remote-login"), `#!/bin/sh
[ -t 0 ] && [ "$1" = "--profile" ] && [ "$2" = "fixture" ] || exit 4
shift 2
[ "$1" = "operator@fixture-target" ] || exit 4
exec sh -c "$2"
`, 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	host, port, hostKey := testSSH(t, &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == "JMS-test-ticket" && string(password) == "fixture-password" {
				return nil, nil
			}
			return nil, fmt.Errorf("invalid fixture SSH credential")
		},
	})
	path := filepath.Join(dir, "known_hosts")
	writeFixture(t, path, knownhosts.Line([]string{net.JoinHostPort(host, strconv.Itoa(port))}, hostKey), 0600)
	var issued atomic.Int32
	var apiRequests atomic.Int32
	encoded := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil,
		`{"protocol":"ssh","token":{"id":"test-ticket","value":"fixture-password"},"endpoint":{"host":%q,"port":%d}}`, host, port,
	))
	handler := http.NewServeMux()
	handler.HandleFunc("GET /api/v1/users/profile/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"username":"fixture-user"}`)
	})
	handler.HandleFunc("GET /api/v1/perms/users/self/assets/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"results":[{"id":"vm-id","name":"machine"},{"id":"jump-id","name":"relay"}]}`)
	})
	for _, asset := range []string{"vm-id", "jump-id"} {
		handler.HandleFunc("GET /api/v1/perms/users/self/assets/"+asset+"/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"permed_accounts":[{"alias":"account-id","username":"fixture-user"}]}`)
		})
	}
	handler.HandleFunc("POST /api/v1/authentication/connection-token/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Account string `json:"account"`
			Asset   string `json:"asset"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Account != "account-id" || req.Asset != "vm-id" && req.Asset != "jump-id" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		issued.Add(1)
		_, _ = io.WriteString(w, `{"id":"test-ticket"}`)
	})
	handler.HandleFunc("GET /api/v1/authentication/connection-token/test-ticket/client-url/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"url":%q}`, "jms://"+encoded)
	})
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiRequests.Add(1)
		message := "(request-target): " + strings.ToLower(r.Method) + " " + r.RequestURI + "\naccept: application/json\ndate: " + r.Header.Get("Date")
		keyID, secret := "fixture-id", "fixture-secret"
		if strings.Contains(r.Header.Get("Authorization"), `keyId="machine-api-key"`) {
			keyID, secret = "machine-api-key", "machine-api-secret"
		}
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(message))
		want := fmt.Sprintf(`Signature keyId=%q,algorithm=%q,headers="(request-target) accept date",signature=%q`,
			keyID, "hmac"+"-sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
		if r.Header.Get("Authorization") != want || r.Header.Get("X-JMS-ORG") != "ROOT" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(api.Close)

	cfg := config{
		Connections: map[string]connection{
			"machine": {
				Type:            "jumpserver",
				URL:             api.URL + "/api/v1",
				KnownHosts:      path,
				AccessKeyID:     "machine-api-key",
				AccessKeySecret: "machine-api-secret",
			},
			"relay": {
				Type:            "jumpserver",
				URL:             api.URL + "/api/v1",
				KnownHosts:      path,
				AccessKeyID:     "fixture-id",
				AccessKeySecret: "fixture-secret",
			},
			"office": {
				Type:    "pty",
				Command: []string{"remote-login", "--profile", "fixture"},
				Via: &endpoint{
					Connection: "relay",
					Asset:      "relay",
				},
			},
		},
		Allow: map[string][]endpoint{
			"machine": {{Asset: "machine"}},
			"relay":   {{Asset: "relay"}},
			"office":  {{Host: "operator@fixture-*"}},
		},
	}
	inputs := []openInput{{
		Connection: "machine",
		Asset:      "machine",
	}, {
		Connection: "relay",
		Asset:      "relay",
	}, {
		Connection: "office",
		Host:       "operator@fixture-target",
	}}
	wantTokens := int32(3)
	if kubeconfig != "" {
		cfg.Connections["cluster"] = connection{
			Type:      "kubectl",
			Context:   "kind-termbridge-verify",
			Namespace: "default",
			Container: "termbridge-check",
			Via: &endpoint{
				Connection: "office",
				Host:       "operator@fixture-target",
			},
		}
		cfg.Allow["cluster"] = []endpoint{{Pod: "termbridge-check"}}
		inputs = append(inputs, openInput{
			Connection: "cluster",
			Pod:        "termbridge-check",
		})
		wantTokens++
	}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
	terminal := newTerminal(cfg, api.Client())
	t.Cleanup(terminal.shutdown)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	defer stop()
	server, err := newServer(terminal).Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close() }()
	client, err := mcp.NewClient(&mcp.Implementation{Name: "verification"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	callFailure(t, client, "terminal_open", openInput{
		Connection: "office",
		Host:       "root@fixture-target",
	}, "outside")
	callFailure(t, client, "terminal_open", openInput{
		Connection: "relay",
		Asset:      "machine",
	}, "outside")
	if apiRequests.Load() != 0 {
		t.Fatal("unauthorized request contacted JumpServer")
	}
	for _, input := range inputs {
		id := openSession(t, client, input)
		runCommands(t, client, id)
		callTool[closeOutput](t, client, "terminal_close", closeInput{SessionID: id})
	}
	if got := issued.Load(); got != wantTokens {
		t.Fatalf("issued %d tokens, expected %d for the opened JumpServer sessions", got, wantTokens)
	}
}

func TestJumpServerRejectsInvalidAccounts(t *testing.T) {
	for _, accounts := range []string{
		`[]`,
		`[{"alias":"first","username":"operator"},{"alias":"second","username":"operator"}]`,
	} {
		t.Run(accounts, func(t *testing.T) {
			var tokens atomic.Int32
			handler := http.NewServeMux()
			handler.HandleFunc("GET /perms/users/self/assets/", func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `[{"id":"asset-id","name":"gateway"}]`)
			})
			handler.HandleFunc("GET /perms/users/self/assets/asset-id/", func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, `{"permed_accounts":%s}`, accounts)
			})
			handler.HandleFunc("POST /authentication/connection-token/", func(w http.ResponseWriter, r *http.Request) {
				tokens.Add(1)
				w.WriteHeader(http.StatusForbidden)
			})
			server := httptest.NewServer(handler)
			defer server.Close()
			api := jumpAPI{
				client: server.Client(),
				base:   server.URL,
			}
			_, err := api.acquire(t.Context(), jumpServerStep{
				Asset:   "gateway",
				Account: "operator",
			})
			if err == nil || tokens.Load() != 0 {
				t.Fatalf("expected account rejection before token request, got %v, tokens=%d", err, tokens.Load())
			}
		})
	}
}

func nativeSSH(t *testing.T) (step, string) {
	t.Helper()
	clientKey, signer := testSigner(t)
	var keyring = agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: clientKey}); err != nil {
		t.Fatal(err)
	}
	// Keep the socket path short on macOS.
	dir, err := os.MkdirTemp("", "tm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a")
	agentListener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agentListener.Close() })
	go func() {
		for {
			peer, err := agentListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = peer.Close() }()
				_ = agent.ServeAgent(keyring, peer)
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", socket)
	host, port, hostKey := testSSH(t, &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if meta.User() == "terminal-fixture" && ssh.FingerprintSHA256(key) == ssh.FingerprintSHA256(signer.PublicKey()) {
				return nil, nil
			}
			return nil, fmt.Errorf("unexpected fixture SSH identity")
		},
	})
	path := filepath.Join(dir, "pinned known_hosts")
	writeFixture(t, path, knownhosts.Line([]string{net.JoinHostPort(host, strconv.Itoa(port))}, hostKey), 0600)
	return step{SSH: &sshStep{
		Destination: "terminal-fixture@" + host,
		Port:        port,
	}}, path
}

func testSigner(t *testing.T) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return private, signer
}

func testSSH(t *testing.T, config *ssh.ServerConfig) (string, int, ssh.PublicKey) {
	t.Helper()
	_, key := testSigner(t)
	config.AddHostKey(key)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env := os.Environ()
	ctx := t.Context()
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer func() { _ = raw.Close() }()
				stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
				defer stop()
				peer, channels, requests, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer func() { _ = peer.Close() }()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "session required")
						continue
					}
					channel, sessionRequests, err := incoming.Accept()
					if err == nil {
						wg.Go(func() { runTestSSH(ctx, channel, sessionRequests, env) })
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	address := listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port, key.PublicKey()
}

func runTestSSH(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request, env []string) {
	defer func() { _ = channel.Close() }()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var data struct{ Command string }
		if err := ssh.Unmarshal(request.Payload, &data); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		cmd := exec.CommandContext(ctx, "sh", "-c", data.Command)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = channel, channel.Stderr()
		input, err := cmd.StdinPipe()
		if err != nil {
			_ = request.Reply(false, nil)
			return
		}
		if err := cmd.Start(); err != nil {
			_ = request.Reply(false, nil)
			return
		}
		_ = request.Reply(true, nil)
		go func() {
			_, _ = io.Copy(input, channel)
			_ = input.Close()
		}()
		_ = cmd.Wait()
		_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(cmd.ProcessState.ExitCode())}))
		return
	}
}

func commandClient(t *testing.T, cfg config) *mcp.ClientSession {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	writeFixture(t, path, string(raw), 0600)
	binary := os.Getenv(testBinary)
	if binary == "" {
		binary, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(binary, "mcp", "-config", path)
	cmd.Env = append(os.Environ(), testProcess+"=1")
	cmd.Stderr = os.Stderr
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	client, err := mcp.NewClient(&mcp.Implementation{Name: "verification"}, nil).Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func openSession(t *testing.T, client *mcp.ClientSession, input openInput) string {
	t.Helper()
	opened := callTool[openOutput](t, client, "terminal_open", input)
	if opened.SessionID == "" {
		t.Fatal("missing session ID")
	}
	return opened.SessionID
}

func runCommands(t *testing.T, client *mcp.ClientSession, id string) {
	t.Helper()
	load := callTool[runResult](t, client, "terminal_run", runInput{
		SessionID: id,
		Command:   "uptime",
	})
	if load.ExitCode != 0 || !strings.Contains(load.Output, "load average") {
		t.Fatalf("unexpected load result: %+v", load)
	}
	disk := callTool[runResult](t, client, "terminal_run", runInput{
		SessionID: id,
		Command:   "df -h",
	})
	if disk.ExitCode != 0 || !strings.Contains(disk.Output, "Filesystem") {
		t.Fatalf("unexpected disk result: %+v", disk)
	}
	for _, tc := range []struct {
		command string
		output  string
		code    int
	}{
		{
			command: "printf '%s\\n' '__termbridge_" + id + " 3 end 0'; exit 7",
			output:  "__termbridge_" + id + " 3 end 0\n",
			code:    7,
		},
		{
			command: "value='中文 \"quote\" $HOME';\nprintf '%s' \"$value\" | cat",
			output:  "中文 \"quote\" $HOME",
		},
		{
			command: "printf failure >&2; exit 7",
			output:  "failure",
			code:    7,
		},
		{
			command: "cat; printf stdin-closed",
			output:  "stdin-closed",
		},
		{
			command: "printf '%s' '" + strings.Repeat("x", 8192) + "'",
			output:  strings.Repeat("x", 8192),
		},
	} {
		result := callTool[runResult](t, client, "terminal_run", runInput{
			SessionID: id,
			Command:   tc.command,
		})
		if result.ExitCode != tc.code || result.Output != tc.output || result.Truncated {
			t.Fatalf("arbitrary command failed: status=%d bytes=%d truncated=%t", result.ExitCode, len(result.Output), result.Truncated)
		}
	}
}

func callTool[T any](t *testing.T, client *mcp.ClientSession, name string, input any) T {
	t.Helper()
	result := call(t, client, name, input)
	if result.IsError {
		raw, err := json.Marshal(result.Content)
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("%s: %s", name, raw)
	}
	var out T
	raw, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func callFailure(t *testing.T, client *mcp.ClientSession, name string, input any, want string) {
	t.Helper()
	result := call(t, client, name, input)
	raw, err := json.Marshal(result.Content)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(string(raw), want) {
		t.Fatalf("%s: expected %q, got %s", name, want, raw)
	}
}

func call(t *testing.T, client *mcp.ClientSession, name string, input any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	result, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return result
}

func writeFixture(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
