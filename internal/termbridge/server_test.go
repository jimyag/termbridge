package termbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s")
}

func waitService(t *testing.T, client *socketClient, done chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ticks := time.NewTicker(10 * time.Millisecond)
	defer ticks.Stop()
	for {
		result, err := client.call(ctx, "close", closeInput{SessionID: "readiness"})
		if err == nil && result.Error == "" {
			return
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("serve stopped before readiness: %v", err)
		case <-ctx.Done():
			t.Fatalf("serve not ready: %v", err)
		case <-ticks.C:
		}
	}
}

func startTestService(t *testing.T, terminal *terminal) (*socketClient, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	socket := testSocket(t)
	done := make(chan error, 1)
	go func() {
		err := serve(ctx, terminal, socket)
		terminal.shutdown()
		done <- err
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(8 * time.Second):
			t.Error("serve did not shut down")
		}
		if _, err := os.Lstat(socket); !os.IsNotExist(err) {
			t.Errorf("socket remains: %v", err)
		}
	})
	t.Cleanup(stop)
	client := newSocketClient(socket)
	t.Cleanup(client.http.CloseIdleConnections)
	waitService(t, client, done)
	return client, stop
}

func cliProcess(t *testing.T, socket string, args ...string) (string, string, int) {
	t.Helper()
	binary := os.Getenv(testBinary)
	if binary == "" {
		var err error
		binary, err = os.Executable()
		if err != nil {
			t.Fatal(err)
		}
	}
	args = append([]string{args[0], "--socket", socket}, args[1:]...)
	cmd := exec.CommandContext(t.Context(), binary, args...)
	cmd.Env = append(os.Environ(), testProcess+"=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestCLIProcessesReuseSession(t *testing.T) {
	direct, known := nativeSSH(t)
	client := commandClient(t, sshFixtureConfig(direct, known))
	id, stderr, code := cliProcess(t, client.socket, "open", "--connection", "machine", "--host", "127.0.0.1")
	if code != 0 || strings.TrimSpace(id) == "" || stderr != "" {
		t.Fatalf("open: %d %q %q", code, id, stderr)
	}
	id = strings.TrimSpace(id)
	first, stderr, code := cliProcess(t, client.socket, "run", "--session", id, "--command", `printf '%s' "$PPID"`)
	if code != 0 || first == "" || stderr != "" {
		t.Fatalf("first: %d %q %q", code, first, stderr)
	}
	second, stderr, code := cliProcess(t, client.socket, "run", "--session", id, "--command", `printf '%s' "$PPID"`)
	if code != 0 || second != first || stderr != "" {
		t.Fatalf("connection was not reused: %d %q %q, first=%q", code, second, stderr, first)
	}
	output, stderr, code := cliProcess(t, client.socket, "run", "--json", "--session", id, "--command", "printf failure; exit 7")
	var response rpcResponse
	var result runResult
	if err := json.Unmarshal([]byte(output), &response); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(response.Data, &result); err != nil {
		t.Fatal(err)
	}
	if code != 7 || stderr != "" || response.Error != "" || result.Output != "failure" || result.ExitCode != 7 {
		t.Fatalf("JSON result: %d %q %q", code, output, stderr)
	}
	for range 2 {
		output, stderr, code = cliProcess(t, client.socket, "close", "--session", id)
		if code != 0 || output != "" || stderr != "" {
			t.Fatalf("close: %d %q %q", code, output, stderr)
		}
	}
	_, stderr, code = cliProcess(t, client.socket, "run", "--session", id, "--command", "uptime")
	if code != 1 || !strings.Contains(stderr, "closed session") {
		t.Fatalf("closed session: %d %q", code, stderr)
	}
}

func TestCLIRequiresServiceAndValidArguments(t *testing.T) {
	socket := testSocket(t)
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"open", "--connection", "machine", "--host", "node"}, 1, "start 'termbridge serve'"},
		{[]string{"run", "--command", "uptime"}, 2, "session is required"},
		{[]string{"run", "--session", "id", "--command", ""}, 2, "command must not be empty"},
		{[]string{"close"}, 2, "session is required"},
		{[]string{"mcp"}, 2, "unknown command"},
		{[]string{"open", "--config", "unused"}, 2, "flag provided but not defined"},
	} {
		_, stderr, code := cliProcess(t, socket, tc.args...)
		if code != tc.code || !strings.Contains(stderr, tc.want) {
			t.Fatalf("%v: %d %q", tc.args, code, stderr)
		}
	}
}

func TestSocketRejectsUnsafeAndExistingPaths(t *testing.T) {
	for _, kind := range []string{"directory permissions", "directory symlink", "regular file", "socket symlink", "live socket", "stale socket"} {
		t.Run(kind, func(t *testing.T) {
			socket := testSocket(t)
			dir := filepath.Dir(socket)
			switch kind {
			case "directory permissions":
				if err := os.Chmod(dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory symlink":
				link := dir + "-link"
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(link) })
				socket = filepath.Join(link, "s")
			case "regular file":
				writeFixture(t, socket, "preserve", 0600)
			case "socket symlink":
				writeFixture(t, socket+"-target", "preserve", 0600)
				if err := os.Symlink(socket+"-target", socket); err != nil {
					t.Fatal(err)
				}
			case "live socket", "stale socket":
				listener, err := net.ListenUnix("unix", &net.UnixAddr{
					Net:  "unix",
					Name: socket,
				})
				if err != nil {
					t.Fatal(err)
				}
				listener.SetUnlinkOnClose(false)
				t.Cleanup(func() { _ = listener.Close() })
				if kind == "stale socket" {
					_ = listener.Close()
				}
			}
			before, _ := os.Lstat(socket)
			terminal := newTerminal(config{}, http.DefaultClient)
			if err := serve(t.Context(), terminal, socket); err == nil {
				t.Fatal("unsafe socket path accepted")
			}
			if before != nil {
				after, err := os.Lstat(socket)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("existing path changed: %v", err)
				}
			}
			if _, err := newSocketClient(socket).call(t.Context(), "close", closeInput{SessionID: "id"}); err == nil {
				t.Fatal("client accepted unsafe or unavailable socket")
			}
		})
	}
}

func TestServiceRejectsInvalidRequests(t *testing.T) {
	terminal := newTerminal(config{}, http.DefaultClient)
	client, _ := startTestService(t, terminal)
	for _, body := range []string{`{"session_id":"id","extra":true}`, `{"session_id":"id"} {}`, `{`, strings.Repeat(" ", 256<<10) + `{}`, `null`} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://termbridge/close", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var result rpcResponse
		err = json.NewDecoder(response.Body).Decode(&result)
		_ = response.Body.Close()
		if err != nil || result.Error == "" {
			t.Fatalf("invalid body accepted: %v %+v", err, result)
		}
	}
	for _, header := range []string{"Origin", "Host", "Content-Type"} {
		request := httptest.NewRequest(http.MethodPost, "http://termbridge/close", strings.NewReader(`{"session_id":"id"}`))
		request.Header.Set("Content-Type", "application/json")
		if header == "Host" {
			request.Host = "example.com"
		} else {
			request.Header.Set(header, "https://example.com")
		}
		writer := httptest.NewRecorder()
		terminalHandler(terminal).ServeHTTP(writer, request)
		if writer.Code != http.StatusForbidden {
			t.Fatalf("unsafe %s accepted: %d", header, writer.Code)
		}
	}
}

func TestServiceShutdownAndConcurrentSessions(t *testing.T) {
	direct, known := nativeSSH(t)
	terminal := newTerminal(sshFixtureConfig(direct, known), http.DefaultClient)
	client, stop := startTestService(t, terminal)
	first := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	second := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	marker := filepath.Join(t.TempDir(), "started")
	finished := make(chan rpcResponse, 1)
	go func() {
		result, _ := client.call(t.Context(), "run", runInput{
			SessionID: first,
			Command:   "printf started > " + shellCommand([]string{marker}) + "; printf partial; exec sleep 30",
		})
		finished <- result
	}()
	awaitFile(t, marker)
	result := callRPC[runResult](t, client, "run", runInput{
		SessionID: second,
		Command:   "printf independent",
	})
	if result.Output != "independent" {
		t.Fatalf("independent session blocked: %+v", result)
	}
	stop()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("in-flight request survived shutdown")
	}
	terminal.mu.Lock()
	defer terminal.mu.Unlock()
	if len(terminal.sessions) != 0 || !terminal.stopping {
		t.Fatal("shutdown retained sessions")
	}
}

func awaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticks := time.NewTicker(10 * time.Millisecond)
	defer ticks.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil && string(data) == "started" {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("command did not start")
		case <-ticks.C:
		}
	}
}

func TestClientCancellationClosesSession(t *testing.T) {
	direct, known := nativeSSH(t)
	terminal := newTerminal(sshFixtureConfig(direct, known), http.DefaultClient)
	client, _ := startTestService(t, terminal)
	id := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	marker := filepath.Join(t.TempDir(), "started")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.call(ctx, "run", runInput{
			SessionID: id,
			Command:   "printf started > " + shellCommand([]string{marker}) + "; exec sleep 30",
		})
		done <- err
	}()
	awaitFile(t, marker)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	terminal.mu.Lock()
	session := terminal.sessions[id]
	terminal.mu.Unlock()
	select {
	case <-session.done:
	case <-time.After(time.Second):
		t.Fatal("disconnected client left its command running")
	}
	callFailure(t, client, "run", runInput{
		SessionID: id,
		Command:   "printf must-not-run",
	}, "closed")
}

func TestConcurrentSocketCommandsStayInTheirSession(t *testing.T) {
	direct, known := nativeSSH(t)
	client := commandClient(t, sshFixtureConfig(direct, known))
	id := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	var group sync.WaitGroup
	for _, text := range []string{"first", "second", "third", "fourth"} {
		group.Go(func() {
			response, err := client.call(t.Context(), "run", runInput{
				SessionID: id,
				Command:   "printf " + text + "; sleep 0.02; printf done",
			})
			if err != nil || response.Error != "" {
				t.Errorf("concurrent run: %v %s", err, response.Error)
				return
			}
			var result runResult
			if err := json.Unmarshal(response.Data, &result); err != nil || result.Output != text+"done" || result.ExitCode != 0 {
				t.Errorf("mixed command output: %v %+v", err, result)
			}
		})
	}
	group.Wait()
}

func TestSocketPermissionsAndRestart(t *testing.T) {
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	client, stop := startTestService(t, newTerminal(cfg, http.DefaultClient))
	id := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	info, err := os.Lstat(client.socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	if err := os.Chmod(client.socket, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := client.call(t.Context(), "close", closeInput{SessionID: id}); err == nil {
		t.Fatal("client accepted world-writable socket")
	}
	if err := os.Chmod(client.socket, 0600); err != nil {
		t.Fatal(err)
	}
	stop()
	terminal := newTerminal(cfg, http.DefaultClient)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, terminal, client.socket) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		terminal.shutdown()
	})
	waitService(t, client, done)
	callFailure(t, client, "run", runInput{
		SessionID: id,
		Command:   "printf old-session-must-not-run",
	}, "unknown or closed")
}

func TestShutdownPreservesReplacementAtSocketPath(t *testing.T) {
	terminal := newTerminal(config{}, http.DefaultClient)
	socket := testSocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, terminal, socket) }()
	stop := sync.OnceFunc(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
		terminal.shutdown()
	})
	t.Cleanup(stop)
	client := newSocketClient(socket)
	waitService(t, client, done)
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, socket, "preserve replacement", 0600)
	stop()
	data, err := os.ReadFile(socket)
	if err != nil || string(data) != "preserve replacement" {
		t.Fatalf("replacement removed: %q %v", data, err)
	}
}
