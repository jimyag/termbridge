package termbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func readAudit(t *testing.T, data []byte) []map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []map[string]any
	for {
		var record map[string]any
		err := decoder.Decode(&record)
		if err == io.EOF {
			return records
		}
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func TestAuditOperations(t *testing.T) {
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	cfg.Logging.File = filepath.Join(t.TempDir(), "logs", "audit.jsonl")
	cfg.Connections["credentials"] = connection{
		Type:            "jumpserver",
		URL:             "https://jump.example.com/api/v1",
		AccessKeyID:     "test-key",
		AccessKeySecret: "test-key-test-secret",
	}
	var stderr bytes.Buffer
	logger, file, err := newAuditLogger(cfg, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	terminal := newTerminal(cfg, http.DefaultClient)
	terminal.logger = logger
	defer terminal.shutdown()
	id, err := terminal.open(t.Context(), openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := terminal.run(t.Context(), id, "printf 'test-key-test-secret'; printf 'failure' >&2; exit 7")
	if err != nil || result.ExitCode != 7 {
		t.Fatalf("command error=%v exit=%d", err, result.ExitCode)
	}
	if _, err := terminal.open(t.Context(), openInput{
		Connection: "unknown",
		Host:       "other",
	}); err == nil {
		t.Fatal("unknown connection accepted")
	}
	if _, err := terminal.run(t.Context(), "unknown", "printf no"); err == nil {
		t.Fatal("unknown session accepted")
	}
	terminal.close(id)
	_, err = terminal.open(t.Context(), openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal.expire(time.Now().Add(idleTimeout + time.Second))
	id, err = terminal.open(t.Context(), openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal.shutdown()
	data, err := os.ReadFile(cfg.Logging.File)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "test-key") || strings.Contains(string(data), "-test-secret") {
		t.Fatal("credential present in audit log")
	}
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("audit permissions: %v", err)
	}
	var failedRun, unknownRun, rejected, expired, shutdown bool
	starts := map[string]bool{}
	for _, record := range readAudit(t, data) {
		operation, _ := record["operation_id"].(string)
		if operation == "" {
			t.Fatal("operation missing correlation ID")
		}
		if record["phase"] == "started" {
			starts[operation] = true
			continue
		}
		if !starts[operation] {
			t.Fatal("finished operation missing its start")
		}
		if _, ok := record["duration_ms"].(float64); !ok {
			t.Fatal("operation missing duration")
		}
		if record["event"] == "terminal.run" && record["exit_code"] == float64(7) {
			failedRun = record["command"] == "printf '[REDACTED]'; printf 'failure' >&2; exit 7" &&
				record["output"] == "[REDACTED]failure" && record["result_known"] == true && record["status"] == "failed"
		}
		if record["event"] == "terminal.run" && record["session_id"] == "unknown" {
			_, hasExit := record["exit_code"]
			unknownRun = !hasExit && record["result_known"] == false && record["status"] == "failed"
		}
		if record["event"] == "terminal.open" && record["connection"] == "unknown" {
			rejected = record["status"] == "failed"
		}
		if record["reason"] == "idle_timeout" {
			expired = true
		}
		if record["reason"] == "shutdown" && record["session_id"] == id {
			shutdown = true
		}
	}
	if !failedRun || !unknownRun || !rejected || !expired || !shutdown {
		t.Fatalf("missing audit results: run=%t unknown=%t rejected=%t expired=%t shutdown=%t", failedRun, unknownRun, rejected, expired, shutdown)
	}
}

func TestAuditPartialResult(t *testing.T) {
	var log bytes.Buffer
	logger, _, err := newAuditLogger(config{}, &log)
	if err != nil {
		t.Fatal(err)
	}
	link, err := startCommand([]string{"sh", "-c", `read -r request encoded; printf 'fixture %s begin\npartial\n' "$request"`})
	if err != nil {
		t.Fatal(err)
	}
	terminal := newTerminal(config{}, nil)
	terminal.logger = logger
	terminal.sessions["partial"] = sessionFixture(t, link)
	defer terminal.shutdown()
	result, err := terminal.run(t.Context(), "partial", "printf something")
	if err == nil || result.Output != "partial\n" {
		t.Fatalf("partial output lost: error=%v bytes=%d", err, len(result.Output))
	}
	records := readAudit(t, log.Bytes())
	last := records[len(records)-1]
	if _, found := last["exit_code"]; found || last["output"] != "partial\n" || last["result_known"] != false || last["session_closed"] != true {
		t.Fatal("incorrect unknown-result audit record")
	}
}

func TestAuditConcurrentAndRedaction(t *testing.T) {
	var stderr bytes.Buffer
	cfg := config{
		Connections: map[string]connection{
			"private": {
				AccessKeyID:     "test-key",
				AccessKeySecret: "test-key-test-secret",
			},
		},
		Logging: loggingConfig{File: filepath.Join(t.TempDir(), "audit.jsonl")},
	}
	logger, file, err := newAuditLogger(cfg, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var workers sync.WaitGroup
	for i := range 12 {
		workers.Go(func() {
			logger.Info("concurrent", "worker", i, "command", "printf test-key-test-secret", "output", "first\nsecond", "error", errors.New("test-key"))
		})
	}
	workers.Wait()
	logger.Info("boundary", "command", strings.Repeat("x", maxCommand-5)+"test-key")
	data, err := os.ReadFile(cfg.Logging.File)
	if err != nil {
		t.Fatal(err)
	}
	records := readAudit(t, data)
	if len(records) != 13 || bytes.Contains(data, []byte("test-key")) || bytes.Contains(stderr.Bytes(), []byte("test-key")) {
		t.Fatal("concurrent audit entries invalid or credential not redacted")
	}
	boundary := records[len(records)-1]["command"].(string)
	if len(boundary) > maxCommand || strings.Contains(boundary, "test-") {
		t.Fatal("redaction must precede truncation")
	}
}

func TestAuditRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"permissions", "symlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			switch kind {
			case "permissions":
				if err := os.WriteFile(path, []byte("original"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := path + ".target"
				if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			_, file, err := newAuditLogger(config{Logging: loggingConfig{File: path}}, io.Discard)
			if err == nil {
				if file != nil {
					_ = file.Close()
				}
				t.Fatal("unsafe audit file accepted")
			}
		})
	}
}

func TestAuditFileFailureUsesStderr(t *testing.T) {
	var stderr bytes.Buffer
	logger, file, err := newAuditLogger(config{Logging: loggingConfig{File: filepath.Join(t.TempDir(), "audit.jsonl")}}, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	logger.Info("still recorded", "event", "test.operation")
	records := readAudit(t, stderr.Bytes())
	if len(records) != 2 || records[0]["event"] != "logging.write" || records[1]["event"] != "test.operation" {
		t.Fatal("audit write failure did not preserve stderr records")
	}
}

func TestAuditLogCannotOverwriteConfiguration(t *testing.T) {
	for _, hardLink := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		logPath := path
		if hardLink {
			logPath = filepath.Join(dir, "linked.jsonl")
		}
		data, err := json.Marshal(config{
			Connections: map[string]connection{"direct": {Type: "ssh"}},
			Logging:     loggingConfig{File: logPath},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if hardLink {
			if err := os.Link(path, logPath); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := loadConfig(path); err == nil {
			t.Fatal("configuration file accepted as audit log")
		}
	}
}

func TestAuditCancellation(t *testing.T) {
	requests, input := io.Pipe()
	output, replies := io.Pipe()
	link := &terminalLink{
		input:  input,
		output: output,
		close:  func() { _ = input.Close(); _ = output.Close(); _ = requests.Close(); _ = replies.Close() },
	}
	var log bytes.Buffer
	logger, _, err := newAuditLogger(config{}, &log)
	if err != nil {
		t.Fatal(err)
	}
	terminal := newTerminal(config{}, nil)
	terminal.logger = logger
	terminal.sessions["cancelled"] = sessionFixture(t, link)
	defer terminal.shutdown()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := terminal.run(ctx, "cancelled", "printf partial; sleep 60"); done <- err }()
	buffer := make([]byte, 1024)
	if _, err := requests.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(replies, "fixture 1 begin\npartial\n"); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled command did not finish")
	}
	records := readAudit(t, log.Bytes())
	last := records[len(records)-1]
	if last["output"] != "partial\n" || last["result_known"] != false || last["status"] != "failed" {
		t.Fatal("cancelled command missing partial audit result")
	}
}

func TestMCPAudit(t *testing.T) {
	direct, known := nativeSSH(t)
	cfg := sshFixtureConfig(direct, known)
	cfg.Logging.File = filepath.Join(t.TempDir(), "mcp.jsonl")
	cfg.Connections["credentials"] = connection{
		Type:            "jumpserver",
		URL:             "https://jump.example.com/api/v1",
		AccessKeyID:     "test-access-key",
		AccessKeySecret: "test-access-secret",
	}
	client := commandClient(t, cfg)
	id := openSession(t, client, openInput{
		Connection: "machine",
		Host:       "127.0.0.1",
	})
	result := callTool[runResult](t, client, "terminal_run", runInput{
		SessionID: id,
		Command:   "printf test-access-secret",
	})
	if result.Output != "test-access-secret" || result.ExitCode != 0 {
		t.Fatal("MCP result changed by audit logging")
	}
	callTool[closeOutput](t, client, "terminal_close", closeInput{SessionID: id})
	data, err := os.ReadFile(cfg.Logging.File)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("test-access-secret")) {
		t.Fatal("MCP audit disclosed configured credential")
	}
	var recorded bool
	for _, record := range readAudit(t, data) {
		if record["event"] == "terminal.run" && record["phase"] == "finished" && record["session_id"] == id {
			recorded = record["command"] == "printf [REDACTED]" && record["output"] == "[REDACTED]" && record["exit_code"] == float64(0) && record["result_known"] == true
		}
	}
	if !recorded {
		t.Fatal("MCP audit missing command result")
	}
}
