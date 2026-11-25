package termbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func TestExitZeroWithoutCompletionIsUnknown(t *testing.T) {
	link, err := startCommand([]string{"sh", "-c", `read -r request check; printf 'fixture %s begin\npartial output\n' "$request"; exit 0`})
	if err != nil {
		t.Fatal(err)
	}
	session := sessionFixture(t, link)
	_, err = session.run(t.Context(), "load")
	if err == nil || !strings.Contains(err.Error(), "result unknown") || !session.isClosed() {
		t.Fatalf("expected unknown result and closed connection, got %v", err)
	}
}

func TestConcurrentChecks(t *testing.T) {
	link, err := startCommand([]string{"sh", "-c", probeProgram, "fixture", "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	session := sessionFixture(t, link)
	var group sync.WaitGroup
	for _, check := range []string{"load", "disk"} {
		group.Go(func() {
			result, err := session.run(t.Context(), "printf '%s' "+check)
			if err != nil || result.Output != check {
				t.Errorf("%s got %+v, %v", check, result, err)
			}
		})
	}
	group.Wait()
}

func TestOutputIsBoundedAndCannotControlTerminal(t *testing.T) {
	script := `read -r request check
printf 'fixture %s begin\n\033%s\nfixture %s end 0\n' "$request" "$1" "$request"`
	link, err := startCommand([]string{"sh", "-c", script, "fixture", strings.Repeat("x", maxOutput+200)})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sessionFixture(t, link).run(t.Context(), "load")
	if err != nil || len(result.Output) != maxOutput || !result.Truncated || strings.ContainsRune(result.Output, '\x1b') {
		t.Fatalf("expected bounded plain text, got length %d, truncated %t, error %v", len(result.Output), result.Truncated, err)
	}
}

func TestCancelledCheckClosesConnection(t *testing.T) {
	requests, input := io.Pipe()
	output, replies := io.Pipe()
	link := &terminalLink{
		input:  input,
		output: output,
		close: func() {
			_ = input.Close()
			_ = output.Close()
			_ = requests.Close()
			_ = replies.Close()
		},
	}
	session := sessionFixture(t, link)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := session.run(ctx, "load")
		done <- err
	}()
	request, err := bufio.NewReader(requests).ReadString('\n')
	if err != nil || !strings.HasPrefix(request, "1 ") {
		t.Fatalf("unexpected request %q, %v", request, err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || !session.isClosed() {
			t.Fatalf("expected a cancelled check and a closed session, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not unblock the check")
	}
}

func TestIdleSessionExpires(t *testing.T) {
	link, err := startCommand([]string{"sh", "-c", "read -r line"})
	if err != nil {
		t.Fatal(err)
	}
	session := sessionFixture(t, link)
	terminal := newTerminal(config{}, nil)
	terminal.sessions["id"] = session
	terminal.expire(time.Now().Add(9 * time.Minute))
	if terminal.sessions["id"] != session || session.isClosed() {
		t.Fatal("session expired before ten minutes of idle time")
	}
	terminal.expire(time.Now().Add(10*time.Minute + time.Second))
	if _, err := terminal.run(t.Context(), "id", "load"); err == nil || !session.isClosed() {
		t.Fatalf("expired session was not removed and closed: %v", err)
	}
}

func TestPTYExitsOnInputEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-c", ptyProgram, "sh", "-c", `test -t 0 || exit 2; printf 'ready\n'; read -r line`)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("PTY program did not start: %q, %v", line, err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatal("PTY retained its child after input EOF")
	}
}

func TestArbitraryShellProtocol(t *testing.T) {
	for _, remotePTY := range []bool{false, true} {
		t.Run(fmt.Sprint(remotePTY), func(t *testing.T) {
			argv := []string{"sh", "-c", probeProgram, "fixture", "fixture"}
			if remotePTY {
				argv = append([]string{"python3", "-c", "import os, pty, sys; sys.exit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[1:])))"}, argv...)
			}
			link, err := startCommand(argv)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			stop := context.AfterFunc(ctx, link.close)
			defer stop()
			session := sessionFixture(t, link)
			line, err := session.reader.ReadString('\n')
			if err != nil || strings.TrimSpace(line) != "fixture ready" {
				t.Fatalf("readiness: %q %v", line, err)
			}
			for _, command := range []string{"", " ", string(rune(0)), strings.Repeat("x", maxCommand+1)} {
				if _, err := session.run(ctx, command); err == nil {
					t.Fatal("invalid command accepted")
				}
			}
			for _, tc := range []struct {
				command   string
				output    string
				code      int
				truncated bool
			}{
				{command: "printf '%s' '" + strings.Repeat("é", 8192) + "'", output: strings.Repeat("é", 8192)},
				{command: "cat <<'END'\nquoted '$HOME'\nEND\n", output: "quoted '$HOME'\n"},
				{command: "printf failure >&2; exit 9", output: "failure", code: 9},
				{command: "cat; printf next", output: "next"},
				{command: "head -c 32768 /dev/zero | tr '\\000' x", output: strings.Repeat("x", maxOutput)},
				{command: "head -c 200000 /dev/zero | tr '\\000' x", output: strings.Repeat("x", maxOutput), truncated: true},
				{command: "i=0; while [ $i -lt 12000 ]; do printf '中文'; i=$((i+1)); done", output: strings.Repeat("中文", maxOutput/6), truncated: true},
				{command: "printf 'after oversized output'", output: "after oversized output"},
				{command: "head -c 33023 /dev/zero | tr '\\000' '\\001'; printf '中文'", output: "中文"},
			} {
				result, err := session.run(ctx, tc.command)
				if err != nil || result.Output != tc.output || result.ExitCode != tc.code || result.Truncated != tc.truncated || !utf8.ValidString(result.Output) {
					t.Fatalf("command result: error=%v status=%d bytes=%d truncated=%t", err, result.ExitCode, len(result.Output), result.Truncated)
				}
			}
		})
	}
}

func sessionFixture(t *testing.T, link *terminalLink) *activeSession {
	t.Helper()
	s := &activeSession{
		link:      link,
		reader:    bufio.NewReaderSize(link.output, maxOutput+256),
		marker:    "fixture",
		gate:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		expiresAt: time.Now().Add(idleTimeout),
	}
	s.close = sync.OnceFunc(func() {
		close(s.done)
		link.close()
	})
	t.Cleanup(s.close)
	return s
}
