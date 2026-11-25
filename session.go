package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	openTimeout    = 30 * time.Second
	commandTimeout = 20 * time.Second
	idleTimeout    = 10 * time.Minute
	maxOutput      = 32 << 10
	maxCommand     = 32 << 10
)

const probeProgram = `marker="$1"
if [ -t 0 ]; then
	stty -echo -icanon min 1 time 0 || exit
fi
printf '%s ready\n' "$marker"
while IFS=' ' read -r request encoded extra; do
	case "$request" in ""|*[!0-9]*) continue ;; esac
	[ -z "$extra" ] || continue
	printf '%s %s begin\n' "$marker" "$request"
	command=$(printf '%b_' "$encoded")
	command=${command%_}
	status=0
	sh -c "$command" </dev/null 2>&1 || status=$?
	printf '\n%s %s end %s\n' "$marker" "$request" "$status"
done`

type runResult struct {
	Output    string `json:"output"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}

type activeSession struct {
	link      *terminalLink
	reader    *bufio.Reader
	marker    string
	target    string
	gate      chan struct{}
	done      chan struct{}
	close     func()
	expiresAt time.Time
	nextID    uint64
}

type terminal struct {
	config     config
	logger     *slog.Logger
	httpClient *http.Client
	mu         sync.Mutex
	sessions   map[string]*activeSession
	stopping   bool
}

func newTerminal(cfg config, client *http.Client) *terminal {
	return &terminal{
		config:     cfg,
		logger:     slog.Default(),
		httpClient: client,
		sessions:   make(map[string]*activeSession),
	}
}

func (t *terminal) open(ctx context.Context, in openInput) (id string, err error) {
	logger, started := beginOperation(t.logger, "terminal.open",
		"connection", in.Connection, "host", in.Host, "asset", in.Asset, "account", in.Account,
		"user", in.User, "port", in.Port, "namespace", in.Namespace, "pod", in.Pod, "container", in.Container)
	defer func() { finishOperation(logger, started, err, "session_id", id) }()
	route, target, err := t.config.resolve(in)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()

	logger = logger.With("target", target)
	id = rand.Text()
	marker := "__termbridge_" + rand.Text()
	link, err := startRoute(ctx, t.httpClient, route, marker)
	if err != nil {
		return "", err
	}
	stop := context.AfterFunc(ctx, link.close)
	reader := bufio.NewReaderSize(link.output, maxOutput+256)
	var ready bool
	var fragment bool
	for {
		line, err := reader.ReadSlice('\n')
		if err == nil && !fragment && strings.TrimRight(string(line), "\r\n") == marker+" ready" {
			ready = true
			break
		}
		fragment = errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !fragment {
			break
		}
	}
	stop()
	if err := ctx.Err(); err != nil {
		link.close()
		return "", fmt.Errorf("open terminal: %w", err)
	}
	if !ready {
		link.close()
		return "", errors.New("terminal ended before readiness")
	}

	session := &activeSession{
		link:      link,
		reader:    reader,
		marker:    marker,
		target:    target,
		gate:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		expiresAt: time.Now().Add(idleTimeout),
	}
	session.close = sync.OnceFunc(func() {
		close(session.done)
		link.close()
	})
	t.mu.Lock()
	if t.stopping {
		t.mu.Unlock()
		session.close()
		return "", errors.New("terminal server is stopping")
	}
	t.sessions[id] = session
	t.mu.Unlock()
	return id, nil
}

func (t *terminal) run(ctx context.Context, id, command string) (result runResult, err error) {
	logger, started := beginOperation(t.logger, "terminal.run", "session_id", id, "command", command,
		"command_bytes", len(command), "command_truncated", len(command) > maxCommand)
	var session *activeSession
	defer func() {
		attrs := []any{"output", result.Output, "output_bytes", len(result.Output), "truncated", result.Truncated, "result_known", err == nil}
		if err == nil {
			attrs = append(attrs, "exit_code", result.ExitCode)
		}
		if session != nil {
			attrs = append(attrs, "session_closed", session.isClosed())
		}
		logErr := err
		if logErr == nil && result.ExitCode != 0 {
			logErr = fmt.Errorf("command exited with status %d", result.ExitCode)
		}
		finishOperation(logger, started, logErr, attrs...)
	}()
	t.mu.Lock()
	session, ok := t.sessions[id]
	t.mu.Unlock()
	if !ok {
		return runResult{}, errors.New("unknown or closed session")
	}
	logger = logger.With("target", session.target)
	return session.run(ctx, command)
}

func validateCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("command must not be empty")
	}
	if strings.ContainsRune(command, '\x00') || len(command) > maxCommand {
		return errors.New("command must contain no NUL and fit within 32 KiB")
	}
	return nil
}

func (s *activeSession) run(ctx context.Context, command string) (runResult, error) {
	if err := validateCommand(command); err != nil {
		return runResult{}, err
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	case <-s.done:
		return runResult{}, errors.New("session closed")
	case <-ctx.Done():
		return runResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return runResult{}, err
	}
	if s.isClosed() || !time.Now().Before(s.expiresAt) {
		s.close()
		return runResult{}, errors.New("session closed or expired")
	}

	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, s.close)
	result, err := s.exchange(command)
	stop()
	if ctx.Err() != nil {
		s.close()
		return result, fmt.Errorf("command interrupted, reopen the session: %w", ctx.Err())
	}
	if err != nil {
		s.close()
		return result, err
	}
	s.expiresAt = time.Now().Add(idleTimeout)
	return result, nil
}

func (s *activeSession) exchange(command string) (runResult, error) {
	s.nextID++
	id := strconv.FormatUint(s.nextID, 10)
	var encoded strings.Builder
	for i := range len(command) {
		fmt.Fprintf(&encoded, "\\0%03o", command[i])
	}
	if _, err := fmt.Fprintf(s.link.input, "%s %s\n", id, encoded.String()); err != nil {
		return runResult{}, errors.New("could not send command, reopen the session")
	}
	prefix := s.marker + " " + id
	begin, end := prefix+" begin", prefix+" end "
	var output strings.Builder
	var result runResult
	var started bool
	var fragment bool
	var pendingNewline bool
	var partialRune string
	for {
		data, err := s.reader.ReadSlice('\n')
		line := strings.TrimRight(string(data), "\r\n")
		if !started {
			started = err == nil && !fragment && line == begin
			fragment = errors.Is(err, bufio.ErrBufferFull)
			if err != nil && !fragment {
				break
			}
			continue
		}
		if code, ok := strings.CutPrefix(line, end); ok && !fragment && err == nil {
			exitCode, err := strconv.Atoi(code)
			if err != nil || exitCode < 0 || exitCode > 255 {
				result.Output = output.String()
				return result, errors.New("invalid terminal completion status")
			}
			result.ExitCode = exitCode
			result.Output = output.String()
			return result, nil
		}
		line = partialRune + string(data)
		partialRune = ""
		if errors.Is(err, bufio.ErrBufferFull) && len(line) != 0 {
			last := len(line) - 1
			for last > 0 && !utf8.RuneStart(line[last]) {
				last--
			}
			if !utf8.FullRuneInString(line[last:]) {
				partialRune, line = line[last:], line[:last]
			}
		}
		if pendingNewline {
			line = "\n" + line
		}
		pendingNewline = strings.HasSuffix(line, "\n")
		if pendingNewline {
			line = strings.TrimSuffix(line, "\n")
		}
		line = strings.Map(func(char rune) rune {
			if char != '\t' && char != '\n' && unicode.IsControl(char) {
				return -1
			}
			return char
		}, line)
		if !result.Truncated {
			remaining := maxOutput - output.Len()
			retained := line[:min(len(line), remaining)]
			for !utf8.ValidString(retained) {
				retained = retained[:len(retained)-1]
			}
			output.WriteString(retained)
			result.Truncated = len(line) > len(retained)
		}
		fragment = errors.Is(err, bufio.ErrBufferFull)
		if err != nil && !fragment {
			break
		}
	}
	if pendingNewline && !result.Truncated {
		if output.Len() < maxOutput {
			output.WriteByte('\n')
		} else {
			result.Truncated = true
		}
	}
	result.Output = output.String()
	return result, errors.New("terminal ended without a completion marker, result unknown")
}

func (s *activeSession) isClosed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (t *terminal) close(id string) {
	logger, started := beginOperation(t.logger, "terminal.close", "session_id", id)
	t.mu.Lock()
	session := t.sessions[id]
	delete(t.sessions, id)
	t.mu.Unlock()
	if session != nil {
		session.close()
		logger = logger.With("target", session.target)
	}
	finishOperation(logger, started, nil, "found", session != nil, "reason", "requested")
}

func (t *terminal) reap(ctx context.Context) {
	ticks := time.Tick(time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case tick := <-ticks:
			t.expire(tick)
		}
	}
}

func (t *terminal) expire(now time.Time) {
	dropped := make(map[string]*activeSession)
	t.mu.Lock()
	for id, session := range t.sessions {
		select {
		case session.gate <- struct{}{}:
			if session.isClosed() || !now.Before(session.expiresAt) {
				delete(t.sessions, id)
				dropped[id] = session
			}
			<-session.gate
		default:
		}
	}
	t.mu.Unlock()
	for id, session := range dropped {
		logger, started := beginOperation(t.logger, "terminal.close", "session_id", id, "target", session.target)
		reason := "idle_timeout"
		if session.isClosed() {
			reason = "connection_closed"
		}
		session.close()
		finishOperation(logger, started, nil, "reason", reason, "found", true)
	}
}

func (t *terminal) shutdown() {
	t.mu.Lock()
	t.stopping = true
	sessions := t.sessions
	t.sessions = nil
	t.mu.Unlock()
	for id, session := range sessions {
		logger, started := beginOperation(t.logger, "terminal.close", "session_id", id, "target", session.target)
		session.close()
		finishOperation(logger, started, nil, "reason", "shutdown", "found", true)
	}
}
