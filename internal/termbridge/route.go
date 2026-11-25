package termbridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type terminalLink struct {
	input  io.WriteCloser
	output io.ReadCloser
	close  func()
}

// Close the PTY on stdin EOF so the child session can exit.
const ptyProgram = `import errno, os, pty, select, sys, tty
pid, master = pty.fork()
if pid == 0:
    tty.setraw(0)
    os.execvp(sys.argv[1], sys.argv[1:])
try:
    while True:
        readable, _, _ = select.select([master, 0], [], [])
        if master in readable:
            try:
                data = os.read(master, 4096)
            except OSError as err:
                if err.errno != errno.EIO:
                    raise
                break
            if not data:
                break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        if 0 in readable:
            data = os.read(0, 4096)
            if not data:
                break
            while data:
                data = data[os.write(master, data):]
finally:
    os.close(master)
_, status = os.waitpid(pid, 0)
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)`

func startRoute(ctx context.Context, client *http.Client, route []step, marker string) (*terminalLink, error) {
	// Shell quoting grows at each hop. Bound the command before starting any connection.
	const maxCommandBytes = 64 << 10
	argv := []string{"sh", "-c", probeProgram, "termbridge", marker}
	for i := len(route) - 1; i >= 0; i-- {
		if first := route[i].JumpServer; first != nil {
			command := shellCommand(argv)
			if len(command) >= maxCommandBytes {
				return nil, errors.New("route command exceeds 64 KiB")
			}
			return startJumpServer(ctx, client, route[i].JumpConfig, route[i].KnownHosts, *first, command)
		}
		argv = route[i].command(argv, route[i].KnownHosts, route[i].PTYCommand)
		size := 0
		for _, arg := range argv {
			size += len(arg) + 1
		}
		if size >= maxCommandBytes {
			return nil, errors.New("route command exceeds 64 KiB")
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return startCommand(argv)
}

func (s step) command(next []string, knownHosts string, ptyCommand []string) []string {
	switch {
	case s.SSH != nil:
		argv := []string{
			"ssh", "-T",
			"-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=yes",
			"-o", "ControlPath=none",
			"-o", "ForwardAgent=no",
			"-o", "ClearAllForwardings=yes",
		}
		if knownHosts != "" {
			argv = append(argv, "-o", "UserKnownHostsFile="+strconv.Quote(knownHosts))
		}
		if s.SSH.Port != 0 {
			argv = append(argv, "-p", strconv.Itoa(s.SSH.Port))
		}
		if s.IdentityFile != "" {
			argv = append(argv, "-i", s.IdentityFile, "-o", "IdentitiesOnly=yes")
		}
		return append(argv, s.SSH.Destination, shellCommand(next))
	case s.Kubectl != nil:
		k := s.Kubectl
		return append([]string{
			"kubectl", "--context=" + k.Context, "--namespace=" + k.Namespace,
			"exec", "-i", "pod/" + k.Pod, "--container=" + k.Container, "--",
		}, next...)
	case s.Docker != nil:
		d := s.Docker
		return append([]string{
			"docker", "--context=" + d.Context, "exec", "-i",
			"--user=" + d.User, d.Container,
		}, next...)
	default:
		return append(append([]string{"python3", "-c", ptyProgram}, ptyCommand...), s.PTY, shellCommand(next))
	}
}

func shellCommand(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = "'" + strings.ReplaceAll(arg, "'", "'\\''") + "'"
	}
	return strings.Join(quoted, " ")
}

func startCommand(argv []string) (*terminalLink, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create command input: %w", err)
	}
	output, writer, err := os.Pipe()
	if err != nil {
		_ = input.Close()
		return nil, fmt.Errorf("create command output: %w", err)
	}
	cmd.Stdout, cmd.Stderr = writer, writer
	err = cmd.Start()
	_ = writer.Close()
	if err != nil {
		_ = input.Close()
		_ = output.Close()
		return nil, fmt.Errorf("start %s: %w", argv[0], err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cmd.Wait()
	}()
	return &terminalLink{
		input:  input,
		output: output,
		close: sync.OnceFunc(func() {
			_ = input.Close()
			_ = output.Close()
			_ = cmd.Process.Kill()
			<-done
		}),
	}, nil
}
