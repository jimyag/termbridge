package termbridge

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type openInput = endpoint

type openOutput struct {
	SessionID string `json:"session_id"`
}

type runInput struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command"`
}

type closeInput struct {
	SessionID string `json:"session_id"`
}

type closeOutput struct {
	Closed bool `json:"closed"`
}

type execInput struct {
	endpoint
	Command string `json:"command"`
}

// Run executes the CLI and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if _, err := fmt.Fprintln(stdout, "Usage: termbridge <serve|open|run|close|exec> [options]\n  serve  Start the local terminal service\n  open   Open a persistent connection\n  run    Run a command in an open session\n  close  Close a session\n  exec   Open, run and close through the service"); err != nil {
			return 1
		}
		return 0
	}
	mode := args[0]
	if mode != "serve" && mode != "open" && mode != "run" && mode != "close" && mode != "exec" {
		_, _ = fmt.Fprintf(stderr, "unknown command %q, expected serve, open, run, close or exec\n", mode)
		return 2
	}
	flags := flag.NewFlagSet("termbridge "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	socket := flags.String("socket", "", "Unix socket path (default ~/.termbridge/run.sock)")
	var configPath, id, command string
	var asJSON bool
	var input endpoint
	if mode == "serve" {
		flags.StringVar(&configPath, "config", "termbridge.yaml", "YAML or JSON connection configuration")
	} else {
		flags.BoolVar(&asJSON, "json", false, "return the response as JSON, including truncation and errors")
	}
	if mode == "open" || mode == "exec" {
		flags.StringVar(&input.Connection, "connection", "", "configured connection name")
		flags.StringVar(&input.Host, "host", "", "SSH or PTY destination host")
		flags.StringVar(&input.User, "user", "", "SSH, PTY or Docker user")
		flags.IntVar(&input.Port, "port", 0, "SSH port")
		flags.StringVar(&input.Asset, "asset", "", "JumpServer asset")
		flags.StringVar(&input.Account, "account", "", "JumpServer account")
		flags.StringVar(&input.Namespace, "namespace", "", "Kubernetes namespace")
		flags.StringVar(&input.Pod, "pod", "", "Kubernetes pod")
		flags.StringVar(&input.Container, "container", "", "Kubernetes or Docker container")
	}
	if mode == "run" || mode == "close" {
		flags.StringVar(&id, "session", "", "session ID returned by open")
	}
	if mode == "run" || mode == "exec" {
		flags.StringVar(&command, "command", "", "shell command to execute at the destination")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if mode == "run" || mode == "exec" {
		if err := validateCommand(command); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if (mode == "run" || mode == "close") && id == "" {
		_, _ = fmt.Fprintln(stderr, "session is required")
		return 2
	}
	if *socket == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		*socket = filepath.Join(home, ".termbridge", "run.sock")
	}
	if mode == "serve" {
		return runService(ctx, configPath, *socket, stderr)
	}
	var request any
	switch mode {
	case "open":
		request = input
	case "run":
		request = runInput{
			SessionID: id,
			Command:   command,
		}
	case "close":
		request = closeInput{SessionID: id}
	case "exec":
		request = execInput{
			endpoint: input,
			Command:  command,
		}
	}
	client := newSocketClient(*socket)
	defer client.http.CloseIdleConnections()
	response, err := client.call(ctx, mode, request)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "connect to termbridge service: %v; start 'termbridge serve' with the same --socket first\n", err)
		return 1
	}
	if asJSON {
		if err := json.NewEncoder(stdout).Encode(response); err != nil {
			return 1
		}
	} else if mode == "open" && response.Error == "" {
		var opened openOutput
		if err := json.Unmarshal(response.Data, &opened); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if _, err := fmt.Fprintln(stdout, opened.SessionID); err != nil {
			return 1
		}
	}
	var result runResult
	if (mode == "run" || mode == "exec") && len(response.Data) != 0 {
		if err := json.Unmarshal(response.Data, &result); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if !asJSON {
			if _, err := fmt.Fprint(stdout, result.Output); err != nil {
				return 1
			}
			if result.Truncated {
				_, _ = fmt.Fprintln(stderr, "command output truncated at 32 KiB")
			}
		}
	}
	if response.Error != "" {
		_, _ = fmt.Fprintln(stderr, response.Error)
		return 1
	}
	return result.ExitCode
}

func runService(ctx context.Context, configPath, socket string, stderr io.Writer) (code int) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		cfg.Logging.File = ""
		logger, _, _ := newAuditLogger(cfg, stderr)
		logger.Error("configuration failed", "event", "service.start", "error", err.Error())
		return 1
	}
	logger, file, err := newAuditLogger(cfg, stderr)
	if err != nil {
		logger.Error("audit logging setup failed", "event", "service.start", "error", err.Error())
		return 1
	}
	previousLogger := slog.Default()
	slog.SetDefault(logger)
	defer func() {
		if file != nil {
			if err := file.Close(); err != nil {
				logger.Error("audit log close failed", "event", "logging.close", "error", err.Error())
			}
		}
		slog.SetDefault(previousLogger)
	}()
	serviceLogger, started := beginOperation(logger, "service.run", "mode", "serve", "socket", socket)
	defer func() {
		var err error
		if code != 0 {
			err = fmt.Errorf("process exited with status %d", code)
		}
		finishOperation(serviceLogger, started, err, "exit_code", code)
	}()
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	terminal := newTerminal(cfg, client)
	defer terminal.shutdown()
	if err := serve(ctx, terminal, socket); err != nil {
		logger.Error("terminal service failed", "event", "service.error", "error", err.Error())
		return 1
	}
	return 0
}
