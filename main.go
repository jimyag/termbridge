package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type openInput = endpoint

type openOutput struct {
	SessionID string `json:"session_id"`
}

type runInput struct {
	SessionID string `json:"session_id"`
	Command   string `json:"command" jsonschema:"Shell command executed with sh -c at the destination; supports multiline scripts. Maximum 32 KiB. Stdin is closed."`
}

type closeInput struct {
	SessionID string `json:"session_id"`
}

type closeOutput struct {
	Closed bool `json:"closed"`
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("local_uid", os.Getuid()))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := runCLI(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func runCLI(ctx context.Context, args []string, stdout, stderr io.Writer) (code int) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if _, err := fmt.Fprintln(stdout, "Usage: termbridge <mcp|exec> [options]\n  mcp   Start the stdio MCP server\n  exec  Run a shell command"); err != nil {
			return 1
		}
		return 0
	}
	mode := args[0]
	if mode != "mcp" && mode != "exec" {
		_, _ = fmt.Fprintf(stderr, "unknown command %q, expected mcp or exec\n", mode)
		return 2
	}
	flags := flag.NewFlagSet("termbridge "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "termbridge.yaml", "path to the YAML or JSON connection configuration")
	var input openInput
	var command string
	if mode == "exec" {
		flags.StringVar(&input.Connection, "connection", "", "configured connection name")
		flags.StringVar(&input.Host, "host", "", "SSH or PTY destination host")
		flags.StringVar(&input.User, "user", "", "SSH, PTY or Docker user")
		flags.IntVar(&input.Port, "port", 0, "SSH port")
		flags.StringVar(&input.Asset, "asset", "", "JumpServer asset")
		flags.StringVar(&input.Account, "account", "", "JumpServer account")
		flags.StringVar(&input.Namespace, "namespace", "", "Kubernetes namespace")
		flags.StringVar(&input.Pod, "pod", "", "Kubernetes pod")
		flags.StringVar(&input.Container, "container", "", "Kubernetes or Docker container")
		flags.StringVar(&command, "command", "", "shell command to execute at the destination")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if mode == "exec" {
		if err := validateCommand(command); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 2
		}
	}
	cfg, err := loadConfig(*configPath)
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
	serviceLogger, started := beginOperation(logger, "service.run", "mode", mode)
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

	if mode == "exec" {
		id, err := terminal.open(ctx, input)
		if err != nil {
			return 1
		}
		defer terminal.close(id)
		result, err := terminal.run(ctx, id, command)
		if err != nil {
			return 1
		}
		if _, err := fmt.Fprint(stdout, result.Output); err != nil {
			logger.Error("command output write failed", "event", "cli.output", "error", err.Error())
			return 1
		}
		if result.Truncated {
			logger.Warn("command output truncated", "event", "cli.output", "truncated", true)
		}
		return result.ExitCode
	}
	if err := serve(ctx, terminal); err != nil && ctx.Err() == nil {
		logger.Error("MCP server failed", "event", "service.error", "error", err.Error())
		return 1
	}
	return 0
}

func serve(ctx context.Context, terminal *terminal) error {
	reaper, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); terminal.reap(reaper) }()
	defer func() { stop(); <-done }()

	return newServer(terminal).Run(ctx, &mcp.StdioTransport{})
}

func newServer(terminal *terminal) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "termbridge",
		Version: "0.1.0",
	}, nil)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "terminal_open",
		Description: "Open a named connection to a permitted destination. Configured via dependencies and type-specific defaults are applied automatically.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in openInput) (*mcp.CallToolResult, openOutput, error) {
		id, err := terminal.open(ctx, in)
		return nil, openOutput{SessionID: id}, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "terminal_run",
		Description: "Execute a shell command at the destination using an open connection. Commands run in independent sh processes with closed stdin. Returns combined stdout/stderr and exit status.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, runResult, error) {
		result, err := terminal.run(ctx, in.SessionID, in.Command)
		return nil, result, err
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "terminal_close",
		Description: "Close an open session and release its connection.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in closeInput) (*mcp.CallToolResult, closeOutput, error) {
		terminal.close(in.SessionID)
		return nil, closeOutput{Closed: true}, nil
	})
	return server
}
