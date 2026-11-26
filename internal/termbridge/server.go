package termbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type rpcResponse struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

type socketClient struct {
	socket string
	http   *http.Client
}

func newSocketClient(socket string) *socketClient {
	return &socketClient{
		socket: socket,
		http: &http.Client{
			Timeout: openTimeout + commandTimeout + 10*time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return new(net.Dialer).DialContext(ctx, "unix", socket)
				},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *socketClient) call(ctx context.Context, operation string, input any) (rpcResponse, error) {
	var result rpcResponse
	if err := checkSocketDir(filepath.Dir(c.socket)); err != nil {
		return result, err
	}
	if err := checkSocket(c.socket); err != nil {
		return result, err
	}
	data, err := json.Marshal(input)
	if err != nil {
		return result, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://termbridge/"+operation, bytes.NewReader(data))
	if err != nil {
		return result, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return result, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("service returned HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 256<<10)).Decode(&result); err != nil {
		return result, fmt.Errorf("invalid service response: %w", err)
	}
	return result, nil
}

func checkSocketDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("socket directory must be owned by the current user with permissions 0700, without symlinks")
	}
	return nil
}

func checkSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0077 != 0 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("socket must be owned by the current user with permissions 0600, without symlinks")
	}
	return nil
}

func serve(ctx context.Context, terminal *terminal, socket string) error {
	if err := os.MkdirAll(filepath.Dir(socket), 0700); err != nil {
		return err
	}
	if err := checkSocketDir(filepath.Dir(socket)); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: socket,
		Net:  "unix",
	})
	if err != nil {
		return fmt.Errorf("listen on socket (existing paths are never removed automatically): %w", err)
	}
	listener.SetUnlinkOnClose(false)
	defer func() { _ = listener.Close() }()
	info, err := os.Lstat(socket)
	if err != nil {
		return err
	}
	defer func() {
		current, err := os.Lstat(socket)
		if err == nil && os.SameFile(info, current) {
			if err := os.Remove(socket); err != nil {
				terminal.logger.Error("socket cleanup failed", "event", "service.cleanup", "error", err.Error())
			}
		}
	}()
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	reaperDone := make(chan struct{})
	go func() {
		defer close(reaperDone)
		terminal.reap(ctx)
	}()
	defer func() { cancel(); <-reaperDone }()
	server := &http.Server{
		Handler:           terminalHandler(terminal),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    8 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
		}
	})
	terminal.logger.Info("terminal service ready", "event", "service.ready", "socket", socket)
	err = server.Serve(listener)
	if stop() {
		_ = server.Close()
	} else {
		<-done
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func terminalHandler(terminal *terminal) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /open", func(w http.ResponseWriter, r *http.Request) {
		var input openInput
		if !readRequest(w, r, &input) {
			return
		}
		id, err := terminal.open(r.Context(), input)
		writeResponse(w, openOutput{SessionID: id}, err)
	})
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		var input runInput
		if !readRequest(w, r, &input) {
			return
		}
		result, err := terminal.run(r.Context(), input.SessionID, input.Command)
		writeResponse(w, result, err)
	})
	mux.HandleFunc("POST /close", func(w http.ResponseWriter, r *http.Request) {
		var input closeInput
		if !readRequest(w, r, &input) {
			return
		}
		if input.SessionID == "" {
			writeResponse(w, nil, errors.New("session is required"))
			return
		}
		terminal.close(input.SessionID)
		writeResponse(w, closeOutput{Closed: true}, nil)
	})
	mux.HandleFunc("POST /exec", func(w http.ResponseWriter, r *http.Request) {
		var input execInput
		if !readRequest(w, r, &input) {
			return
		}
		if err := validateCommand(input.Command); err != nil {
			writeResponse(w, nil, err)
			return
		}
		id, err := terminal.open(r.Context(), input.endpoint)
		if err != nil {
			writeResponse(w, nil, err)
			return
		}
		defer terminal.close(id)
		result, err := terminal.run(r.Context(), id, input.Command)
		writeResponse(w, result, err)
	})
	return mux
}

func readRequest(w http.ResponseWriter, r *http.Request, input any) bool {
	if r.Host != "termbridge" || r.Header.Get("Origin") != "" || r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "local JSON client required", http.StatusForbidden)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(input); err != nil {
		writeResponse(w, nil, errors.New("invalid request JSON or body too large"))
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeResponse(w, nil, errors.New("request must contain a single JSON object"))
		return false
	}
	return true
}

func writeResponse(w http.ResponseWriter, data any, err error) {
	response := rpcResponse{}
	if data != nil {
		response.Data, _ = json.Marshal(data)
	}
	if err != nil {
		response.Error = err.Error()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
