package main

import (
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

func newAuditLogger(cfg config, stderr io.Writer) (*slog.Logger, *os.File, error) {
	var secrets []string
	for _, item := range cfg.Connections {
		for _, value := range []string{item.AccessKeyID, item.AccessKeySecret} {
			if value != "" {
				secrets = append(secrets, value)
			}
		}
	}
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	var replacements []string
	for _, secret := range secrets {
		replacements = append(replacements, secret, "[REDACTED]")
	}
	redact := strings.NewReplacer(replacements...)
	options := &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if err, ok := attr.Value.Any().(error); ok {
				attr.Value = slog.StringValue(err.Error())
			}
			if attr.Value.Kind() == slog.KindString {
				value := redact.Replace(attr.Value.String())
				if len(value) > maxOutput {
					value = value[:maxOutput]
					for !utf8.ValidString(value) {
						value = value[:len(value)-1]
					}
				}
				attr.Value = slog.StringValue(value)
			}
			return attr
		},
	}
	fallback := slog.New(slog.NewJSONHandler(stderr, options)).With("local_uid", os.Getuid())
	if cfg.Logging.File == "" {
		return fallback, nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Logging.File), 0700); err != nil {
		return fallback, nil, err
	}
	info, err := os.Lstat(cfg.Logging.File)
	if err != nil && !os.IsNotExist(err) {
		return fallback, nil, err
	}
	if err == nil && !info.Mode().IsRegular() {
		return fallback, nil, errors.New("audit log must be a regular file")
	}
	file, err := os.OpenFile(cfg.Logging.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return fallback, nil, err
	}
	info, err = file.Stat()
	if err != nil {
		return fallback, nil, errors.Join(err, file.Close())
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return fallback, nil, errors.Join(errors.New("audit log requires a regular file with permissions 0600"), file.Close())
	}
	writer := &auditWriter{
		file:     file,
		stderr:   stderr,
		fallback: fallback,
	}
	return slog.New(slog.NewJSONHandler(writer, options)).With("local_uid", os.Getuid()), file, nil
}

type auditWriter struct {
	file     *os.File
	stderr   io.Writer
	fallback *slog.Logger
}

func (w *auditWriter) Write(data []byte) (int, error) {
	_, fileErr := w.file.Write(data)
	if fileErr != nil {
		w.fallback.Error("audit log write failed", "event", "logging.write", "error", fileErr.Error())
	}
	n, err := w.stderr.Write(data)
	if fileErr != nil {
		return n, fileErr
	}
	return n, err
}

func beginOperation(base *slog.Logger, event string, attrs ...any) (*slog.Logger, time.Time) {
	started := time.Now()
	logger := base.With("event", event, "operation_id", rand.Text()).With(attrs...)
	logger.Info("operation started", "phase", "started")
	return logger, started
}

func finishOperation(logger *slog.Logger, started time.Time, err error, attrs ...any) {
	attrs = append(attrs, "phase", "finished", "duration_ms", float64(time.Since(started).Microseconds())/1000)
	if err != nil {
		logger.Warn("operation failed", append(attrs, "status", "failed", "error", err.Error())...)
		return
	}
	logger.Info("operation completed", append(attrs, "status", "completed")...)
}
