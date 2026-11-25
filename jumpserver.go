package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type jumpAPI struct {
	client        *http.Client
	base, org     string
	keyID, secret string
}

type assetMatch struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type kokoCredential struct {
	address, username, password string
}

func startJumpServer(ctx context.Context, client *http.Client, cfg *jumpServerConfig, path string, hop jumpServerStep, command string) (*terminalLink, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("locate known_hosts: %w", err)
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	checkKey, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("read known_hosts: %w", err)
	}

	api := jumpAPI{
		client: client,
		base:   strings.TrimRight(cfg.URL, "/"),
		org:    cmp.Or(cfg.Org, "ROOT"),
		keyID:  cfg.AccessKeyID,
		secret: cfg.AccessKeySecret,
	}
	if api.keyID == "" || api.secret == "" || !printable(api.keyID) {
		return nil, errors.New("JumpServer access key is missing or invalid")
	}
	credential, err := api.acquire(ctx, hop)
	if err != nil {
		return nil, err
	}
	return startKoKo(ctx, credential, checkKey, command)
}

func (a jumpAPI) acquire(ctx context.Context, hop jumpServerStep) (kokoCredential, error) {
	account := hop.Account
	if account == "" {
		var profile struct {
			Username string `json:"username"`
		}
		if err := a.request(ctx, http.MethodGet, "/users/profile/", nil, &profile); err != nil {
			return kokoCredential{}, fmt.Errorf("get JumpServer profile: %w", err)
		}
		if strings.TrimSpace(profile.Username) == "" {
			return kokoCredential{}, errors.New("JumpServer profile has no username")
		}
		account = profile.Username
	}
	asset, err := a.findAsset(ctx, hop.Asset)
	if err != nil {
		return kokoCredential{}, err
	}
	var detail struct {
		Accounts []struct {
			Alias    string `json:"alias"`
			Username string `json:"username"`
		} `json:"permed_accounts"`
	}
	if err := a.request(ctx, http.MethodGet, "/perms/users/self/assets/"+url.PathEscape(asset)+"/", nil, &detail); err != nil {
		return kokoCredential{}, fmt.Errorf("get permitted JumpServer accounts: %w", err)
	}
	var alias string
	for _, candidate := range detail.Accounts {
		if candidate.Username != account && candidate.Alias != account {
			continue
		}
		if alias != "" && alias != candidate.Alias {
			return kokoCredential{}, errors.New("JumpServer account is ambiguous")
		}
		alias = candidate.Alias
	}
	if alias == "" {
		return kokoCredential{}, errors.New("JumpServer account is not permitted")
	}
	var token struct {
		ID string `json:"id"`
	}
	body := map[string]any{
		"asset":           asset,
		"account":         alias,
		"input_username":  account,
		"input_secret":    "",
		"protocol":        "ssh",
		"connect_method":  "web_cli",
		"connect_options": map[string]any{"reusable": false},
	}
	const tokenEndpoint = "/authentication/connection-token/"
	if err := a.request(ctx, http.MethodPost, tokenEndpoint, body, &token); err != nil {
		return kokoCredential{}, fmt.Errorf("request JumpServer connection token: %w", err)
	}
	if strings.TrimSpace(token.ID) == "" {
		return kokoCredential{}, errors.New("JumpServer did not return a connection token ID")
	}

	var result struct {
		URL string `json:"url"`
	}
	endpoint := tokenEndpoint + url.PathEscape(token.ID) + "/client-url/"
	if err := a.request(ctx, http.MethodGet, endpoint, nil, &result); err != nil {
		return kokoCredential{}, fmt.Errorf("get JumpServer client URL: %w", err)
	}
	return parseClientURL(result.URL)
}

func (a jumpAPI) findAsset(ctx context.Context, name string) (string, error) {
	query := url.Values{"search": {name}}
	var raw json.RawMessage
	if err := a.request(ctx, http.MethodGet, "/perms/users/self/assets/?"+query.Encode(), nil, &raw); err != nil {
		return "", fmt.Errorf("look up JumpServer asset: %w", err)
	}
	raw = bytes.TrimSpace(raw)
	var matches []assetMatch
	if bytes.HasPrefix(raw, []byte("[")) {
		if err := json.Unmarshal(raw, &matches); err != nil {
			return "", errors.New("invalid JumpServer asset list")
		}
	} else {
		var page struct {
			Data    []assetMatch `json:"data"`
			Results []assetMatch `json:"results"`
		}
		if err := json.Unmarshal(raw, &page); err != nil {
			return "", errors.New("invalid JumpServer asset page")
		}
		matches = append(page.Data, page.Results...)
	}
	var id string
	for _, item := range matches {
		if item.ID == "" || !strings.EqualFold(item.Name, name) {
			continue
		}
		if id != "" && item.ID != id {
			return "", errors.New("JumpServer asset name is ambiguous")
		}
		id = item.ID
	}
	if id == "" {
		return "", errors.New("JumpServer asset is unavailable")
	}
	return id, nil
}

func (a jumpAPI) request(ctx context.Context, method, path string, body, result any) error {
	var reader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, reader)
	if err != nil {
		return errors.New("invalid JumpServer request URL")
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Date", date)
	req.Header.Set("X-JMS-ORG", a.org)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	mac := hmac.New(sha256.New, []byte(a.secret))
	_, _ = fmt.Fprintf(mac, "(request-target): %s %s\naccept: application/json\ndate: %s", strings.ToLower(method), req.URL.RequestURI(), date)
	req.Header.Set("Authorization", fmt.Sprintf(
		`Signature keyId=%q,algorithm=%q,headers="(request-target) accept date",signature=%q`,
		a.keyID, "hmac-sha256", base64.StdEncoding.EncodeToString(mac.Sum(nil)),
	))

	resp, err := a.client.Do(req)
	if err != nil {
		if requestErr, ok := errors.AsType[*url.Error](err); ok {
			err = requestErr.Err
		}
		return fmt.Errorf("JumpServer HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("JumpServer returned HTTP %d", resp.StatusCode)
	}
	const maxResponse = 1 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("read JumpServer response: %w", err)
	}
	if len(data) > maxResponse || json.Unmarshal(data, result) != nil {
		return errors.New("invalid or oversized JumpServer response")
	}
	return nil
}

func parseClientURL(rawURL string) (kokoCredential, error) {
	encoded, ok := strings.CutPrefix(strings.TrimSpace(rawURL), "jms://")
	if !ok || encoded == "" {
		return kokoCredential{}, errors.New("invalid JumpServer client URL")
	}
	var (
		raw []byte
		err error
	)
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		raw, err = encoding.DecodeString(encoded)
		if err == nil {
			break
		}
	}
	var payload struct {
		Protocol string `json:"protocol"`
		Value    string `json:"value"`
		Token    struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"token"`
		Endpoint struct {
			Host string          `json:"host"`
			Port json.RawMessage `json:"port"`
		} `json:"endpoint"`
	}
	if err != nil || json.Unmarshal(raw, &payload) != nil || !strings.EqualFold(payload.Protocol, "ssh") {
		return kokoCredential{}, errors.New("invalid JumpServer SSH client payload")
	}
	port, portErr := strconv.Atoi(strings.Trim(string(payload.Endpoint.Port), `"`))
	host := strings.Trim(strings.TrimSpace(payload.Endpoint.Host), "[]")
	id := cmp.Or(payload.Token.ID, payload.Value)
	secret := cmp.Or(payload.Token.Value, payload.Value)
	if host == "" || !printable(host) || portErr != nil || port < 1 || port > 65535 || id == "" || secret == "" {
		return kokoCredential{}, errors.New("incomplete KoKo SSH credentials")
	}
	return kokoCredential{
		address:  net.JoinHostPort(host, strconv.Itoa(port)),
		username: "JMS-" + id,
		password: secret,
	}, nil
}

func startKoKo(ctx context.Context, credential kokoCredential, checkKey ssh.HostKeyCallback, command string) (*terminalLink, error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", credential.address)
	if err != nil {
		return nil, fmt.Errorf("connect KoKo: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	conn, channels, requests, err := ssh.NewClientConn(raw, credential.address, &ssh.ClientConfig{
		User:            credential.username,
		Auth:            []ssh.AuthMethod{ssh.Password(credential.password)},
		HostKeyCallback: checkKey,
	})
	if err != nil {
		_ = raw.Close()
		if _, invalidKey := errors.AsType[*knownhosts.KeyError](err); invalidKey {
			return nil, errors.New("KoKo host key verification failed")
		}
		return nil, errors.New("KoKo SSH handshake failed")
	}
	client := ssh.NewClient(conn, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, errors.New("open KoKo SSH session failed")
	}
	input, err := session.StdinPipe()
	if err != nil {
		_ = client.Close()
		return nil, errors.New("open KoKo SSH input failed")
	}
	output, writer := io.Pipe()
	session.Stdout, session.Stderr = writer, writer
	if err := session.Start(command); err != nil {
		_ = client.Close()
		_ = output.Close()
		_ = writer.Close()
		return nil, errors.New("start command through KoKo failed")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = session.Wait()
		_ = writer.Close()
	}()
	return &terminalLink{
		input:  input,
		output: output,
		close: sync.OnceFunc(func() {
			_ = client.Close()
			_ = output.Close()
			<-done
		}),
	}, nil
}
