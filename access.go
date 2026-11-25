package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

func (c config) resolve(in endpoint) ([]step, string, error) {
	item, ok := c.Connections[in.Connection]
	if !ok {
		return nil, "", errors.New("unknown connection")
	}
	actual, err := item.prepare(in, false)
	if err != nil {
		return nil, "", err
	}
	allowed := false
	for _, rule := range c.Allow[in.Connection] {
		permitted, err := item.prepare(rule, true)
		if err != nil {
			return nil, "", err
		}
		if permitted.allows(actual) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, "", errors.New("destination is outside the configured allow rules")
	}
	backwards := []step{actual}
	seen := map[string]bool{in.Connection: true}
	for item.Via != nil {
		parent := *item.Via
		if seen[parent.Connection] {
			return nil, "", errors.New("connection via cycle")
		}
		seen[parent.Connection] = true
		item, ok = c.Connections[parent.Connection]
		if !ok {
			return nil, "", errors.New("unknown via connection")
		}
		hop, err := item.prepare(parent, false)
		if err != nil {
			return nil, "", err
		}
		backwards = append(backwards, hop)
	}
	slices.Reverse(backwards)
	labels := make([]string, len(backwards))
	for index, hop := range backwards {
		if err := hop.validateInline(index, hop.JumpConfig != nil); err != nil {
			return nil, "", err
		}
		labels[index] = hop.label()
	}
	return backwards, in.Connection + " -> " + strings.Join(labels, " -> "), nil
}

func (c connection) prepare(in endpoint, pattern bool) (step, error) {
	fields := map[string]bool{
		"host": in.Host != "", "asset": in.Asset != "", "account": in.Account != "",
		"user": in.User != "", "port": in.Port != 0, "namespace": in.Namespace != "",
		"pod": in.Pod != "", "container": in.Container != "",
	}
	permitted := map[string]string{
		"ssh":        "host user port",
		"pty":        "host user",
		"jumpserver": "asset account",
		"kubectl":    "namespace pod container",
		"docker":     "container user",
	}
	for key, present := range fields {
		if present && !strings.Contains(" "+permitted[c.Type]+" ", " "+key+" ") {
			return step{}, fmt.Errorf("destination field %q is not valid for %s", key, c.Type)
		}
	}
	original := in
	if pattern {
		values := []*string{&in.Host, &in.Asset, &in.Pod}
		if c.Type == "docker" {
			values = append(values, &in.Container)
		}
		for _, value := range values {
			if strings.Count(*value, "*") > 1 {
				return step{}, errors.New("allow patterns support one wildcard")
			}
			*value = strings.Replace(*value, "*", "sample", 1)
		}
	}
	mergedUser := in.User
	if mergedUser == "" {
		mergedUser = c.User
	}
	host := in.Host
	if mergedUser != "" {
		if strings.Contains(host, "@") {
			return step{}, errors.New("specify user separately from host when a user is configured")
		}
		host = mergedUser + "@" + host
	}
	hop := step{
		KnownHosts:   c.KnownHosts,
		IdentityFile: c.IdentityFile,
	}
	switch c.Type {
	case "ssh":
		port := in.Port
		if port == 0 {
			port = c.Port
		}
		hop.SSH = &sshStep{
			Destination: host,
			Port:        port,
		}
	case "pty":
		hop.PTY, hop.PTYCommand = host, c.Command
	case "jumpserver":
		hop.JumpServer = &jumpServerStep{
			Asset:   in.Asset,
			Account: in.Account,
		}
		hop.JumpConfig = &jumpServerConfig{
			URL:             c.URL,
			Org:             c.Org,
			AccessKeyID:     c.AccessKeyID,
			AccessKeySecret: c.AccessKeySecret,
		}
	case "kubectl":
		namespace, container := in.Namespace, in.Container
		if namespace == "" {
			namespace = c.Namespace
		}
		if container == "" {
			container = c.Container
		}
		hop.Kubectl = &kubectlStep{
			Context:   c.Context,
			Namespace: namespace,
			Pod:       in.Pod,
			Container: container,
		}
	case "docker":
		hop.Docker = &dockerStep{
			Context:   c.Context,
			Container: in.Container,
			User:      mergedUser,
		}
	default:
		return step{}, errors.New("unknown connection type")
	}
	if err := hop.validateInline(0, hop.JumpConfig != nil); err != nil {
		return step{}, err
	}
	if pattern {
		host = original.Host
		if mergedUser != "" {
			host = mergedUser + "@" + host
		}
		if hop.SSH != nil {
			hop.SSH.Destination = host
		}
		if hop.PTY != "" {
			hop.PTY = host
		}
		if hop.JumpServer != nil {
			hop.JumpServer.Asset = original.Asset
		}
		if hop.Kubectl != nil {
			hop.Kubectl.Pod = original.Pod
			if original.Container != "" {
				hop.Kubectl.Container = original.Container
			}
		}
		if hop.Docker != nil {
			hop.Docker.Container = original.Container
		}
	}
	return hop, nil
}
func (s step) validateInline(index int, hasJumpServer bool) error {
	if err := s.validate(index, hasJumpServer); err != nil {
		return err
	}
	if s.SSH != nil && !validDestinationHost(s.SSH.Destination) ||
		s.PTY != "" && !validDestinationHost(s.PTY) {
		return errors.New("invalid route host")
	}
	return nil
}

func validDestinationHost(destination string) bool {
	_, host := splitDestination(destination)
	if targetName.MatchString(host) {
		return true
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	_, err := netip.ParseAddr(host)
	return err == nil
}

func (s step) allows(hop step) bool {
	switch {
	case s.SSH != nil && hop.SSH != nil:
		return s.SSH.Port == hop.SSH.Port && matchesDestination(s.SSH.Destination, hop.SSH.Destination)
	case s.JumpServer != nil && hop.JumpServer != nil:
		return s.JumpServer.Account == hop.JumpServer.Account && matchesName(s.JumpServer.Asset, hop.JumpServer.Asset)
	case s.PTY != "" && hop.PTY != "":
		return matchesDestination(s.PTY, hop.PTY)
	case s.Kubectl != nil && hop.Kubectl != nil:
		return s.Kubectl.Context == hop.Kubectl.Context &&
			s.Kubectl.Namespace == hop.Kubectl.Namespace &&
			s.Kubectl.Container == hop.Kubectl.Container &&
			matchesName(s.Kubectl.Pod, hop.Kubectl.Pod)
	case s.Docker != nil && hop.Docker != nil:
		return s.Docker.Context == hop.Docker.Context &&
			s.Docker.User == hop.Docker.User &&
			matchesName(s.Docker.Container, hop.Docker.Container)
	default:
		return false
	}
}

func (s step) label() string {
	switch {
	case s.SSH != nil:
		if s.SSH.Port != 0 {
			return fmt.Sprintf("ssh %s port %d", s.SSH.Destination, s.SSH.Port)
		}
		return "ssh " + s.SSH.Destination
	case s.JumpServer != nil:
		if s.JumpServer.Account != "" {
			return "jumpserver " + s.JumpServer.Account + "@" + s.JumpServer.Asset
		}
		return "jumpserver " + s.JumpServer.Asset
	case s.Kubectl != nil:
		return "kubectl exec " + s.Kubectl.Context + "/" + s.Kubectl.Namespace + "/" + s.Kubectl.Pod + "/" + s.Kubectl.Container
	case s.Docker != nil:
		return "docker exec " + s.Docker.Context + "/" + s.Docker.Container + "/" + s.Docker.User
	default:
		return "pty " + s.PTY
	}
}

func matchesDestination(pattern, actual string) bool {
	allowedAccount, allowedHost := splitDestination(pattern)
	account, host := splitDestination(actual)
	return account == allowedAccount && matchesName(allowedHost, host)
}

func splitDestination(destination string) (account, host string) {
	index := strings.LastIndexByte(destination, '@') + 1
	return destination[:index], destination[index:]
}

func matchesName(pattern, name string) bool {
	prefix, suffix, ok := strings.Cut(pattern, "*")
	if !ok {
		return pattern == name
	}
	return len(name) >= len(prefix)+len(suffix) && strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix)
}
