package facts

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/oscmd"
)

var netbirdConfigPaths = []string{
	"/etc/netbird/config.json",
	"/var/lib/netbird/config.json",
	"/etc/netbird/default.json",
}

func collectNetBird(ctx context.Context) NetBirdFact {
	n := NetBirdFact{Installed: oscmd.LookPath("netbird")}
	if !n.Installed {
		if _, err := os.Stat("/usr/bin/netbird"); err == nil {
			n.Installed = true
		}
	}
	if !n.Installed {
		return n
	}
	out, _, _ := oscmd.Run(ctx, 5*time.Second, "systemctl", "is-active", "netbird")
	n.Running = strings.TrimSpace(out) == "active"

	raw, _, err := oscmd.Run(ctx, 8*time.Second, "netbird", "status", "--json")
	if err == nil && strings.TrimSpace(raw) != "" {
		parsed := ParseNetBirdStatusJSON(raw)
		n.Connected = parsed.Connected
		n.SSHEnabled = parsed.SSHEnabled
		n.SSHKnown = parsed.SSHKnown
		n.IP = parsed.IP
		if parsed.Running {
			n.Running = true
		}
	}
	if !n.Connected || n.IP == "" || !n.SSHKnown {
		text, _, textErr := oscmd.Run(ctx, 8*time.Second, "netbird", "status")
		if textErr == nil {
			parsed := ParseNetBirdStatusText(text)
			if !n.Connected {
				n.Connected = parsed.Connected
			}
			if n.IP == "" {
				n.IP = parsed.IP
			}
			if !n.SSHKnown {
				n.SSHEnabled = parsed.SSHEnabled
				n.SSHKnown = parsed.SSHKnown
			}
		}
	}
	if !n.SSHKnown {
		if ok, allowed := netbirdConfigSSHAllowed(); ok {
			n.SSHEnabled = allowed
			n.SSHKnown = true
		}
	}
	return n
}

func collectSSHListener(ctx context.Context) bool {
	for _, name := range []string{"ssh.socket", "ssh", "sshd"} {
		out, _, _ := oscmd.Run(ctx, 5*time.Second, "systemctl", "is-active", name)
		if strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return false
}

func netbirdConfigSSHAllowed() (bool, bool) {
	for _, p := range netbirdConfigPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if allowed, ok := ParseNetBirdConfigSSH(b); ok {
			return true, allowed
		}
	}
	return false, false
}

func ParseNetBirdStatusJSON(raw string) NetBirdFact {
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return NetBirdFact{}
	}
	n := NetBirdFact{}
	if s := jsonString(top, "daemonStatus", "daemon_status", "status"); s != "" {
		n.Connected = strings.EqualFold(s, "connected")
		if strings.EqualFold(s, "connected") || strings.EqualFold(s, "connecting") {
			n.Running = true
		}
	}
	if ip := jsonString(top, "netbirdIp", "netbird_ip", "ip"); ip != "" {
		n.IP = stripCIDR(ip)
	}
	if raw, ok := top["management"]; ok {
		var mgmt map[string]any
		if json.Unmarshal(raw, &mgmt) == nil {
			if c, ok := mgmt["connected"].(bool); ok && c {
				n.Connected = true
			}
		}
	}
	if raw, ok := top["sshServer"]; ok {
		n.SSHKnown = true
		n.SSHEnabled = jsonEnabled(raw)
	} else if raw, ok := top["ssh_server"]; ok {
		n.SSHKnown = true
		n.SSHEnabled = jsonEnabled(raw)
	} else if raw, ok := top["sshServerState"]; ok {
		n.SSHKnown = true
		n.SSHEnabled = jsonEnabled(raw)
	}
	return n
}

func ParseNetBirdStatusText(s string) NetBirdFact {
	n := NetBirdFact{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		valLow := strings.ToLower(val)
		switch {
		case strings.Contains(key, "daemon status") || key == "status":
			n.Connected = strings.Contains(valLow, "connected")
			n.Running = n.Connected || strings.Contains(valLow, "connecting")
		case strings.Contains(key, "netbird ip") || key == "ip":
			n.IP = stripCIDR(strings.Fields(val)[0])
		case strings.Contains(key, "ssh server") || strings.Contains(key, "ssh access"):
			n.SSHKnown = true
			n.SSHEnabled = strings.Contains(valLow, "enabled") || valLow == "on" || valLow == "yes" || valLow == "true"
		}
	}
	return n
}

func ParseNetBirdConfigSSH(b []byte) (bool, bool) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return false, false
	}
	for _, k := range []string{"ServerSSHAllowed", "serverSSHAllowed", "AllowServerSSH"} {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case bool:
				return t, true
			case string:
				return strings.EqualFold(t, "true") || strings.EqualFold(t, "yes"), true
			}
		}
	}
	return false, false
}

func jsonString(m map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func jsonEnabled(raw json.RawMessage) bool {
	var obj map[string]any
	if json.Unmarshal(raw, &obj) == nil {
		for _, k := range []string{"enabled", "Enabled"} {
			if v, ok := obj[k].(bool); ok {
				return v
			}
		}
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return false
}

func stripCIDR(ip string) string {
	ip = strings.TrimSpace(ip)
	if i := strings.Index(ip, "/"); i > 0 {
		return ip[:i]
	}
	return ip
}

func meshIPv4(ip string) bool {
	ip = strings.TrimSpace(ip)
	if !strings.HasPrefix(ip, "100.") {
		return false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	second := 0
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
		second = second*10 + int(c-'0')
	}
	return second >= 64 && second <= 127
}
