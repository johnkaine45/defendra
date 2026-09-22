package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const Dir = "/var/log/defendra"

func Event(cmd, result, detail string) {
	write("audit.log", fmt.Sprintf("cmd=%s result=%s%s",
		safe(cmd), safe(result), optionalDetail(detail)))
}

func Watch(level string, fails int) {
	write("watch.log", fmt.Sprintf("level=%s fails=%d", safe(level), fails))
}

func optionalDetail(detail string) string {
	detail = sanitize(detail)
	if detail == "" {
		return ""
	}
	return " detail=" + detail
}

func sanitize(s string) string {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	if strings.Contains(low, "password") || strings.Contains(low, "begin ") || strings.Contains(s, "ssh-ed25519") {
		return ""
	}
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

func safe(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, " ", "_")
	if s == "" {
		return "-"
	}
	return s
}

func write(name, body string) {
	if err := os.MkdirAll(Dir, 0750); err != nil {
		return
	}
	line := time.Now().UTC().Format(time.RFC3339) + " " + body + "\n"
	p := filepath.Join(Dir, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	_, _ = f.WriteString(line)
	_ = f.Close()
}
