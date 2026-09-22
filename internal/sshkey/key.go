package sshkey

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

var prefixes = []string{"ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-nistp256 ", "ecdsa-sha2-nistp384 ", "ecdsa-sha2-nistp521 ", "sk-ssh-ed25519@", "sk-ecdsa-sha2-nistp256@"}

func LooksPrivate(s string) bool {
	u := strings.ToUpper(s)
	return strings.Contains(u, "BEGIN OPENSSH PRIVATE KEY") ||
		strings.Contains(u, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(u, "BEGIN EC PRIVATE KEY") ||
		strings.Contains(u, "BEGIN PRIVATE KEY")
}

func ParsePublic(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	if LooksPrivate(raw) {
		return "", "private"
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, `"'`)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) || strings.HasPrefix(line, strings.TrimSuffix(p, " ")) {
				fields := strings.Fields(line)
				if len(fields) < 2 || len(fields[1]) < 20 {
					return "", "short"
				}
				return strings.Join(fields, " "), ""
			}
		}
	}
	if strings.Contains(raw, " ") && len(raw) > 40 {
		return "", "short"
	}
	return "", "invalid"
}

func HasAny(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(line, p) || strings.HasPrefix(line, strings.TrimSuffix(p, " ")) {
				return true
			}
		}
	}
	return false
}

func Fingerprint(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
