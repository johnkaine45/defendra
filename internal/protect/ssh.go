package protect

import (
	"os"
	"path/filepath"
	"strings"
)

var sshLockKeys = []string{
	"PermitRootLogin",
	"PasswordAuthentication",
	"KbdInteractiveAuthentication",
	"ChallengeResponseAuthentication",
	"PermitEmptyPasswords",
	"PubkeyAuthentication",
	"AllowUsers",
	"DenyUsers",
	"DenyGroups",
	"AllowGroups",
	"AuthenticationMethods",
	"AuthorizedKeysFile",
	"ForceCommand",
	"ChrootDirectory",
	"MaxAuthTries",
	"X11Forwarding",
	"UseDNS",
	"GSSAPIAuthentication",
}

func commentSSHLockKeys(src string) (string, bool) {
	changed := false
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trim := strings.TrimSpace(line)
		if trim != "" && !strings.HasPrefix(trim, "#") {
			key := trim
			if i := strings.IndexAny(key, " \t="); i >= 0 {
				key = key[:i]
			}
			hit := false
			for _, k := range sshLockKeys {
				if strings.EqualFold(key, k) {
					out = append(out, "# defendra: "+line)
					changed = true
					hit = true
					break
				}
			}
			if hit {
				continue
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), changed
}

func snapshotSSHDropins() (map[string][]byte, error) {
	m := map[string][]byte{}
	matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		return m, nil
	}
	for _, p := range matches {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		m[p] = append([]byte(nil), b...)
	}
	return m, nil
}

func restoreSSHDropins(orig map[string][]byte) error {
	keep := map[string]bool{}
	for p, b := range orig {
		keep[p] = true
		if err := os.WriteFile(p, b, 0644); err != nil {
			return err
		}
	}
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	for _, p := range matches {
		if !keep[p] {
			_ = os.Remove(p)
		}
	}
	return nil
}

func neutralizeOtherSSHDropins() error {
	matches, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	if err != nil {
		return err
	}
	for _, p := range matches {
		base := filepath.Base(p)
		if base == "00-defendra.conf" || base == "99-defendra.conf" {
			continue
		}
		if err := neutralizeFile(p); err != nil {
			return err
		}
	}
	return nil
}

func neutralizeSSHMain() error {
	return neutralizeFile("/etc/ssh/sshd_config")
}

func neutralizeFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, changed := commentSSHLockKeys(string(b))
	if !changed {
		return nil
	}
	mode := os.FileMode(0644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	return os.WriteFile(path, []byte(next), mode)
}
