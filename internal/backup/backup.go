package backup

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/johnkaine/defendra/internal/state"
)

var rootDir = state.Dir

func LastDir() string    { return filepath.Join(rootDir, "backups", "last") }
func ArchiveDir() string { return filepath.Join(rootDir, "backups", "archive") }
func OriginDir() string  { return filepath.Join(rootDir, "backups", "origin") }

func Rotate() error {
	last := LastDir()
	if _, err := os.Stat(last); err != nil {
		return os.MkdirAll(last, 0700)
	}
	dest := filepath.Join(ArchiveDir(), time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(ArchiveDir(), 0700); err != nil {
		return err
	}
	_ = os.RemoveAll(dest)
	if err := os.Rename(last, dest); err != nil {
		return err
	}
	_ = pruneArchive(5)
	return os.MkdirAll(last, 0700)
}

func pruneArchive(keep int) error {
	ents, err := os.ReadDir(ArchiveDir())
	if err != nil {
		return err
	}
	if len(ents) <= keep {
		return nil
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	sort.Strings(names)
	drop := names[:len(names)-keep]
	for _, n := range drop {
		_ = os.RemoveAll(filepath.Join(ArchiveDir(), n))
	}
	return nil
}

func Snapshot(paths ...string) error {
	if err := os.MkdirAll(LastDir(), 0700); err != nil {
		return err
	}
	seen := map[string]bool{}
	var saved []string
	var absent []string
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		err := copyPath(p, filepath.Join(LastDir(), filepath.Base(p)+"__"+encode(p)))
		if err == nil {
			saved = append(saved, p)
			continue
		}
		if os.IsNotExist(err) {
			absent = append(absent, p)
			continue
		}
		return err
	}
	if err := writeLines(filepath.Join(LastDir(), "MANIFEST"), saved); err != nil {
		return err
	}
	return writeLines(filepath.Join(LastDir(), "ABSENT"), absent)
}

func copyPath(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, st.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func writeLines(path string, paths []string) error {
	var b []byte
	for _, p := range paths {
		b = append(b, []byte(p+"\n")...)
	}
	return os.WriteFile(path, b, 0600)
}

func RestoreLast() ([]string, error) {
	return restoreFrom(LastDir())
}

// SealOriginFromLast keeps a one-time copy of the first protect snapshot.
// Later protect runs rotate "last", but uninstall restores from origin.
func SealOriginFromLast() error {
	if HasOrigin() {
		return nil
	}
	if !HasLast() {
		return nil
	}
	_ = os.RemoveAll(OriginDir())
	return copyTree(LastDir(), OriginDir())
}

func RestoreOrigin() ([]string, error) {
	return restoreFrom(OriginDir())
}

func restoreFrom(dir string) ([]string, error) {
	man, err := os.ReadFile(filepath.Join(dir, "MANIFEST"))
	if err != nil {
		return nil, err
	}
	paths := splitLines(string(man))
	var restored []string
	for _, p := range paths {
		if skipUFWRuleRestore(paths, p) {
			continue
		}
		src := filepath.Join(dir, filepath.Base(p)+"__"+encode(p))
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyPath(src, p); err != nil {
			return restored, err
		}
		restored = append(restored, p)
	}
	if abs, err := os.ReadFile(filepath.Join(dir, "ABSENT")); err == nil {
		for _, p := range splitLines(string(abs)) {
			if !CreatedByUs(p) {
				continue
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				return restored, err
			}
			restored = append(restored, p)
		}
	}
	return restored, nil
}

func copyTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	ents, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if err := copyPath(from, to); err != nil {
			return err
		}
	}
	return nil
}

// CreatedByUs is true for files Defendra itself writes. Undo may delete them
// only when the snapshot recorded that they did not exist before protect.
func CreatedByUs(p string) bool {
	for _, ours := range OurFiles() {
		if p == ours {
			return true
		}
	}
	return false
}

// OurFiles lists drop-ins and units Defendra itself writes.
func OurFiles() []string {
	return []string{
		"/etc/ssh/sshd_config.d/00-defendra.conf",
		"/etc/ssh/sshd_config.d/99-defendra.conf",
		"/etc/sysctl.d/99-defendra.conf",
		"/etc/fail2ban/jail.d/defendra.conf",
		"/etc/sudoers.d/defendra-admin",
		"/etc/update-motd.d/99-defendra",
		"/etc/apt/apt.conf.d/51defendra-unattended",
		"/etc/systemd/system/defendra-watch.service",
		"/etc/systemd/system/defendra-watch.timer",
		"/etc/mysql/mysql.conf.d/zz-defendra.cnf",
		"/etc/mysql/conf.d/zz-defendra.cnf",
	}
}

func HasLast() bool {
	_, err := os.Stat(filepath.Join(LastDir(), "MANIFEST"))
	return err == nil
}

func HasOrigin() bool {
	_, err := os.Stat(filepath.Join(OriginDir(), "MANIFEST"))
	return err == nil
}

func LastSkipsUFWRules() bool {
	return skipsUFWRules(LastDir())
}

func OriginSkipsUFWRules() bool {
	return skipsUFWRules(OriginDir())
}

func skipsUFWRules(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "MANIFEST"))
	if err != nil {
		return false
	}
	return skipUFWRuleRestore(splitLines(string(b)), "/etc/ufw/user.rules")
}

func containsPath(paths []string, want string) bool {
	for _, p := range paths {
		if p == want {
			return true
		}
	}
	return false
}

func skipUFWRuleRestore(manifest []string, path string) bool {
	if path != "/etc/ufw/user.rules" && path != "/etc/ufw/user6.rules" {
		return false
	}
	return !containsPath(manifest, "/etc/ufw/ufw.conf")
}

func encode(p string) string {
	b := make([]byte, len(p))
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			c = '_'
		}
		b[i] = c
	}
	return string(b)
}

func splitLines(s string) []string {
	var o []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				o = append(o, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		o = append(o, s[start:])
	}
	return o
}
