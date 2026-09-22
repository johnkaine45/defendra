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
	var saved []string
	for _, p := range paths {
		err := copyPath(p, filepath.Join(LastDir(), filepath.Base(p)+"__"+encode(p)))
		if err == nil {
			saved = append(saved, p)
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
	}
	return writeManifest(saved)
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

func writeManifest(paths []string) error {
	var b []byte
	for _, p := range paths {
		b = append(b, []byte(p+"\n")...)
	}
	return os.WriteFile(filepath.Join(LastDir(), "MANIFEST"), b, 0600)
}

func RestoreLast() ([]string, error) {
	man, err := os.ReadFile(filepath.Join(LastDir(), "MANIFEST"))
	if err != nil {
		return nil, err
	}
	var restored []string
	for _, p := range splitLines(string(man)) {
		src := filepath.Join(LastDir(), filepath.Base(p)+"__"+encode(p))
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := copyPath(src, p); err != nil {
			return restored, err
		}
		restored = append(restored, p)
	}
	return restored, nil
}

func HasLast() bool {
	_, err := os.Stat(filepath.Join(LastDir(), "MANIFEST"))
	return err == nil
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
