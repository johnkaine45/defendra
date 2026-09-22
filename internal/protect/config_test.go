package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetConfigLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "redis.conf")
	if err := os.WriteFile(p, []byte("port 6379\nbind 0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := setConfigLine(p, "bind", "bind 127.0.0.1 -::1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "bind 127.0.0.1 -::1") {
		t.Fatal(s)
	}
	if strings.Contains(s, "bind 0.0.0.0") {
		t.Fatal(s)
	}
}
