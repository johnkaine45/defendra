package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreMissingCopyDoesNotDeleteLive(t *testing.T) {
	rootDir = t.TempDir()
	t.Cleanup(func() { rootDir = "/var/lib/defendra" })

	live := filepath.Join(t.TempDir(), "ufw", "user.rules")
	if err := os.MkdirAll(filepath.Dir(live), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte("keep-me\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(LastDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(LastDir(), "MANIFEST"), []byte(live+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := RestoreLast()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("restored %v", got)
	}
	b, err := os.ReadFile(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "keep-me\n" {
		t.Fatalf("live deleted or changed: %q", b)
	}
}

func TestSnapshotSkipsMissingAndRestoresExisting(t *testing.T) {
	rootDir = t.TempDir()
	t.Cleanup(func() { rootDir = "/var/lib/defendra" })

	srcDir := t.TempDir()
	exist := filepath.Join(srcDir, "dropin.conf")
	missing := filepath.Join(srcDir, "no-such.conf")
	if err := os.WriteFile(exist, []byte("PermitRootLogin no\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Snapshot(exist, missing); err != nil {
		t.Fatal(err)
	}
	man, err := os.ReadFile(filepath.Join(LastDir(), "MANIFEST"))
	if err != nil {
		t.Fatal(err)
	}
	if string(man) != exist+"\n" {
		t.Fatalf("manifest=%q", man)
	}

	if err := os.WriteFile(exist, []byte("changed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := RestoreLast()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != exist {
		t.Fatalf("restored %v", got)
	}
	b, _ := os.ReadFile(exist)
	if string(b) != "PermitRootLogin no\n" {
		t.Fatalf("got %q", b)
	}
}
