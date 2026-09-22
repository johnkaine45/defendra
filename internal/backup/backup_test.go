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

func TestCreatedByUsUndoWhitelist(t *testing.T) {
	own := []string{
		"/etc/ssh/sshd_config.d/00-defendra.conf",
		"/etc/fail2ban/jail.d/defendra.conf",
		"/etc/sudoers.d/defendra-admin",
	}
	for _, p := range own {
		if !CreatedByUs(p) {
			t.Fatalf("should own %s", p)
		}
	}
	keep := []string{"/etc/ssh/sshd_config", "/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/redis/redis.conf"}
	for _, p := range keep {
		if CreatedByUs(p) {
			t.Fatalf("must not delete %s on undo", p)
		}
	}
}

func TestRestoreDoesNotDeleteForeignAbsent(t *testing.T) {
	rootDir = t.TempDir()
	t.Cleanup(func() { rootDir = "/var/lib/defendra" })

	live := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(live, []byte("keep\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(LastDir(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(LastDir(), "MANIFEST"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(LastDir(), "ABSENT"), []byte(live+"\n/etc/ssh/sshd_config\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreLast(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("foreign file was deleted")
	}
}

func TestSkipUFWRuleRestoreWithoutConf(t *testing.T) {
	old := []string{"/etc/ufw/user.rules", "/etc/ssh/sshd_config"}
	if !skipUFWRuleRestore(old, "/etc/ufw/user.rules") {
		t.Fatal("old snapshot must keep live ufw rules")
	}
	if skipUFWRuleRestore(old, "/etc/ssh/sshd_config") {
		t.Fatal("ssh still restores")
	}
	fresh := []string{"/etc/ufw/ufw.conf", "/etc/ufw/user.rules"}
	if skipUFWRuleRestore(fresh, "/etc/ufw/user.rules") {
		t.Fatal("new snapshot restores rules with ufw.conf")
	}
}
