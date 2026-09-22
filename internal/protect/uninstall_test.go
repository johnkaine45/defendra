package protect

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/backup"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/ui"
)

func TestUninstallQuestion(t *testing.T) {
	q := uninstallQuestion()
	if !strings.Contains(q, "Уберу Defendra") {
		t.Fatal(q)
	}
	if strings.Contains(q, "ufw") || strings.Contains(q, "fail2ban") || strings.Contains(q, "sshd") {
		t.Fatal(q)
	}
	if !strings.Contains(q, "admin не трогаю") {
		t.Fatal(q)
	}
}

func TestUninstallYesRefused(t *testing.T) {
	var out bytes.Buffer
	u := ui.New(strings.NewReader(""), &out, &out)
	code := Uninstall(context.Background(), host.Info{}, u, true, false)
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(out.String(), "--yes не делает") {
		t.Fatal(out.String())
	}
}

func TestUninstallDryRun(t *testing.T) {
	var out bytes.Buffer
	u := ui.New(strings.NewReader(""), &out, &out)
	code := Uninstall(context.Background(), host.Info{}, u, false, true)
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(out.String(), "Ничего не меняю") {
		t.Fatal(out.String())
	}
}

func TestOurFilesIncludeSSHDropin(t *testing.T) {
	got := backup.OurFiles()
	want := "/etc/ssh/sshd_config.d/00-defendra.conf"
	found := false
	for _, p := range got {
		if !backup.CreatedByUs(p) {
			t.Fatalf("OurFiles entry not CreatedByUs: %s", p)
		}
		if p == want {
			found = true
		}
	}
	if !found {
		t.Fatal(got)
	}
}
