package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/ui"
)

func TestParseFlags(t *testing.T) {
	cmd, f := parse([]string{"protect", "--yes", "--user", "deploy", "--dry-run"})
	if cmd != "protect" || !f.yes || !f.dry || f.user != "deploy" {
		t.Fatalf("cmd=%s flags=%+v", cmd, f)
	}
	cmd, f = parse([]string{"scan", "--format=json"})
	if cmd != "scan" || !f.json {
		t.Fatalf("scan json: %s %+v", cmd, f)
	}
	cmd, _ = parse([]string{"-h"})
	if cmd != "help" {
		t.Fatalf("help: %s", cmd)
	}
	cmd, _ = parse([]string{"explain", "SSH-PASSWORD"})
	if cmd != "explain" {
		t.Fatalf("explain cmd: %s", cmd)
	}
	_, f = parse([]string{"explain", "SSH-PASSWORD"})
	if f.extra != "SSH-PASSWORD" {
		t.Fatalf("extra: %s", f.extra)
	}
}

func TestRunHelpVersionUnknown(t *testing.T) {
	var out, err bytes.Buffer
	if code := Run([]string{"help"}, strings.NewReader(""), &out, &err); code != 0 {
		t.Fatalf("help %d", code)
	}
	if strings.Contains(out.String(), "ufw disable") {
		t.Fatal("help leaked ufw disable")
	}
	if !strings.Contains(out.String(), "sudo defendra allow-site") {
		t.Fatal("help missing allow-site")
	}
	out.Reset()
	if code := Run([]string{"version"}, strings.NewReader(""), &out, &err); code != 0 {
		t.Fatalf("version %d", code)
	}
	if !strings.Contains(out.String(), "Defendra") {
		t.Fatal(out.String())
	}
	out.Reset()
	if code := Run([]string{"nope"}, strings.NewReader(""), &out, &err); code != 2 {
		t.Fatalf("unknown %d %s", code, out.String())
	}
}

func TestHelpCopy(t *testing.T) {
	h := ui.Help()
	if strings.Contains(h, "ufw disable") || strings.Contains(h, "ufw reset") {
		t.Fatal(h)
	}
	if !strings.Contains(h, "wget -O defendra.deb") {
		t.Fatal("help missing wget")
	}
	if strings.Contains(h, "ssh root@") {
		t.Fatal("help should not send people to ssh root after protect")
	}
}

func TestHowToLoginRescue(t *testing.T) {
	s := ui.HowToLogin("203.0.113.10", "admin", true)
	if !strings.Contains(s, "ssh admin@203.0.113.10") {
		t.Fatal(s)
	}
	if strings.Contains(s, "ssh root@") {
		t.Fatal("rescue promised root SSH")
	}
}
