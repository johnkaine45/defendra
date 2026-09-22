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
	cmd, _ = parse([]string{"netbird"})
	if cmd != "netbird" {
		t.Fatalf("netbird: %s", cmd)
	}
	cmd, _ = parse([]string{"street"})
	if cmd != "street" {
		t.Fatalf("street: %s", cmd)
	}
	cmd, f = parse([]string{"allow-port", "8080"})
	if cmd != "allow-port" || f.extra != "8080" {
		t.Fatalf("allow-port: %s %+v", cmd, f)
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
	if !strings.Contains(h, "wget -O defendra_amd64.deb") {
		t.Fatal("help missing wget")
	}
	if !strings.Contains(h, "sha256sum -c defendra_amd64.deb.sha256") {
		t.Fatal("help missing checksum")
	}
	if !strings.Contains(h, "sudo defendra update") {
		t.Fatal("help missing update")
	}
	if strings.Contains(h, "ssh root@") {
		t.Fatal("help should not send people to ssh root after protect")
	}
	if !strings.Contains(h, "sudo defendra netbird") {
		t.Fatal("help missing netbird")
	}
	if !strings.Contains(h, "sudo defendra street") {
		t.Fatal("help missing street")
	}
	if !strings.Contains(h, "sudo defendra allow-port") {
		t.Fatal("help missing allow-port")
	}
	if !strings.Contains(h, "--yes этот шаг не делает") {
		t.Fatal("help missing allow-port --yes warning")
	}
}

func TestMenuAfterHasNetBird(t *testing.T) {
	m := ui.MenuAfter("green")
	if !strings.Contains(m, "sudo defendra netbird") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "вход только через NetBird") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "sudo defendra street") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "вернуть обычный вход с улицы") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "sudo defendra allow-port") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "слабое место") {
		t.Fatal(m)
	}
	if !strings.Contains(m, "Версия ") {
		t.Fatal(m)
	}
}

func TestMenuShowsVersion(t *testing.T) {
	v := strings.TrimSpace(strings.TrimPrefix(ui.VersionLine(), "Defendra "))
	fresh := ui.MenuFresh()
	after := ui.MenuAfter("green")
	if !strings.Contains(fresh, "Версия "+v) {
		t.Fatal(fresh)
	}
	if !strings.Contains(after, "Версия "+v) {
		t.Fatal(after)
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

func TestHowToLoginStreetOff(t *testing.T) {
	s := ui.FormatHowToLogin(ui.LoginHint{
		IP: "195.58.153.30", User: "admin", SSHLocked: true,
		StreetOff: true, NetBirdIP: "100.64.1.2",
	})
	if !strings.Contains(s, "ssh admin@100.64.1.2") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "Обычный вход с улицы выключен") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "NetBird") {
		t.Fatal(s)
	}
}
