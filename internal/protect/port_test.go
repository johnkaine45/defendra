package protect

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/ui"
)

func TestParsePortSpec(t *testing.T) {
	port, proto, err := parsePortSpec("8080")
	if err != nil || port != 8080 || proto != "tcp" {
		t.Fatalf("8080: %d %s %v", port, proto, err)
	}
	port, proto, err = parsePortSpec(" 25565/udp ")
	if err != nil || port != 25565 || proto != "udp" {
		t.Fatalf("udp: %d %s %v", port, proto, err)
	}
	port, proto, err = parsePortSpec("443/tcp")
	if err != nil || port != 443 || proto != "tcp" {
		t.Fatalf("tcp: %d %s %v", port, proto, err)
	}
	if _, _, err := parsePortSpec("0"); err == nil {
		t.Fatal("port 0")
	}
	if _, _, err := parsePortSpec("65536"); err == nil {
		t.Fatal("65536")
	}
	if _, _, err := parsePortSpec("abc"); err == nil {
		t.Fatal("abc")
	}
	if _, _, err := parsePortSpec("8080/icmp"); err == nil {
		t.Fatal("icmp")
	}
}

func TestRefuseAllowPort(t *testing.T) {
	if refuseAllowPort(8080, false) != "" {
		t.Fatal(refuseAllowPort(8080, false))
	}
	got := refuseAllowPort(6379, false)
	if !strings.Contains(got, "база") || !strings.Contains(got, "6379") {
		t.Fatal(got)
	}
	got = refuseAllowPort(2375, false)
	if !strings.Contains(got, "Docker") {
		t.Fatal(got)
	}
	got = refuseAllowPort(2376, false)
	if !strings.Contains(got, "Docker") || !strings.Contains(got, "2376") {
		t.Fatal(got)
	}
	got = refuseAllowPort(22, false)
	if !strings.Contains(got, "вход") {
		t.Fatal(got)
	}
	got = refuseAllowPort(22, true)
	if !strings.Contains(got, "sudo defendra street") {
		t.Fatal(got)
	}
	got = refuseAllowPort(22022, true)
	if !strings.Contains(got, "street") {
		t.Fatal(got)
	}
}

func TestAllowPortQuestion(t *testing.T) {
	q := allowPortQuestion(8080, "tcp")
	if !strings.Contains(q, "слабое место") {
		t.Fatal(q)
	}
	if !strings.Contains(q, "sudo defendra allow-site") {
		t.Fatal(q)
	}
	if strings.Contains(q, "ufw") || strings.Contains(q, "fail2ban") {
		t.Fatal(q)
	}
	q = allowPortQuestion(25565, "udp")
	if !strings.Contains(q, "необычный") {
		t.Fatal(q)
	}
}

func TestAllowPortYesRefused(t *testing.T) {
	var out bytes.Buffer
	u := ui.New(strings.NewReader(""), &out, &out)
	code := AllowPort(context.Background(), host.Info{}, u, true, false, "8080")
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(out.String(), "--yes не открывает") {
		t.Fatal(out.String())
	}
	if !strings.Contains(out.String(), "sudo defendra allow-port") {
		t.Fatal(out.String())
	}
}
