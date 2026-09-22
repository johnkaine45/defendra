package report

import (
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/check"
	"github.com/johnkaine/defendra/internal/facts"
)

func TestLevelIgnoresWarn(t *testing.T) {
	fs := []check.Finding{
		{ID: "SUID-UNUSUAL", Status: check.Warn, Severity: check.SevLow},
		{ID: "USER-NOPASSWD-ALL", Status: check.Warn, Severity: check.SevMedium},
		{ID: "SSH-PASSWORD", Status: check.Pass},
	}
	if Level(fs) != "green" {
		t.Fatalf("got %s", Level(fs))
	}
}

func TestLevelFailIsYellow(t *testing.T) {
	fs := []check.Finding{
		{ID: "SSH-PASSWORD", Status: check.Fail, Severity: check.SevHigh},
	}
	if Level(fs) != "yellow" {
		t.Fatalf("got %s", Level(fs))
	}
}

func TestRuCountAttempts(t *testing.T) {
	cases := map[int]string{
		0: "0 попыток", 1: "1 попытка", 2: "2 попытки", 3: "3 попытки",
		4: "4 попытки", 5: "5 попыток", 11: "11 попыток", 12: "12 попыток",
		21: "21 попытка", 22: "22 попытки", 104: "104 попытки",
	}
	for n, want := range cases {
		if got := ruCount(n, "попытка", "попытки", "попыток"); got != want {
			t.Errorf("%d: got %q want %q", n, got, want)
		}
	}
}

func TestStatusTextPlural(t *testing.T) {
	s := facts.Snapshot{
		Fail2ban: facts.Fail2ban{Active: true, SSHBanned: 2},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
	}
	txt := StatusText(s, nil, "203.0.113.10", "admin")
	if !strings.Contains(txt, "2 попытки") {
		t.Fatal(txt)
	}
}

func TestPrettyAllows(t *testing.T) {
	got := prettyAllows([]string{"22/tcp", "80/tcp", "443/tcp", "51820/udp", "22/tcp"})
	if got != "22, 80, 443, 51820/udp" {
		t.Fatal(got)
	}
}

func TestLevelDBIsRed(t *testing.T) {
	fs := []check.Finding{
		{ID: "NET-DB-EXPOSED", Status: check.Fail, Severity: check.SevHigh},
	}
	if Level(fs) != "red" {
		t.Fatalf("got %s", Level(fs))
	}
}
