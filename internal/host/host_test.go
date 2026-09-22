package host

import "testing"

func TestParseSSHConnection(t *testing.T) {
	ip, port := parseSSHConnection("203.0.113.10 53122 192.0.2.5 22")
	if ip != "203.0.113.10" || port != 22 {
		t.Fatalf("%s %d", ip, port)
	}
	ip, _ = parseSSHConnection("")
	if ip != "" {
		t.Fatalf("empty: %s", ip)
	}
}
