package host

import "testing"

func TestUbuntuSupported(t *testing.T) {
	ok := [][2]string{{"ubuntu", "22.04"}, {"ubuntu", "24.04"}, {"ubuntu", "26.04"}}
	for _, p := range ok {
		if !ubuntuSupported(p[0], p[1]) {
			t.Fatalf("want ok %s %s", p[0], p[1])
		}
	}
	bad := [][2]string{{"ubuntu", "25.04"}, {"ubuntu", "20.04"}, {"debian", "12"}, {"", "26.04"}}
	for _, p := range bad {
		if ubuntuSupported(p[0], p[1]) {
			t.Fatalf("want no %s %s", p[0], p[1])
		}
	}
}

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

func TestParseSSHClientPort(t *testing.T) {
	ip, port := parseSSHClient("203.0.113.10 53122 2222")
	if ip != "203.0.113.10" || port != 2222 {
		t.Fatalf("%s %d", ip, port)
	}
	ip, port = parseSSHClient("203.0.113.10")
	if ip != "203.0.113.10" || port != 22 {
		t.Fatalf("short %s %d", ip, port)
	}
}
