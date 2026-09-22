package facts

import "testing"

func TestParseNetBirdStatusJSON(t *testing.T) {
	raw := `{
		"daemonStatus": "Connected",
		"netbirdIp": "100.127.40.14/16",
		"management": {"connected": true},
		"sshServer": {"enabled": true, "sessions": []}
	}`
	n := ParseNetBirdStatusJSON(raw)
	n.Installed = true
	if !n.Connected || !n.SSHEnabled || n.IP != "100.127.40.14" {
		t.Fatalf("%+v", n)
	}
	if !n.Ready() {
		t.Fatalf("ready %+v", n)
	}
}

func TestParseNetBirdStatusJSONOff(t *testing.T) {
	n := ParseNetBirdStatusJSON(`{"daemonStatus":"Connected","sshServer":{"enabled":false}}`)
	if !n.Connected || n.SSHEnabled || !n.SSHKnown {
		t.Fatalf("%+v", n)
	}
}

func TestParseNetBirdStatusJSONNoSSHField(t *testing.T) {
	n := ParseNetBirdStatusJSON(`{"daemonStatus":"Connected","netbirdIp":"100.64.1.1"}`)
	if n.SSHKnown || n.SSHEnabled {
		t.Fatalf("absent field must not look enabled: %+v", n)
	}
}

func TestParseNetBirdStatusText(t *testing.T) {
	n := ParseNetBirdStatusText("Daemon status: Connected\nNetBird IP: 100.127.40.14/16\nSSH Server: Enabled\n")
	if !n.Connected || !n.SSHEnabled || n.IP != "100.127.40.14" {
		t.Fatalf("%+v", n)
	}
}

func TestParseNetBirdConfigSSH(t *testing.T) {
	allowed, ok := ParseNetBirdConfigSSH([]byte(`{"ServerSSHAllowed": true}`))
	if !ok || !allowed {
		t.Fatal("allowed")
	}
	allowed, ok = ParseNetBirdConfigSSH([]byte(`{"ServerSSHAllowed": false}`))
	if !ok || allowed {
		t.Fatal("off")
	}
	if _, ok := ParseNetBirdConfigSSH([]byte(`not json`)); ok {
		t.Fatal("junk")
	}
}

func TestMeshIPv4(t *testing.T) {
	if !meshIPv4("100.64.0.1") || !meshIPv4("100.127.1.2") {
		t.Fatal("mesh")
	}
	if meshIPv4("100.63.0.1") || meshIPv4("195.58.153.30") || meshIPv4("10.0.0.1") {
		t.Fatal("not mesh")
	}
}

func TestListenNetBird(t *testing.T) {
	if !(Listen{Process: `users:(("netbird",pid=1))`}).NetBird() {
		t.Fatal("netbird")
	}
	if (Listen{Process: "sshd"}).NetBird() {
		t.Fatal("sshd")
	}
}
