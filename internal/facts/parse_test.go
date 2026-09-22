package facts

import "testing"

func TestParseSSHDT(t *testing.T) {
	in := "permitrootlogin yes\npasswordauthentication yes\nport 22\npubkeyauthentication yes\npermitemptypasswords no\nallowusers admin deploy\n"
	f := ParseSSHDT(in)
	if f.PermitRootLogin != "yes" || f.PasswordAuth != "yes" {
		t.Fatalf("%+v", f)
	}
	if len(f.AllowUsers) != 2 || f.AllowUsers[0] != "admin" || f.AllowUsers[1] != "deploy" {
		t.Fatalf("allowusers %+v", f.AllowUsers)
	}
}

func TestParseSSHConfigEquals(t *testing.T) {
	in := "PermitRootLogin no\nPasswordAuthentication=no\n"
	f := ParseSSHDT(in)
	if f.PermitRootLogin != "no" || f.PasswordAuth != "no" {
		t.Fatalf("%+v", f)
	}
}

func TestParseSS(t *testing.T) {
	in := `LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=9,fd=5))
LISTEN 0 4096 *:6379 0.0.0.0:* users:(("redis-server",pid=8,fd=6))`
	ls := ParseSS(in)
	if len(ls) != 3 {
		t.Fatalf("len=%d", len(ls))
	}
	if ls[0].Port != 22 || !ls[0].Public() {
		t.Fatalf("%+v", ls[0])
	}
	if ls[1].Public() {
		t.Fatal("postgres localhost should not be public")
	}
	if ls[2].Addr != "0.0.0.0" || ls[2].Port != 6379 {
		t.Fatalf("%+v", ls[2])
	}
}

func TestParseUFWOpenSSH(t *testing.T) {
	in := `Status: active
Default: deny (incoming), allow (outgoing)
22/tcp (OpenSSH)           ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere`
	fw := ParseUFW(in)
	if !fw.Active || !fw.AllowsPort(22) || !fw.AllowsPort(80) {
		t.Fatalf("%+v", fw)
	}
	n22 := 0
	for _, a := range fw.Allows {
		if a == "22" || a == "22/tcp" {
			n22++
		}
	}
	if n22 != 1 {
		t.Fatalf("dup 22: %+v", fw.Allows)
	}
}

func TestParseSSPublicUDP(t *testing.T) {
	in := `UNCONN 0 0 127.0.0.54:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=3))
udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:* users:(("wg",pid=2,fd=4))
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=3,fd=5))`
	ls := ParseSS(in)
	if len(ls) != 2 {
		t.Fatalf("%+v", ls)
	}
	if ls[0].Proto != "udp" || ls[0].Port != 51820 || !ls[0].Public() {
		t.Fatalf("wg: %+v", ls[0])
	}
	if ls[1].Port != 22 {
		t.Fatalf("ssh: %+v", ls[1])
	}
}

func TestParseSSSkipsUnconn(t *testing.T) {
	in := `UNCONN 0 0 127.0.0.54:53 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`
	ls := ParseSS(in)
	if len(ls) != 1 || ls[0].Port != 22 {
		t.Fatalf("%+v", ls)
	}
}

func TestListenPublicIPv6AndMapped(t *testing.T) {
	cases := []struct {
		addr string
		pub  bool
	}{
		{"0.0.0.0", true},
		{"::", true},
		{"[::]", true},
		{"127.0.0.1", false},
		{"127.0.0.53", false},
		{"localhost", false},
		{"::1", false},
		{"[::1]", false},
		{"::ffff:127.0.0.1", false},
		{"[::ffff:127.0.0.1]", false},
		{"fe80::1", false},
		{"[fe80::1]", false},
		{"203.0.113.10", true},
		{"2001:db8::1", true},
	}
	for _, c := range cases {
		got := Listen{Addr: c.addr, Port: 80}.Public()
		if got != c.pub {
			t.Errorf("%s: got %v want %v", c.addr, got, c.pub)
		}
	}
}

func TestParseSSIPv6Localhost(t *testing.T) {
	in := `LISTEN 0 511 [::1]:80 [::]:* users:(("nginx",pid=2,fd=8))
LISTEN 0 511 *:443 *:* users:(("nginx",pid=2,fd=9))`
	ls := ParseSS(in)
	if len(ls) != 2 {
		t.Fatalf("%+v", ls)
	}
	if ls[0].Public() {
		t.Fatalf("ipv6 localhost public: %+v", ls[0])
	}
	if !ls[1].Public() || ls[1].Port != 443 {
		t.Fatalf("%+v", ls[1])
	}
}

func TestParseUFW(t *testing.T) {
	in := `Status: active
Default: deny (incoming), allow (outgoing)
To                         Action      From
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere`
	fw := ParseUFW(in)
	if !fw.Active || !fw.AllowsPort(22) || !fw.AllowsPort(80) {
		t.Fatalf("%+v", fw)
	}
}
