package check

import (
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
)

func TestRootLoginClosed(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
	}
	fs := Run(s, true, true, nil)
	for _, f := range fs {
		if f.ID == "SSH-ROOT-LOGIN" && f.Status != Pass {
			t.Fatalf("%+v", f)
		}
		if f.ID == "SSH-PASSWORD" && f.Status != Pass {
			t.Fatalf("%+v", f)
		}
	}
}

func TestSSHPasswordFail(t *testing.T) {
	s := facts.Snapshot{
		SSH:  facts.SSHFact{PermitRootLogin: "yes", PasswordAuth: "yes", EmptyPasswords: "no", Port: 22},
		Host: facts.HostFact{SSHPort: 22},
	}
	fs := Run(s, false, false, nil)
	got := map[string]Status{}
	for _, f := range fs {
		got[f.ID] = f.Status
	}
	if got["SSH-PASSWORD"] != Fail {
		t.Fatalf("password: %v", got["SSH-PASSWORD"])
	}
	if got["SSH-NO-KEY"] != Fail {
		t.Fatalf("nokey: %v", got["SSH-NO-KEY"])
	}
}

func TestSSHEmptyIsFail(t *testing.T) {
	s := facts.Snapshot{SSH: facts.SSHFact{}, Host: facts.HostFact{SSHPort: 22}}
	fs := Run(s, false, false, nil)
	got := map[string]Status{}
	for _, f := range fs {
		got[f.ID] = f.Status
	}
	if got["SSH-ROOT-LOGIN"] != Fail || got["SSH-PASSWORD"] != Fail {
		t.Fatalf("%v", got)
	}
}

func TestDBExposed(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Addr: "0.0.0.0", Port: 6379, Proto: "tcp", Process: "redis-server"}},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
	}
	fs := Run(s, false, true, nil)
	for _, f := range fs {
		if f.ID == "NET-DB-EXPOSED" && f.Status != Fail {
			t.Fatalf("%+v", f)
		}
	}
}

func TestWebLocalhostNotBlocked(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Addr: "127.0.0.1", Port: 80, Proto: "tcp", Process: "nginx"}},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
	}
	fs := Run(s, false, true, nil)
	for _, f := range fs {
		if f.ID == "FW-WEB-BLOCKED" && f.Status != Pass {
			t.Fatalf("%+v", f)
		}
	}
}

func TestSSHKeysWorldReadable(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
		Perms: []facts.FilePerm{
			{Path: "/home/admin/.ssh", Perm: 0755},
			{Path: "/home/admin/.ssh/authorized_keys", Perm: 0644},
		},
	}
	fs := Run(s, false, true, nil)
	for _, f := range fs {
		if f.ID == "PERM-SHADOW" && f.Status != Fail {
			t.Fatalf("%+v", f)
		}
	}
}

func TestShadowWorldReadable(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
		Perms:    []facts.FilePerm{{Path: "/etc/shadow", Perm: 0644}},
	}
	fs := Run(s, false, true, nil)
	for _, f := range fs {
		if f.ID == "PERM-SHADOW" && f.Status != Fail {
			t.Fatalf("%+v", f)
		}
	}
}

func TestUnexpectedPortDedupesIPv6(t *testing.T) {
	s := facts.Snapshot{
		SSH:  facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host: facts.HostFact{SSHPort: 22},
		Ports: []facts.Listen{
			{Addr: "0.0.0.0", Port: 8080, Proto: "tcp", Process: "docker-proxy"},
			{Addr: "::", Port: 8080, Proto: "tcp", Process: "docker-proxy"},
		},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22", "80", "443"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
	}
	fs := Run(s, true, true, nil)
	for _, f := range fs {
		if f.ID == "NET-UNEXPECTED-PORT" {
			if f.Status != Fail {
				t.Fatalf("%+v", f)
			}
			if strings.Contains(f.Plain, "8080, 8080") {
				t.Fatalf("duplicated port: %s", f.Plain)
			}
		}
	}
}

func TestKeepPortsNotUnexpected(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Addr: "0.0.0.0", Port: 3000, Proto: "tcp", Process: "docker-proxy"}},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22", "80", "443", "3000"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
	}
	fs := Run(s, true, true, []int{3000})
	for _, f := range fs {
		if f.ID == "NET-UNEXPECTED-PORT" && f.Status != Pass {
			t.Fatalf("%+v", f)
		}
	}
}

func TestDockerDBNotAutomatic(t *testing.T) {
	s := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no", EmptyPasswords: "no"},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Addr: "0.0.0.0", Port: 6379, Proto: "tcp", Process: "docker-proxy"}},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{Unattended: true, UnattendedEnabled: true},
		Sysctl:   map[string]string{"net.ipv4.tcp_syncookies": "1"},
		Users:    []facts.User{{Name: "admin", UID: 1000, Sudo: true, HasKeys: true}},
	}
	fs := Run(s, false, true, nil)
	for _, f := range fs {
		if f.ID == "NET-DB-EXPOSED" {
			if f.Status != Fail || f.Automatic {
				t.Fatalf("%+v", f)
			}
		}
	}
}

func TestMergePortsSortUnique(t *testing.T) {
	got := MergePorts([]int{443, 22, 80}, []int{80, 22}, []int{0, 99999})
	if len(got) != 3 || got[0] != 22 || got[1] != 80 || got[2] != 443 {
		t.Fatalf("%v", got)
	}
}

func TestProjectPortsSkipsRedis(t *testing.T) {
	s := facts.Snapshot{
		Host: facts.HostFact{SSHPort: 22},
		Ports: []facts.Listen{
			{Addr: "0.0.0.0", Port: 22, Proto: "tcp", Process: "sshd"},
			{Addr: "0.0.0.0", Port: 80, Proto: "tcp", Process: "nginx"},
			{Addr: "0.0.0.0", Port: 6379, Proto: "tcp", Process: "redis-server"},
			{Addr: "0.0.0.0", Port: 8888, Proto: "tcp", Process: "aapanel"},
			{Addr: "0.0.0.0", Port: 3000, Proto: "tcp", Process: "docker-proxy"},
			{Addr: "127.0.0.1", Port: 4000, Proto: "tcp", Process: "docker-proxy"},
		},
	}
	got := ProjectPorts(s)
	if len(got) != 3 || got[0] != 80 || got[1] != 8888 || got[2] != 3000 {
		t.Fatalf("want 80,8888,3000 got %v", got)
	}
}
