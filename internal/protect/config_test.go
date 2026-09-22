package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/state"
)

func TestSetConfigLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "redis.conf")
	if err := os.WriteFile(p, []byte("port 6379\nbind 0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := setConfigLine(p, "bind", "bind 127.0.0.1 -::1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "bind 127.0.0.1 -::1") {
		t.Fatal(s)
	}
	if strings.Contains(s, "bind 0.0.0.0") {
		t.Fatal(s)
	}
}

func TestLeftoverPublicPortsKeepsAppSkipsDBAndPanel(t *testing.T) {
	snap := facts.Snapshot{
		Ports: []facts.Listen{
			{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Process: "node"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 5432, Process: "postgres"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8888, Process: "aapanel"},
			{Proto: "tcp", Addr: "127.0.0.1", Port: 3000, Process: "node"},
		},
	}
	got := leftoverPublicPorts(snap, []int{22}, "tcp", []int{8888})
	if len(got) != 1 || got[0] != 8080 {
		t.Fatalf("tcp leftover %v", got)
	}
	kept := leftoverPublicPorts(snap, []int{22}, "tcp", nil)
	if len(kept) != 2 || kept[0] != 8080 || kept[1] != 8888 {
		t.Fatalf("panel kept unless declined %v", kept)
	}
}

func TestLeftoverPublicUDP(t *testing.T) {
	snap := facts.Snapshot{
		Ports: []facts.Listen{
			{Proto: "udp", Addr: "0.0.0.0", Port: 51820, Process: "wg"},
			{Proto: "udp", Addr: "127.0.0.1", Port: 53, Process: "systemd-resolve"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 80, Process: "nginx"},
		},
	}
	got := leftoverPublicPorts(snap, nil, "udp", nil)
	if len(got) != 1 || got[0] != 51820 {
		t.Fatalf("udp leftover %v", got)
	}
}

func TestSetConfigLineYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mongod.conf")
	if err := os.WriteFile(p, []byte("net:\n  bindIp: 0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := setConfigLine(p, "bindIp", "  bindIp: 127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "bindIp: 127.0.0.1") {
		t.Fatal(s)
	}
	if strings.Contains(s, "0.0.0.0") {
		t.Fatal(s)
	}
}

func TestDeclinedPanelPorts(t *testing.T) {
	snap := facts.Snapshot{Panels: []facts.Panel{{Name: "aaPanel", Port: 8888}}}
	if got := declinedPanelPorts(snap, 0); len(got) != 1 || got[0] != 8888 {
		t.Fatalf("%v", got)
	}
	if got := declinedPanelPorts(snap, 8888); len(got) != 0 {
		t.Fatalf("allowed panel %v", got)
	}
}

func TestPlannedKeepHonorsNoPanel(t *testing.T) {
	snap := facts.Snapshot{
		Host: facts.HostFact{SSHPort: 22},
		Ports: []facts.Listen{
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8080, Process: "node"},
			{Proto: "tcp", Addr: "0.0.0.0", Port: 8888, Process: "aapanel"},
		},
		Panels: []facts.Panel{{Name: "aaPanel", Port: 8888}},
	}
	st := state.State{KeepPorts: []int{8888}}
	got := plannedKeep(st, snap, 0)
	for _, p := range got {
		if p == 8888 {
			t.Fatalf("declined panel stayed in keep %v", got)
		}
	}
	yes := plannedKeep(st, snap, 8888)
	found := false
	for _, p := range yes {
		if p == 8888 {
			found = true
		}
	}
	if !found {
		t.Fatalf("allowed panel missing %v", yes)
	}
}

func TestPatchListenAddressesZero(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "postgresql.conf")
	src := "listen_addresses = '0.0.0.0'\nport = 5432\n"
	if err := os.WriteFile(p, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	if !patchListenAddressesFile(p) {
		t.Fatal("expected patch")
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "listen_addresses = 'localhost'") {
		t.Fatal(string(b))
	}
	if strings.Contains(string(b), "0.0.0.0") {
		t.Fatal(string(b))
	}
	if patchListenAddressesFile(p) {
		t.Fatal("idempotent")
	}
}

func TestUFWConfEnabled(t *testing.T) {
	if !ufwConfEnabled("ENABLED=yes\nLOGLEVEL=low\n") {
		t.Fatal("yes")
	}
	if ufwConfEnabled("ENABLED=no\n") {
		t.Fatal("no")
	}
	if ufwConfEnabled("# ENABLED=yes\nENABLED=no\n") {
		t.Fatal("comment")
	}
	if !ufwConfEnabled(`ENABLED="yes"`) {
		t.Fatal("quoted")
	}
}

func TestReplaceConfigLineDoesNotAppend(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "50-client.cnf")
	if err := os.WriteFile(p, []byte("[client]\nport = 3306\n"), 0644); err != nil {
		t.Fatal(err)
	}
	ok, err := replaceConfigLine(p, "bind-address", "bind-address = 127.0.0.1")
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	b, _ := os.ReadFile(p)
	if strings.Contains(string(b), "bind-address") {
		t.Fatal(string(b))
	}
}

func TestSSHMatchAddr(t *testing.T) {
	if sshMatchAddr("203.0.113.10") != "203.0.113.10" {
		t.Fatal("v4")
	}
	if sshMatchAddr("[2001:db8::1]") != "2001:db8::1" {
		t.Fatal("v6")
	}
	if sshMatchAddr("evil;rm") != "" || sshMatchAddr("*") != "" {
		t.Fatal("reject")
	}
	specs := sshMatchSpecs("admin", "203.0.113.10")
	if len(specs) != 3 {
		t.Fatalf("%v", specs)
	}
	if specs[2] != "user=admin" {
		t.Fatalf("user-only fallback: %v", specs)
	}
}
