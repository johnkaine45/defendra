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
