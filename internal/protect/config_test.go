package protect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
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
	got := leftoverPublicPorts(snap, []int{22}, "tcp")
	if len(got) != 2 || got[0] != 8080 || got[1] != 8888 {
		t.Fatalf("tcp leftover %v", got)
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
	got := leftoverPublicPorts(snap, nil, "udp")
	if len(got) != 1 || got[0] != 51820 {
		t.Fatalf("udp leftover %v", got)
	}
}
