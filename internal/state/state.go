package state

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const Dir = "/var/lib/defendra"

type State struct {
	ProtectedAt  *time.Time `json:"protected_at,omitempty"`
	User         string     `json:"user"`
	SSHLocked    bool       `json:"ssh_locked"`
	SiteAllowed  bool       `json:"site_allowed"`
	PanelPort    int        `json:"panel_port,omitempty"`
	PublicIP     string     `json:"public_ip,omitempty"`
	SSHPort      int        `json:"ssh_port"`
	Level        string     `json:"level"`
	Motd         string     `json:"motd"`
	Reason       string     `json:"reason,omitempty"`
	KeepPorts    []int      `json:"keep_ports,omitempty"`
	SSHUsers     []string   `json:"ssh_users,omitempty"`
	HasProtect   bool       `json:"has_protect"`
	StreetSSHOff bool       `json:"street_ssh_off,omitempty"`
	NetBirdIP    string     `json:"netbird_ip,omitempty"`
}

func Path() string { return filepath.Join(Dir, "state.json") }

func Saved() bool {
	_, err := os.Stat(Path())
	return err == nil
}
func SummaryPath() string { return filepath.Join(Dir, "summary.json") }
func MotdPath() string    { return filepath.Join(Dir, "motd.txt") }
func ScansDir() string    { return filepath.Join(Dir, "scans") }

func Load() State {
	s := loadJSON(Path())
	if s.User == "" {
		s = loadJSON(SummaryPath())
	}
	if s.User == "" {
		s.User = "admin"
	}
	if s.SSHPort == 0 {
		s.SSHPort = 22
	}
	if !s.HasProtect {
		for _, p := range []string{
			"/etc/ssh/sshd_config.d/00-defendra.conf",
			"/etc/ssh/sshd_config.d/99-defendra.conf",
		} {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			s.HasProtect = true
			s.SSHLocked = true
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "AllowUsers ") {
					fields := strings.Fields(strings.TrimPrefix(line, "AllowUsers "))
					if len(fields) > 0 {
						s.User = fields[0]
						s.SSHUsers = fields
					}
				}
			}
			break
		}
	}
	return s
}

func loadJSON(path string) State {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	return s
}

func Save(s State) error {
	if err := os.MkdirAll(Dir, 0750); err != nil {
		return err
	}
	_ = os.MkdirAll(ScansDir(), 0700)
	_ = os.MkdirAll(filepath.Join(Dir, "backups"), 0700)
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(Path(), b, 0640); err != nil {
		return err
	}
	_ = os.WriteFile(SummaryPath(), b, 0640)
	if s.Motd != "" {
		_ = os.WriteFile(MotdPath(), []byte(s.Motd+"\n"), 0644)
	}
	if s.User != "" {
		if u, err := user.Lookup(s.User); err == nil {
			gid, _ := strconv.Atoi(u.Gid)
			_ = os.Chown(Dir, 0, gid)
			_ = os.Chmod(Dir, 0750)
			_ = os.Chown(Path(), 0, gid)
			_ = os.Chmod(Path(), 0640)
			_ = os.Chown(SummaryPath(), 0, gid)
			_ = os.Chmod(SummaryPath(), 0640)
		}
	} else {
		_ = os.Chmod(Dir, 0750)
	}
	_ = pruneFiles(ScansDir(), 15)
	return nil
}

func pruneFiles(dir string, keep int) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	sort.Strings(names)
	for _, n := range names[:len(names)-keep] {
		_ = os.Remove(filepath.Join(dir, n))
	}
	return nil
}
