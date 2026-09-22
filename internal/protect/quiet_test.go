package protect

import (
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/state"
)

func TestAlreadyQuiet(t *testing.T) {
	st := state.State{HasProtect: true, SSHLocked: true, KeepPorts: []int{80, 443}}
	snap := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no"},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22", "80", "443"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{UnattendedEnabled: true},
		Host:     facts.HostFact{SSHPort: 22},
	}
	keep := []int{80, 443}
	if !alreadyQuiet(st, snap, keep) {
		t.Fatal("expected quiet")
	}
	st.SSHLocked = false
	if alreadyQuiet(st, snap, keep) {
		t.Fatal("unlocked should not be quiet")
	}
}

func TestAlreadyQuietNewPort(t *testing.T) {
	st := state.State{HasProtect: true, SSHLocked: true, KeepPorts: []int{80, 443}}
	snap := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no"},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22", "80", "443"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{UnattendedEnabled: true},
		Host:     facts.HostFact{SSHPort: 22},
	}
	if alreadyQuiet(st, snap, []int{80, 443, 3000}) {
		t.Fatal("new port should run full protect")
	}
}
