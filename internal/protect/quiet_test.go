package protect

import (
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/check"
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

func TestAlreadyQuietHostDB(t *testing.T) {
	st := state.State{HasProtect: true, SSHLocked: true, KeepPorts: []int{80, 443}}
	snap := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no"},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22", "80", "443"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{UnattendedEnabled: true},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, Process: "redis-server"}},
	}
	if alreadyQuiet(st, snap, []int{80, 443}) {
		t.Fatal("public host DB should not skip protect")
	}
	snap.Ports[0].Process = "docker-proxy"
	if !alreadyQuiet(st, snap, []int{80, 443}) {
		t.Fatal("docker DB is warn-only, quiet is ok")
	}
}

func TestAlreadyQuietUDPGap(t *testing.T) {
	st := state.State{HasProtect: true, SSHLocked: true, KeepPorts: []int{80, 443}}
	snap := facts.Snapshot{
		SSH:      facts.SSHFact{PermitRootLogin: "no", PasswordAuth: "no"},
		Firewall: facts.Firewall{Active: true, Allows: []string{"22/tcp", "80/tcp", "443/tcp"}},
		Fail2ban: facts.Fail2ban{Active: true},
		Packages: facts.Packages{UnattendedEnabled: true},
		Host:     facts.HostFact{SSHPort: 22},
		Ports:    []facts.Listen{{Proto: "udp", Addr: "0.0.0.0", Port: 51820, Process: "wg"}},
	}
	if alreadyQuiet(st, snap, []int{80, 443}) {
		t.Fatal("open UDP must not skip protect — would lock a VPN")
	}
	snap.Firewall.Allows = append(snap.Firewall.Allows, "51820/udp")
	if !alreadyQuiet(st, snap, []int{80, 443}) {
		t.Fatal("allowed UDP should stay quiet")
	}
}

func TestSkipQuestions(t *testing.T) {
	if !skipQuestions(Options{DryRun: true}) || !skipQuestions(Options{Yes: true}) {
		t.Fatal("dry-run and --yes must not ask")
	}
	if skipQuestions(Options{}) {
		t.Fatal("interactive still asks")
	}
}

func TestExitIfNotGreen(t *testing.T) {
	if exitIfNotGreen("green") != 0 {
		t.Fatal("green")
	}
	if exitIfNotGreen("yellow") != 1 || exitIfNotGreen("red") != 1 {
		t.Fatal("not green")
	}
}

func TestQuietNotGreenLeadDocker(t *testing.T) {
	fs := []check.Finding{{ID: "NET-DB-EXPOSED", Status: check.Fail, Fix: "none"}}
	got := quietNotGreenLead(fs)
	if !strings.Contains(got, "Контейнеры не трогал") {
		t.Fatal(got)
	}
	if strings.Contains(got, "Менять нечего") {
		t.Fatal(got)
	}
	if quietNotGreenLead(nil) != "Проверил. Часть защиты ещё не зелёная." {
		t.Fatal(quietNotGreenLead(nil))
	}
}
