package protect

import (
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/state"
)

func TestStreetOffQuestion(t *testing.T) {
	q := streetOffQuestion(facts.Snapshot{
		NetBird: facts.NetBirdFact{Installed: true, Connected: true, SSHEnabled: true},
	})
	if !strings.Contains(q, "уже работает") {
		t.Fatal(q)
	}
	q = streetOffQuestion(facts.Snapshot{
		NetBird: facts.NetBirdFact{Installed: true, Connected: true},
	})
	if !strings.Contains(q, "Сейчас включу вход через NetBird") {
		t.Fatal(q)
	}
}

func TestStreetNeedsWork(t *testing.T) {
	st := state.State{}
	snap := facts.Snapshot{
		SSH:     facts.SSHFact{ListenerKnown: true, ListenerActive: true},
		NetBird: facts.NetBirdFact{Installed: true, Connected: true, SSHEnabled: true},
	}
	if streetNeedsWork(st, snap) {
		t.Fatal("offer is a separate command")
	}
	st.StreetSSHOff = true
	snap.SSH.ListenerActive = false
	if streetNeedsWork(st, snap) {
		t.Fatal("stable off")
	}
	snap.SSH.ListenerActive = true
	if !streetNeedsWork(st, snap) {
		t.Fatal("listener came back")
	}
	snap.SSH.ListenerActive = false
	snap.NetBird.SSHEnabled = false
	if !streetNeedsWork(st, snap) {
		t.Fatal("restore")
	}
}
