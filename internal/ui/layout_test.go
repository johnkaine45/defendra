package ui

import (
	"strings"
	"testing"
)

func TestPasswordBoxCloses(t *testing.T) {
	s := PasswordBox("Abc+123")
	if !strings.Contains(s, "Abc+123") {
		t.Fatal(s)
	}
	if !strings.Contains(s, "│") || !strings.Contains(s, "┘") {
		t.Fatal(s)
	}
	if strings.Count(s, "\n") < 4 {
		t.Fatal(s)
	}
	if PasswordBox("") != "" {
		t.Fatal("empty")
	}
}

func TestFirstLockRitualIsShort(t *testing.T) {
	s := FirstLockRitual("203.0.113.10", "admin", 22)
	if !strings.Contains(s, "ssh admin@203.0.113.10") {
		t.Fatal(s)
	}
	if strings.Contains(s, "-p ") {
		t.Fatal("default port must omit -p")
	}
	if strings.Contains(s, "sudo defendra undo") {
		t.Fatal("ritual must not dump rescue")
	}
	if strings.Contains(s, "how-to-login") {
		t.Fatal("ritual must not dump help")
	}
	s = FirstLockRitual("203.0.113.10", "admin", 54821)
	if !strings.Contains(s, "ssh -p 54821 admin@203.0.113.10") {
		t.Fatal(s)
	}
}

func TestFirstLockNextPointsToHelp(t *testing.T) {
	s := FirstLockNext()
	if !strings.Contains(s, "defendra how-to-login") {
		t.Fatal(s)
	}
}
