package facts

import "testing"

func TestSystemSSHPortPrefersSSHD(t *testing.T) {
	if got := systemSSHPort(54821, 22022); got != 54821 {
		t.Fatalf("got %d", got)
	}
	if got := systemSSHPort(22, 22022); got != 22 {
		t.Fatalf("got %d", got)
	}
	if got := systemSSHPort(0, 22022); got != 22 {
		t.Fatalf("netbird session alone → 22, got %d", got)
	}
	if got := systemSSHPort(0, 54821); got != 54821 {
		t.Fatalf("got %d", got)
	}
	if got := systemSSHPort(0, 0); got != 22 {
		t.Fatalf("got %d", got)
	}
}
