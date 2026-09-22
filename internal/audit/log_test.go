package audit

import "testing"

func TestSanitizeDropsSecrets(t *testing.T) {
	if sanitize("password=secret") != "" {
		t.Fatal("password leaked")
	}
	if sanitize("ssh-ed25519 AAAAC3") != "" {
		t.Fatal("key leaked")
	}
	if sanitize("ufw enable ok") == "" {
		t.Fatal("plain detail dropped")
	}
}
