package sshkey

import (
	"strings"
	"testing"
)

func TestLooksPrivate(t *testing.T) {
	if !LooksPrivate("-----BEGIN OPENSSH PRIVATE KEY-----\nabc") {
		t.Fatal("expected private")
	}
	if LooksPrivate("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJustAFakeKeyHereNotReal000000 comment") {
		t.Fatal("pubkey is not private")
	}
}

func TestParsePublic(t *testing.T) {
	k, why := ParsePublic("  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJustAFakeKeyHereNotReal000000 me@pc  ")
	if why != "" || !HasAny(k) {
		t.Fatalf("got %q %q", k, why)
	}
	_, why = ParsePublic("-----BEGIN OPENSSH PRIVATE KEY-----\nabc")
	if why != "private" {
		t.Fatalf("why=%s", why)
	}
	_, why = ParsePublic("ssh-ed25519 short")
	if why != "short" {
		t.Fatalf("why=%s", why)
	}
}

func TestFingerprint(t *testing.T) {
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl comment"
	fp := Fingerprint(line)
	if !strings.HasPrefix(fp, "SHA256:") || len(fp) < 20 {
		t.Fatalf("fp=%s", fp)
	}
}
