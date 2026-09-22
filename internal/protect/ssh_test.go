package protect

import (
	"strings"
	"testing"
)

func TestCommentSSHLockKeys(t *testing.T) {
	in := `PasswordAuthentication yes
PermitRootLogin yes
# already
ListenAddress 0.0.0.0
`
	out, changed := commentSSHLockKeys(in)
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.Contains(out, "# defendra: PasswordAuthentication yes") {
		t.Fatalf("password: %s", out)
	}
	if !strings.Contains(out, "# defendra: PermitRootLogin yes") {
		t.Fatalf("root: %s", out)
	}
	if !strings.Contains(out, "ListenAddress 0.0.0.0") {
		t.Fatalf("listen lost: %s", out)
	}
}

func TestCommentSSHLockKeysUseDNS(t *testing.T) {
	in := "UseDNS yes\nGSSAPIAuthentication yes\nListenAddress 0.0.0.0\n"
	out, changed := commentSSHLockKeys(in)
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.Contains(out, "# defendra: UseDNS yes") {
		t.Fatalf("usedns: %s", out)
	}
	if !strings.Contains(out, "# defendra: GSSAPIAuthentication yes") {
		t.Fatalf("gssapi: %s", out)
	}
	if !strings.Contains(out, "ListenAddress 0.0.0.0") {
		t.Fatalf("listen lost: %s", out)
	}
}

func TestCommentSSHLockKeysMatchAndDeny(t *testing.T) {
	in := `Match User ubuntu
    PasswordAuthentication yes
DenyUsers admin
ListenAddress 0.0.0.0
`
	out, changed := commentSSHLockKeys(in)
	if !changed {
		t.Fatal("expected change")
	}
	if !strings.Contains(out, "# defendra:     PasswordAuthentication yes") && !strings.Contains(out, "# defendra: PasswordAuthentication yes") {
		t.Fatalf("match password: %s", out)
	}
	if !strings.Contains(out, "# defendra: DenyUsers admin") {
		t.Fatalf("deny: %s", out)
	}
	if !strings.Contains(out, "Match User ubuntu") {
		t.Fatalf("match header lost: %s", out)
	}
	if !strings.Contains(out, "ListenAddress 0.0.0.0") {
		t.Fatalf("listen lost: %s", out)
	}
}
