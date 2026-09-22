package protect

import "testing"

func TestSplitSSHAddr(t *testing.T) {
	h, p := splitSSHAddr("195.58.153.30:22")
	if h != "195.58.153.30" || p != "22" {
		t.Fatalf("%s %s", h, p)
	}
	h, p = splitSSHAddr("[::1]:22")
	if h != "::1" || p != "22" {
		t.Fatalf("%s %s", h, p)
	}
	if sshAddrPort("0.0.0.0:2222") != 2222 {
		t.Fatal("port")
	}
	if sshAddrHost("[2001:db8::1]:44122") != "2001:db8::1" {
		t.Fatal("host")
	}
}
