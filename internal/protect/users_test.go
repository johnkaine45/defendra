package protect

import (
	"testing"

	"github.com/johnkaine/defendra/internal/facts"
)

func TestValidUnixUser(t *testing.T) {
	ok := []string{"admin", "deploy", "www_data", "a1", "my-bot"}
	bad := []string{"", "root", "nobody", "Admin", "1admin", "admin!", "../x"}
	for _, n := range ok {
		if !validUnixUser(n) {
			t.Fatalf("want ok %q", n)
		}
	}
	for _, n := range bad {
		if validUnixUser(n) {
			t.Fatalf("want bad %q", n)
		}
	}
}

func TestSSHAllowUsersKeepsDeploy(t *testing.T) {
	snap := facts.Snapshot{
		Users: []facts.User{
			{Name: "root", UID: 0, HasKeys: true, Shell: "/bin/bash"},
			{Name: "admin", UID: 1000, HasKeys: true, Shell: "/bin/bash"},
			{Name: "deploy", UID: 1001, HasKeys: true, Shell: "/bin/bash"},
			{Name: "www-data", UID: 33, HasKeys: false, Shell: "/usr/sbin/nologin"},
			{Name: "sync", UID: 1002, HasKeys: true, Shell: "/usr/sbin/nologin"},
		},
	}
	got := sshAllowUsers(snap, "admin")
	if len(got) != 2 || got[0] != "admin" || got[1] != "deploy" {
		t.Fatalf("%v", got)
	}
}
