package protect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteIfChanged(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "dropin.conf")
	changed, err := writeIfChanged(p, "hello\n", 0644)
	if err != nil || !changed {
		t.Fatalf("first: changed=%v err=%v", changed, err)
	}
	changed, err = writeIfChanged(p, "hello\n", 0644)
	if err != nil || changed {
		t.Fatalf("same: changed=%v err=%v", changed, err)
	}
	changed, err = writeIfChanged(p, "bye\n", 0600)
	if err != nil || !changed {
		t.Fatalf("diff: changed=%v err=%v", changed, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
}
