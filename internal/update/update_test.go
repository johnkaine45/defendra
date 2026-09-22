package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/johnkaine/defendra/internal/ui"
)

func TestVersionCmp(t *testing.T) {
	if versionCmp("0.1.22", "0.1.23") >= 0 {
		t.Fatal("22 < 23")
	}
	if versionCmp("0.1.23", "0.1.23") != 0 {
		t.Fatal("eq")
	}
	if versionCmp("0.1.23", "0.1.22") <= 0 {
		t.Fatal("23 > 22")
	}
	if versionCmp("v0.1.9", "0.1.10") >= 0 {
		t.Fatal("numeric")
	}
	if versionCmp("0.1.23-dev", "0.1.23") != 0 {
		t.Fatal("suffix")
	}
}

func TestTagFromLocation(t *testing.T) {
	if tagFromLocation("https://github.com/johnkaine45/defendra/releases/tag/v0.1.22") != "0.1.22" {
		t.Fatal("abs")
	}
	if tagFromLocation("/johnkaine45/defendra/releases/tag/v0.1.23?foo=1") != "0.1.23" {
		t.Fatal("rel")
	}
	if tagFromLocation("https://example.com/") != "" {
		t.Fatal("empty")
	}
}

func TestParseChecksum(t *testing.T) {
	got, err := parseChecksum("d9ebd80058c9efdc609556af3efcd6287da83176590d2b99a19020589668c803  defendra_amd64.deb\n")
	if err != nil || got != "d9ebd80058c9efdc609556af3efcd6287da83176590d2b99a19020589668c803" {
		t.Fatal(got, err)
	}
	if _, err := parseChecksum("short  file\n"); err == nil {
		t.Fatal("short")
	}
}

func TestRunAlreadyLatest(t *testing.T) {
	srv, payload := testReleaseServer(t, "0.1.22")
	defer srv.Close()
	var out bytes.Buffer
	code := Run(context.Background(), Options{
		UI:      ui.New(strings.NewReader(""), &out, &out),
		Client:  srv.Client(),
		Repo:    srv.URL,
		Current: "0.1.22",
		Arch:    "amd64",
		Install: func(context.Context, string) error { t.Fatal("must not install"); return nil },
	})
	if code != 0 {
		t.Fatal(code, out.String())
	}
	if !strings.Contains(out.String(), "Уже стоит последняя") {
		t.Fatal(out.String())
	}
	_ = payload
}

func TestRunRefuseDowngrade(t *testing.T) {
	srv, _ := testReleaseServer(t, "0.1.22")
	defer srv.Close()
	var out bytes.Buffer
	code := Run(context.Background(), Options{
		UI:      ui.New(strings.NewReader(""), &out, &out),
		Client:  srv.Client(),
		Repo:    srv.URL,
		Current: "0.1.23",
		Arch:    "amd64",
		Install: func(context.Context, string) error { t.Fatal("must not install"); return nil },
	})
	if code != 0 || !strings.Contains(out.String(), "Не откатываю") {
		t.Fatal(code, out.String())
	}
}

func TestRunDryRunNewer(t *testing.T) {
	srv, _ := testReleaseServer(t, "0.1.30")
	defer srv.Close()
	var out bytes.Buffer
	code := Run(context.Background(), Options{
		DryRun:  true,
		UI:      ui.New(strings.NewReader(""), &out, &out),
		Client:  srv.Client(),
		Repo:    srv.URL,
		Current: "0.1.22",
		Arch:    "amd64",
		Install: func(context.Context, string) error { t.Fatal("dry"); return nil },
	})
	if code != 0 || !strings.Contains(out.String(), "Поставил бы Defendra 0.1.30") {
		t.Fatal(code, out.String())
	}
}

func TestRunInstallsWhenNewer(t *testing.T) {
	srv, payload := testReleaseServer(t, "0.1.30")
	defer srv.Close()
	var got string
	var out bytes.Buffer
	code := Run(context.Background(), Options{
		Yes:     true,
		UI:      ui.New(strings.NewReader(""), &out, &out),
		Client:  srv.Client(),
		Repo:    srv.URL,
		Current: "0.1.22",
		Arch:    "amd64",
		Install: func(_ context.Context, deb string) error {
			got = deb
			b, err := os.ReadFile(deb)
			if err != nil {
				return err
			}
			if !bytes.Equal(b, payload) {
				t.Fatalf("payload")
			}
			return nil
		},
	})
	if code != 0 {
		t.Fatal(code, out.String())
	}
	if got == "" || !strings.HasSuffix(got, "defendra_0.1.30_amd64.deb") {
		t.Fatal(got)
	}
	if !strings.Contains(out.String(), "Готово. Сейчас Defendra 0.1.30") {
		t.Fatal(out.String())
	}
}

func TestRunChecksumMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/v0.1.30", http.StatusFound)
	})
	mux.HandleFunc("/releases/download/v0.1.30/defendra_0.1.30_amd64.deb", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("real-deb"))
	})
	mux.HandleFunc("/releases/download/v0.1.30/defendra_0.1.30_amd64.deb.sha256", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  defendra_0.1.30_amd64.deb\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var out bytes.Buffer
	installed := false
	code := Run(context.Background(), Options{
		Yes:     true,
		UI:      ui.New(strings.NewReader(""), &out, &out),
		Client:  srv.Client(),
		Repo:    srv.URL,
		Current: "0.1.22",
		Arch:    "amd64",
		Install: func(context.Context, string) error { installed = true; return nil },
	})
	if code != 2 || installed {
		t.Fatal(code, installed, out.String())
	}
	if !strings.Contains(out.String(), "не сошёлся") {
		t.Fatal(out.String())
	}
}

func TestRunUnknownArch(t *testing.T) {
	var out bytes.Buffer
	code := Run(context.Background(), Options{
		UI:   ui.New(strings.NewReader(""), &out, &out),
		Arch: "riscv64",
	})
	if code != 2 || !strings.Contains(out.String(), "процессор") {
		t.Fatal(code, out.String())
	}
}

func TestVerifyDeb(t *testing.T) {
	dir := t.TempDir()
	deb := filepath.Join(dir, "x.deb")
	sum := filepath.Join(dir, "x.deb.sha256")
	payload := []byte("pkg")
	if err := os.WriteFile(deb, payload, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(payload)
	if err := os.WriteFile(sum, []byte(hex.EncodeToString(h[:])+"  x.deb\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeb(deb, sum); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sum, []byte(strings.Repeat("0", 64)+"  x.deb\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeb(deb, sum); err == nil {
		t.Fatal("mismatch")
	}
}

func testReleaseServer(t *testing.T, ver string) (*httptest.Server, []byte) {
	t.Helper()
	payload := []byte("fake-deb-" + ver)
	sum := sha256.Sum256(payload)
	line := hex.EncodeToString(sum[:]) + "  defendra_" + ver + "_amd64.deb\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/releases/tag/v"+ver, http.StatusFound)
	})
	mux.HandleFunc("/releases/download/v"+ver+"/defendra_"+ver+"_amd64.deb", func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	})
	mux.HandleFunc("/releases/download/v"+ver+"/defendra_"+ver+"_amd64.deb.sha256", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(line))
	})
	return httptest.NewServer(mux), payload
}
