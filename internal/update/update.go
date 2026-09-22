package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/ui"
	"github.com/johnkaine/defendra/internal/version"
)

const (
	defaultRepo = "https://github.com/johnkaine45/defendra"
	defaultAPI  = "https://api.github.com/repos/johnkaine45/defendra/releases/latest"
	maxDeb      = 50 << 20
)

type Options struct {
	Yes, DryRun bool
	UI          *ui.IO
	Client      *http.Client
	Repo        string
	API         string
	Current     string
	Arch        string
	Install     func(ctx context.Context, debPath string) error
}

func Run(ctx context.Context, opt Options) int {
	u := opt.UI
	if opt.Yes || opt.DryRun {
		u.NoPrompt = true
	}
	arch := opt.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if arch != "amd64" && arch != "arm64" {
		u.Println("Этот процессор программа пока не обновляет сама.")
		u.Println("Скачайте файл вручную — в справке блок «Поставить Defendra»: defendra help")
		return 2
	}
	cur := strings.TrimPrefix(strings.TrimSpace(opt.Current), "v")
	if cur == "" {
		cur = strings.TrimPrefix(version.Version, "v")
	}

	u.Println("Смотрю, есть ли новая версия…")
	latest, err := latestVersion(ctx, opt)
	if err != nil {
		u.Println("Не получилось узнать новую версию. Сеть или сайт с программой. Попробуйте через 5 минут.")
		return 2
	}
	cmp := versionCmp(cur, latest)
	if cmp > 0 {
		u.Println("У вас " + cur + ", на сайте " + latest + ". Не откатываю.")
		return 0
	}
	if cmp == 0 {
		u.Println("Уже стоит последняя версия. Сейчас " + cur + ".")
		return 0
	}
	if opt.DryRun {
		u.Println("Ничего не меняю (только показ). Поставил бы Defendra " + latest + " вместо " + cur + ".")
		return 0
	}
	ok, err := u.Confirm("На сайте есть Defendra " + latest + ". Сейчас у вас " + cur + ".\nПоставить новую? Вход и сайт не сбросятся.")
	if err != nil || !ok {
		u.Println("Ничего не менял.")
		return 0
	}

	dir, err := os.MkdirTemp("", "defendra-update-")
	if err != nil {
		u.Println("Не получилось создать папку для загрузки.")
		return 2
	}
	defer os.RemoveAll(dir)

	debName := "defendra_" + latest + "_" + arch + ".deb"
	debURL := strings.TrimRight(repoURL(opt), "/") + "/releases/download/v" + latest + "/" + debName
	sumURL := debURL + ".sha256"
	debPath := filepath.Join(dir, debName)
	sumPath := filepath.Join(dir, debName+".sha256")

	u.Println("Скачиваю " + latest + "…")
	if err := downloadFile(ctx, opt, debURL, debPath, maxDeb); err != nil {
		u.Println("Не получилось скачать файл. Сеть или сайт с программой. Попробуйте через 5 минут.")
		return 2
	}
	if err := downloadFile(ctx, opt, sumURL, sumPath, 4096); err != nil {
		u.Println("Не получилось скачать проверку файла. Не ставлю.")
		return 2
	}
	u.Println("Проверяю файл…")
	if err := verifyDeb(debPath, sumPath); err != nil {
		u.Println("Файл с сайта не сошёлся. Не ставлю. Попробуйте позже.")
		return 2
	}
	u.Println("Ставлю…")
	install := opt.Install
	if install == nil {
		install = aptInstallDeb
	}
	if err := install(ctx, debPath); err != nil {
		u.Println("Не получилось поставить пакет. Попробуйте через 5 минут: sudo defendra update")
		return 2
	}
	u.Println("Готово. Сейчас Defendra " + latest + ".")
	u.Println("Проверьте защиту: sudo defendra protect")
	return 0
}

func repoURL(opt Options) string {
	if opt.Repo != "" {
		return opt.Repo
	}
	return defaultRepo
}

func latestVersion(ctx context.Context, opt Options) (string, error) {
	c := lookupClient(opt)
	repo := strings.TrimRight(repoURL(opt), "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Defendra/"+version.Version)
	resp, err := c.Do(req)
	if err != nil {
		return latestFromAPI(ctx, opt)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "" {
		if tag := tagFromLocation(loc); tag != "" {
			return tag, nil
		}
	}
	if tag := tagFromLocation(resp.Request.URL.String()); tag != "" {
		return tag, nil
	}
	return latestFromAPI(ctx, opt)
}

func latestFromAPI(ctx context.Context, opt Options) (string, error) {
	api := opt.API
	if api == "" {
		api = defaultAPI
	}
	c := downloadClient(opt)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Defendra/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("api %d", resp.StatusCode)
	}
	var doc struct {
		Tag string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", err
	}
	tag := strings.TrimPrefix(strings.TrimSpace(doc.Tag), "v")
	if tag == "" {
		return "", fmt.Errorf("empty tag")
	}
	return tag, nil
}

func lookupClient(opt Options) *http.Client {
	base := downloadClient(opt)
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: base.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func downloadClient(opt Options) *http.Client {
	if opt.Client != nil {
		return opt.Client
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func downloadFile(ctx context.Context, opt Options, rawURL, dest string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Defendra/"+version.Version)
	resp, err := downloadClient(opt).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("too large")
	}
	return nil
}

func verifyDeb(debPath, sumPath string) error {
	want, err := parseChecksumFile(sumPath)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(debPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("checksum")
	}
	return nil
}

func parseChecksumFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return parseChecksum(string(b))
}

func parseChecksum(s string) (string, error) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		h := strings.ToLower(fields[0])
		if len(h) != 64 {
			return "", fmt.Errorf("bad checksum")
		}
		for _, c := range h {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return "", fmt.Errorf("bad checksum")
			}
		}
		return h, nil
	}
	return "", fmt.Errorf("empty checksum")
}

func tagFromLocation(loc string) string {
	loc = strings.TrimSpace(loc)
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return ""
	}
	tag := loc[i+len("/tag/"):]
	if j := strings.IndexAny(tag, "/?#"); j >= 0 {
		tag = tag[:j]
	}
	return strings.TrimPrefix(tag, "v")
}

func versionCmp(a, b string) int {
	pa := parseVer(a)
	pb := parseVer(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func parseVer(s string) []int {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func aptInstallDeb(ctx context.Context, debPath string) error {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "apt-get", "install", "-y", "-qq", debPath)
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=1",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
