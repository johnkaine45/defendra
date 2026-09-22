package host

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

type Info struct {
	Pretty    string
	ID        string
	VersionID string
	Arch      string
	Hostname  string
	Kernel    string
	Desktop   bool
	Root      bool
	UbuntuOK  bool
	SSHClient string
	SSHPort   int
}

func Detect() Info {
	info := Info{
		Root:     os.Geteuid() == 0,
		Arch:     arch(),
		Hostname: hostname(),
		Kernel:   kernel(),
	}
	osr := readOSRelease()
	info.Pretty = osr["PRETTY_NAME"]
	if info.Pretty == "" {
		info.Pretty = "неизвестно"
	}
	info.ID = osr["ID"]
	info.VersionID = osr["VERSION_ID"]
	info.UbuntuOK = ubuntuSupported(info.ID, info.VersionID)
	info.Desktop = lookDesktop()
	info.SSHClient, info.SSHPort = sshConn()
	return info
}

func sshConn() (string, int) {
	if ip, port := parseSSHConnection(os.Getenv("SSH_CONNECTION")); ip != "" {
		return ip, port
	}
	if ip, port := parseSSHClient(os.Getenv("SSH_CLIENT")); ip != "" {
		return ip, port
	}
	pid := os.Getppid()
	for i := 0; i < 12 && pid > 1; i++ {
		env := readProcEnviron(pid)
		if ip, port := parseSSHConnection(env["SSH_CONNECTION"]); ip != "" {
			return ip, port
		}
		if ip, port := parseSSHClient(env["SSH_CLIENT"]); ip != "" {
			return ip, port
		}
		pid = procPPID(pid)
	}
	return "", 22
}

func parseSSHConnection(s string) (string, int) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 22
	}
	parts := strings.Fields(s)
	if len(parts) < 4 {
		if len(parts) >= 1 {
			return parts[0], 22
		}
		return "", 22
	}
	port, _ := strconv.Atoi(parts[3])
	if port == 0 {
		port = 22
	}
	return parts[0], port
}

func parseSSHClient(s string) (string, int) {
	parts := strings.Fields(strings.TrimSpace(s))
	if len(parts) == 0 || parts[0] == "" {
		return "", 22
	}
	port := 22
	if len(parts) >= 3 {
		if n, err := strconv.Atoi(parts[2]); err == nil && n > 0 && n <= 65535 {
			port = n
		}
	}
	return parts[0], port
}

func readProcEnviron(pid int) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return m
	}
	for _, kv := range strings.Split(string(b), "\x00") {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			m[k] = v
		}
	}
	return m
}

func procPPID(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 1
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "PPid:") {
			n, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(sc.Text(), "PPid:")))
			if n <= 0 {
				return 1
			}
			return n
		}
	}
	return 1
}

func arch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func readOSRelease() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		m[k] = strings.Trim(v, `"`)
	}
	return m
}

func lookDesktop() bool {
	if _, err := os.Stat("/usr/share/xsessions"); err == nil {
		entries, _ := os.ReadDir("/usr/share/xsessions")
		if len(entries) > 0 {
			return true
		}
	}
	_, err := os.Stat("/usr/bin/gnome-shell")
	return err == nil
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func kernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func ubuntuSupported(id, versionID string) bool {
	if id != "ubuntu" {
		return false
	}
	switch versionID {
	case "22.04", "24.04", "26.04":
		return true
	default:
		return false
	}
}
