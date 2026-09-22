package facts

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/sshkey"
)

func Collect(ctx context.Context, hi host.Info) Snapshot {
	return collect(ctx, hi, false)
}

func CollectFull(ctx context.Context, hi host.Info) Snapshot {
	return collect(ctx, hi, true)
}

func collect(ctx context.Context, hi host.Info, extra bool) Snapshot {
	s := Snapshot{
		CollectedAt: time.Now().UTC(),
		Host: HostFact{
			Hostname:  hi.Hostname,
			PrettyOS:  hi.Pretty,
			ID:        hi.ID,
			VersionID: hi.VersionID,
			Arch:      hi.Arch,
			Desktop:   hi.Desktop,
			SSHClient: hi.SSHClient,
			SSHPort:   hi.SSHPort,
		},
		Sysctl: map[string]string{},
	}
	s.Host.PublicIP = firstPublicIP(ctx)
	s.SSH = collectSSH(ctx)
	s.SSH.ListenerKnown = true
	s.SSH.ListenerActive = collectSSHListener(ctx)
	s.NetBird = collectNetBird(ctx)
	if s.Host.SSHPort == 0 {
		if s.SSH.Port != 0 {
			s.Host.SSHPort = s.SSH.Port
		} else {
			s.Host.SSHPort = 22
		}
	}
	s.Users = collectUsers()
	s.Ports = collectPorts(ctx)
	s.Firewall = collectFirewall(ctx)
	s.Packages = collectPackages()
	s.Fail2ban = collectFail2ban(ctx)
	s.Sysctl = collectSysctl(ctx)
	s.Panels = detectPanels(s.Ports)
	s.Perms = collectPerms(s.Users)
	s.Sudo = collectSudo()
	if extra {
		s.SUID = collectSUID(ctx)
	}
	return s
}

func collectSSH(ctx context.Context) SSHFact {
	out, errOut, err := oscmd.Run(ctx, 10*time.Second, "sshd", "-T")
	if err != nil {
		out, errOut, err = oscmd.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T")
	}
	if err == nil {
		f := ParseSSHDT(out)
		f.ConfigOK = true
		return f
	}
	f := sshFromDropin()
	f.ConfigOK = false
	if f.ConfigError == "" {
		f.ConfigError = errOut
	}
	if f.ConfigError == "" && err != nil {
		f.ConfigError = err.Error()
	}
	return f
}

func sshFromDropin() SSHFact {
	for _, p := range []string{
		"/etc/ssh/sshd_config.d/00-defendra.conf",
		"/etc/ssh/sshd_config.d/99-defendra.conf",
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		f := ParseSSHDT(string(b))
		f.ConfigOK = true
		return f
	}
	return SSHFact{Port: 22}
}

func collectPorts(ctx context.Context) []Listen {
	out, _, err := oscmd.Run(ctx, 10*time.Second, "ss", "-lntupH")
	if err != nil {
		out, _, err = oscmd.Run(ctx, 10*time.Second, "ss", "-lntup")
		if err != nil {
			return nil
		}
	}
	return ParseSS(out)
}

func collectFirewall(ctx context.Context) Firewall {
	if !oscmd.LookPath("ufw") {
		return Firewall{}
	}
	out, _, err := oscmd.Run(ctx, 10*time.Second, "ufw", "status", "verbose")
	if err != nil {
		return Firewall{Installed: true}
	}
	return ParseUFW(out)
}

func collectPackages() Packages {
	p := Packages{
		UFW:        dpkgInstalled("ufw"),
		Fail2ban:   dpkgInstalled("fail2ban"),
		Unattended: dpkgInstalled("unattended-upgrades"),
	}
	if b, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err == nil {
		p.UnattendedEnabled = strings.Contains(string(b), `Unattended-Upgrade "1"`) ||
			strings.Contains(string(b), `Unattended-Upgrade "yes"`)
	}
	_, err := os.Stat("/var/run/reboot-required")
	p.RebootRequired = err == nil && kernelRebootPending()
	return p
}

func kernelRebootPending() bool {
	b, err := os.ReadFile("/var/run/reboot-required.pkgs")
	if err != nil || strings.TrimSpace(string(b)) == "" {
		return true
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if strings.Contains(line, "linux-image") || strings.Contains(line, "linux-generic") ||
			strings.HasPrefix(line, "linux-modules") {
			return true
		}
	}
	return false
}

func dpkgInstalled(name string) bool {
	paths := []string{"/usr/bin/" + name, "/usr/sbin/" + name, "/usr/bin/" + name + "-client", "/usr/sbin/" + name + "-server"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

func collectFail2ban(ctx context.Context) Fail2ban {
	f := Fail2ban{Installed: dpkgInstalled("fail2ban")}
	if !f.Installed {
		return f
	}
	out, _, err := oscmd.Run(ctx, 8*time.Second, "systemctl", "is-active", "fail2ban")
	f.Active = err == nil && strings.TrimSpace(out) == "active"
	if oscmd.LookPath("fail2ban-client") {
		st, _, err := oscmd.Run(ctx, 8*time.Second, "fail2ban-client", "status", "sshd")
		if err != nil {
			st, _, _ = oscmd.Run(ctx, 8*time.Second, "fail2ban-client", "status", "ssh")
		}
		f.SSHBanned = ParseFail2banSSH(st)
	}
	return f
}

func collectSysctl(ctx context.Context) map[string]string {
	keys := []string{
		"net.ipv4.tcp_syncookies",
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.all.accept_redirects",
		"net.ipv4.conf.all.send_redirects",
		"net.ipv4.icmp_echo_ignore_broadcasts",
	}
	m := map[string]string{}
	for _, k := range keys {
		out, _, err := oscmd.Run(ctx, 3*time.Second, "sysctl", "-n", k)
		if err == nil {
			m[k] = strings.TrimSpace(out)
		}
	}
	return m
}

func collectUsers() []User {
	sudoers := sudoGroupMembers()
	var users []User
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(parts[2])
		u := User{
			Name:  parts[0],
			UID:   uid,
			Home:  parts[5],
			Shell: parts[6],
			Sudo:  sudoers[parts[0]] || uid == 0,
		}
		keyPath := filepath.Join(u.Home, ".ssh", "authorized_keys")
		if b, err := os.ReadFile(keyPath); err == nil {
			u.HasKeys = sshkey.HasAny(string(b))
			if st, err := os.Stat(keyPath); err == nil {
				u.KeysMode = st.Mode().String()
			}
		}
		users = append(users, u)
	}
	return users
}

func sudoGroupMembers() map[string]bool {
	m := map[string]bool{}
	f, err := os.Open("/etc/group")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) < 4 {
			continue
		}
		if parts[0] == "sudo" || parts[0] == "admin" || parts[0] == "wheel" {
			for _, n := range strings.Split(parts[3], ",") {
				n = strings.TrimSpace(n)
				if n != "" {
					m[n] = true
				}
			}
		}
	}
	return m
}

func collectPerms(users []User) []FilePerm {
	paths := []string{
		"/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
		"/etc/ssh/sshd_config.d/00-defendra.conf", "/var/lib/defendra/first-login.txt",
		"/usr/bin/defendra", "/usr/local/bin/defendra",
	}
	for _, u := range users {
		if u.UID < 1000 || u.UID == 65534 || u.Home == "" || u.Home == "/" {
			continue
		}
		paths = append(paths, filepath.Join(u.Home, ".ssh"), filepath.Join(u.Home, ".ssh", "authorized_keys"))
	}
	var out []FilePerm
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		sys, _ := st.Sys().(*syscall.Stat_t)
		fp := FilePerm{Path: p, Mode: st.Mode().String(), Perm: uint32(st.Mode().Perm())}
		if sys != nil {
			fp.UID = int(sys.Uid)
			fp.GID = int(sys.Gid)
		}
		out = append(out, fp)
	}
	return out
}

func collectSudo() SudoFact {
	paths := []string{"/etc/sudoers"}
	if ents, err := os.ReadDir("/etc/sudoers.d"); err == nil {
		for _, e := range ents {
			paths = append(paths, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}
	sf := SudoFact{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "NOPASSWD: ALL") || strings.Contains(string(b), "NOPASSWD:ALL") {
			sf.NOPASSWDAll = true
		}
	}
	return sf
}

func collectSUID(ctx context.Context) []string {
	dirs := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib/cargo/bin"}
	seen := map[string]bool{}
	var s []string
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		out, _, err := oscmd.Run(ctx, 15*time.Second, "find", dir, "-xdev", "-perm", "-4000")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || seen[line] {
				continue
			}
			seen[line] = true
			s = append(s, line)
		}
	}
	return s
}

var panels = []Panel{
	{Name: "FastPanel / aaPanel", Port: 8888},
	{Name: "ISPmanager", Port: 1500},
	{Name: "Hestia / Vesta", Port: 8083},
	{Name: "Webmin", Port: 10000},
	{Name: "Plesk", Port: 8443},
	{Name: "CyberPanel", Port: 8090},
	{Name: "Cockpit", Port: 9090},
}

func detectPanels(ports []Listen) []Panel {
	have := map[int]bool{}
	for _, p := range ports {
		if p.Public() {
			have[p.Port] = true
		}
	}
	var found []Panel
	for _, pan := range panels {
		if have[pan.Port] {
			found = append(found, pan)
		}
	}
	return found
}

func firstPublicIP(ctx context.Context) string {
	out, _, err := oscmd.Run(ctx, 5*time.Second, "hostname", "-I")
	if err != nil {
		return ""
	}
	return pickPublicIP(strings.Fields(out))
}

func pickPublicIP(ips []string) string {
	var v6 string
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" || strings.HasPrefix(ip, "127.") {
			continue
		}
		low := strings.ToLower(ip)
		if strings.Contains(ip, ":") {
			if strings.HasPrefix(low, "fe80:") || strings.HasPrefix(low, "::1") {
				continue
			}
			if v6 == "" {
				v6 = ip
			}
			continue
		}
		if meshIPv4(ip) {
			continue
		}
		return ip
	}
	return v6
}
