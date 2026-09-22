package protect

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
)

const (
	sshdDropin       = "/etc/ssh/sshd_config.d/00-defendra.conf"
	sshdDropinLegacy = "/etc/ssh/sshd_config.d/99-defendra.conf"
	sysctlDropin     = "/etc/sysctl.d/99-defendra.conf"
	fail2banJail     = "/etc/fail2ban/jail.d/defendra.conf"
	sudoersFile      = "/etc/sudoers.d/defendra-admin"
	motdFile         = "/etc/update-motd.d/99-defendra"
	watchUnit        = "/etc/systemd/system/defendra-watch.service"
	watchTimer       = "/etc/systemd/system/defendra-watch.timer"
	autoUpgrades     = "/etc/apt/apt.conf.d/20auto-upgrades"
	firstLogin       = "/var/lib/defendra/first-login.txt"
	lockPath         = "/var/lib/defendra/apply.lock"
)

type Options struct {
	User   string
	Yes    bool
	DryRun bool
	SSHKey string
	UI     *ui.IO
}

func lock() (*os.File, error) {
	if err := os.MkdirAll(state.Dir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("уже идёт другая настройка. Подождите и повторите")
	}
	return f, nil
}

func sshService(ctx context.Context) string {
	for _, name := range []string{"ssh", "sshd"} {
		out, _, _ := oscmd.Run(ctx, 5*time.Second, "systemctl", "is-active", name)
		if strings.TrimSpace(out) == "active" {
			return name
		}
	}
	return "ssh"
}

func ensureSSHListener(ctx context.Context) {
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "unmask", "ssh.socket")
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "enable", "ssh.socket")
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "start", "ssh.socket")
	out, _, _ := oscmd.Run(ctx, 5*time.Second, "systemctl", "is-active", "ssh.socket")
	if strings.TrimSpace(out) != "active" {
		_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "start", "ssh")
		_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "start", "sshd")
	}
}

func armSSHWatchdog(ctx context.Context) {
	if err := os.MkdirAll(state.Dir, 0755); err != nil {
		return
	}
	body := `#!/bin/bash
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 2
  if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -qE ':22$'; then
    exit 0
  fi
  systemctl start ssh.socket >/dev/null 2>&1 || true
  systemctl start ssh >/dev/null 2>&1 || true
  systemctl start sshd >/dev/null 2>&1 || true
done
`
	path := filepath.Join(state.Dir, "ssh-watchdog.sh")
	if err := writeFile(path, body, 0700); err != nil {
		return
	}
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemctl", "reset-failed", "defendra-ssh-watchdog.service")
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemd-run", "--unit=defendra-ssh-watchdog", "--collect", "/bin/bash", path)
}

func writeFile(path, body string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func writeIfChanged(path, body string, mode os.FileMode) (bool, error) {
	if b, err := os.ReadFile(path); err == nil && string(b) == body {
		_ = os.Chmod(path, mode)
		return false, nil
	}
	return true, writeFile(path, body, mode)
}

func randPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#%+"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

func visudoCheck(ctx context.Context, path string) error {
	_, errOut, err := oscmd.Run(ctx, 10*time.Second, "visudo", "-c", "-f", path)
	if err != nil {
		return fmt.Errorf("проверка sudo: %s", errOut)
	}
	return nil
}

func reloadSSH(ctx context.Context) error {
	svc := sshService(ctx)
	out, errOut, err := oscmd.Run(ctx, 15*time.Second, "sshd", "-t")
	if err != nil {
		return fmt.Errorf("конфиг входа сломан: %s %s", out, errOut)
	}
	_, _, err = oscmd.Run(ctx, 15*time.Second, "systemctl", "reload", svc)
	ensureSSHListener(ctx)
	return err
}

func ensureUser(ctx context.Context, name, keyLine string, uiio *ui.IO) (string, error) {
	home := "/home/" + name
	existed := userExists(name)
	if !existed {
		args := []string{"-m", "-s", "/bin/bash", "-G", "sudo"}
		if groupExists(name) {
			args = append(args, "-g", name)
		}
		args = append(args, name)
		_, errOut, err := oscmd.Run(ctx, 20*time.Second, "useradd", args...)
		if err != nil {
			_, errOut2, err2 := oscmd.Run(ctx, 20*time.Second, "adduser", "--disabled-password", "--gecos", "", name)
			if err2 != nil {
				msg := errOut
				if errOut2 != "" {
					msg = errOut + "; " + errOut2
				}
				if msg == "" {
					msg = err.Error()
				}
				return "", fmt.Errorf("%s", msg)
			}
			_, _, _ = oscmd.Run(ctx, 10*time.Second, "usermod", "-aG", "sudo", name)
		}
	} else {
		_, _, _ = oscmd.Run(ctx, 10*time.Second, "usermod", "-aG", "sudo", name)
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return "", err
	}
	if !existed {
		_, _, _ = oscmd.Run(ctx, 5*time.Second, "chown", "-R", name+":"+name, home)
	}

	ak := filepath.Join(sshDir, "authorized_keys")
	existing, _ := os.ReadFile(ak)
	merged := string(existing)
	rootKeys, _ := os.ReadFile("/root/.ssh/authorized_keys")
	for _, line := range strings.Split(string(rootKeys), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(merged, line) {
			merged = strings.TrimSpace(merged) + "\n" + line + "\n"
		}
	}
	if keyLine != "" && !strings.Contains(merged, keyLine) {
		merged = strings.TrimSpace(merged) + "\n" + keyLine + "\n"
	}
	if err := os.WriteFile(ak, []byte(strings.TrimSpace(merged)+"\n"), 0600); err != nil {
		return "", err
	}
	_, _, _ = oscmd.Run(ctx, 5*time.Second, "chown", "-R", name+":"+name, sshDir)
	_, _, _ = oscmd.Run(ctx, 5*time.Second, "chmod", "700", sshDir)
	_, _, _ = oscmd.Run(ctx, 5*time.Second, "chmod", "600", ak)

	var pw string
	if !existed {
		var err error
		pw, err = randPassword()
		if err != nil {
			return "", err
		}
		if err := chpasswd(name, pw); err != nil {
			return "", err
		}
		_ = os.MkdirAll(state.Dir, 0700)
		_ = os.WriteFile(firstLogin, []byte(pw+"\n"), 0600)
	}

	tmp := sudoersFile + ".tmp"
	body := name + " ALL=(ALL:ALL) ALL\n"
	if err := os.WriteFile(tmp, []byte(body), 0440); err != nil {
		return pw, err
	}
	if err := visudoCheck(ctx, tmp); err != nil {
		os.Remove(tmp)
		return pw, err
	}
	if err := os.Rename(tmp, sudoersFile); err != nil {
		return pw, err
	}
	_ = uiio
	return pw, nil
}

func groupExists(name string) bool {
	b, err := os.ReadFile("/etc/group")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, name+":") {
			return true
		}
	}
	return false
}

func userExists(name string) bool {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, name+":") {
			return true
		}
	}
	return false
}

func chpasswd(user, pw string) error {
	cmd := execCommand("chpasswd")
	cmd.Stdin = strings.NewReader(user + ":" + pw + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("пароль пользователя: %s %w", string(out), err)
	}
	return nil
}

func execCommand(name string, args ...string) *exec.Cmd {
	return exec.Command(name, args...)
}
