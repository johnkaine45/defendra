package protect

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
)

func streetNeedsWork(st state.State, snap facts.Snapshot) bool {
	if st.StreetSSHOff && !snap.NetBird.Ready() {
		return true
	}
	if st.StreetSSHOff && snap.SSH.ListenerKnown && snap.SSH.ListenerActive {
		return true
	}
	return false
}

func streetOffQuestion(snap facts.Snapshot) string {
	if snap.NetBird.Ready() {
		return `Вход через NetBird уже работает.
Выключить обычную службу входа с улицы?

С публичного адреса зайти будет нельзя.
Только NetBird (на своём компьютере он тоже должен быть) или консоль хостера.`
	}
	return `Вижу NetBird. Сейчас включу вход через NetBird
и выключу обычную службу входа с улицы.

С публичного адреса зайти будет нельзя.
Только NetBird (на своём компьютере он тоже должен быть) или консоль хостера.`
}

func applyStreetOff(ctx context.Context, hi host.Info, u *ui.IO, snap facts.Snapshot) bool {
	if !snap.NetBird.Ready() {
		u.Println("Включаю вход через NetBird…")
		if err := enableNetBirdSSH(ctx); err != nil {
			u.Println("Не включил вход через NetBird. Обычную службу входа не трогаю.")
			u.Printf("(%v)\n", err)
			return false
		}
		check := facts.Collect(ctx, hi)
		if !check.NetBird.Ready() {
			u.Println("Вход через NetBird не подтвердился. Обычную службу входа не трогаю.")
			return false
		}
	}
	if err := disableStreetSSH(ctx, snap.Host.SSHPort); err != nil {
		u.Println("Не выключил обычную службу входа. Её оставляю включённой.")
		u.Printf("(%v)\n", err)
		restoreStreetSSH(ctx, snap.Host.SSHPort)
		return false
	}
	return true
}

func enableNetBirdSSH(ctx context.Context) error {
	if !oscmd.LookPath("netbird") {
		return fmt.Errorf("NetBird не найден")
	}
	_, errOut, err := oscmd.Run(ctx, 45*time.Second, "netbird", "up", "--allow-server-ssh")
	if err != nil {
		if errOut != "" {
			return fmt.Errorf("%s", errOut)
		}
		return err
	}
	return nil
}

func disableStreetSSH(ctx context.Context, port int) error {
	disarmSSHWatchdog(ctx)
	for _, name := range []string{"ssh.socket", "ssh", "sshd"} {
		_, _, _ = oscmd.Run(ctx, 15*time.Second, "systemctl", "stop", name)
		_, _, _ = oscmd.Run(ctx, 15*time.Second, "systemctl", "disable", name)
	}
	closeStreetUFW(ctx, port)
	if streetListenerUp(ctx) {
		return fmt.Errorf("служба входа всё ещё запущена")
	}
	return nil
}

func restoreStreetSSH(ctx context.Context, port int) {
	if port <= 0 || port > 65535 {
		port = 22
	}
	if oscmd.LookPath("ufw") {
		_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "allow", fmt.Sprintf("%d/tcp", port))
		if port != 22 {
			_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "allow", "22/tcp")
		}
	}
	forceSSHListener(ctx)
}

func closeStreetUFW(ctx context.Context, port int) {
	if !oscmd.LookPath("ufw") {
		return
	}
	_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "delete", "allow", "22/tcp")
	_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "delete", "allow", "OpenSSH")
	if port > 0 && port != 22 {
		_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "delete", "allow", fmt.Sprintf("%d/tcp", port))
	}
}

func streetListenerUp(ctx context.Context) bool {
	for _, name := range []string{"ssh.socket", "ssh", "sshd"} {
		out, _, _ := oscmd.Run(ctx, 5*time.Second, "systemctl", "is-active", name)
		if strings.TrimSpace(out) == "active" {
			return true
		}
	}
	return false
}

func disarmSSHWatchdog(ctx context.Context) {
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemctl", "stop", "defendra-ssh-watchdog.service")
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemctl", "reset-failed", "defendra-ssh-watchdog.service")
}

func keepStreetOff(st state.State) bool {
	return st.StreetSSHOff
}

func StreetOff(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool) int {
	if yes || dry {
		u.NoPrompt = true
	}
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	user := st.User
	if user == "" {
		user = "admin"
	}
	if dry {
		if st.StreetSSHOff && !snap.SSH.ListenerActive {
			u.Println("Ничего не меняю (только показ). Обычный вход с улицы уже выключен.")
			return 0
		}
		if snap.NetBird.Installed && snap.NetBird.Connected {
			u.Println("Ничего не меняю (только показ). Включил бы вход через NetBird, если его ещё нет, и выключил бы обычную службу входа с улицы.")
			return 0
		}
		u.Println("Ничего не меняю (только показ). NetBird не готов — обычную службу входа не трогал бы.")
		return 0
	}
	if yes {
		u.Println("Обычную службу входа --yes не выключает. Запустите в терминале:\n\n  sudo defendra netbird")
		return 2
	}
	if st.StreetSSHOff && snap.SSH.ListenerKnown && !snap.SSH.ListenerActive {
		u.Println("Обычный вход с улицы уже выключен.")
		printNetBirdLogin(u, user, netBirdIP(st, snap))
		u.Println("\nВернуть обычную службу входа:\n\n  sudo defendra street")
		return 0
	}
	if !snap.NetBird.Installed {
		u.Println("NetBird на этом сервере не вижу. Обычную службу входа не трогаю.")
		return 2
	}
	if !snap.NetBird.Connected {
		u.Println("NetBird не подключён. Сначала включите его, потом:\n\n  sudo defendra netbird")
		return 2
	}
	if !st.HasProtect && !st.SSHLocked {
		u.Println("Сначала защита:\n\n  sudo defendra protect\n\nПотом можно выключить обычный вход:\n\n  sudo defendra netbird")
		return 2
	}
	ok, err := u.ConfirmStrict(streetOffQuestion(snap))
	if err != nil {
		u.Print(ui.Interrupted())
		return 2
	}
	if !ok {
		u.Println("Обычную службу входа не трогал.")
		return 0
	}
	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	if !applyStreetOff(ctx, hi, u, snap) {
		return 0
	}
	st.StreetSSHOff = true
	if ip := netBirdIP(st, snap); ip != "" {
		st.NetBirdIP = ip
	} else {
		later := facts.Collect(ctx, hi)
		st.NetBirdIP = later.NetBird.IP
	}
	_ = state.Save(st)
	u.Println("Обычную службу входа с улицы выключил. Заходите через NetBird.")
	printNetBirdLogin(u, user, st.NetBirdIP)
	return 0
}

func StreetOn(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool) int {
	if yes || dry {
		u.NoPrompt = true
	}
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	user := st.User
	if user == "" {
		user = "admin"
	}
	port := snap.Host.SSHPort
	if port <= 0 {
		port = st.SSHPort
	}
	if dry {
		if streetListenerUp(ctx) && !st.StreetSSHOff {
			u.Println("Ничего не меняю (только показ). Обычная служба входа уже работает.")
			return 0
		}
		u.Println("Ничего не меняю (только показ). Вернул бы обычную службу входа с улицы. Вход через NetBird останется.")
		return 0
	}
	if streetListenerUp(ctx) && !st.StreetSSHOff {
		u.Println("Обычная служба входа уже работает.")
		if ip := snap.Host.PublicIP; ip != "" {
			u.Printf("\nВход с улицы:\n\n  ssh %s@%s\n", user, ip)
		}
		return 0
	}
	if !yes {
		ok, err := u.Confirm(`Верну обычную службу входа с улицы.
С публичного адреса снова можно будет зайти.
Вход через NetBird останется.`)
		if err != nil {
			u.Print(ui.Interrupted())
			return 2
		}
		if !ok {
			u.Println("Обычную службу входа не включал.")
			return 0
		}
	}
	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	restoreStreetSSH(ctx, port)
	armSSHWatchdog(ctx, port)
	if !streetListenerUp(ctx) {
		u.Println("Не получилось включить обычную службу входа. Консоль хостера и: sudo defendra undo")
		return 2
	}
	st.StreetSSHOff = false
	if snap.NetBird.IP != "" {
		st.NetBirdIP = snap.NetBird.IP
	}
	_ = state.Save(st)
	u.Println("Обычную службу входа с улицы включил.")
	ip := snap.Host.PublicIP
	if ip == "" {
		ip = st.PublicIP
	}
	if ip != "" {
		u.Printf("\nВход с улицы:\n\n  ssh %s@%s\n", user, ip)
	}
	if nb := netBirdIP(st, snap); nb != "" {
		u.Printf("\nЧерез NetBird по-прежнему:\n\n  ssh %s@%s\n", user, nb)
	}
	return 0
}

func netBirdIP(st state.State, snap facts.Snapshot) string {
	if snap.NetBird.IP != "" {
		return snap.NetBird.IP
	}
	return st.NetBirdIP
}

func printNetBirdLogin(u *ui.IO, user, ip string) {
	if user == "" {
		user = "admin"
	}
	if ip == "" {
		ip = "АДРЕС_NETBIRD"
	}
	u.Printf("\nВход через NetBird (на своём компьютере он тоже должен быть):\n\n  ssh %s@%s\n", user, ip)
	u.Printf("\nили:\n\n  netbird ssh %s@%s\n", user, ip)
}
