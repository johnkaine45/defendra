package protect

import (
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/johnkaine/defendra/internal/backup"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
)

func uninstallQuestion() string {
	return `Уберу Defendra с этого сервера.

Сниму программу и её настройки.
Если есть снимок — верну вход и фильтр как до последней настройки.
Пользователя admin не трогаю. Фильтр и защиту от подбора пароля пакетами не удаляю.
Обычный вход с улицы, если был выключен, верну.`
}

func Uninstall(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool) int {
	if yes {
		u.Println("Удаление --yes не делает. Запустите в терминале:\n\n  sudo defendra uninstall")
		return 2
	}
	if dry {
		u.NoPrompt = true
		u.Println("Ничего не меняю (только показ). Снял бы программу, её настройки и сторожа. Admin и пакеты фильтра оставил бы.")
		if backup.HasLast() {
			u.Println("Снимок есть — вернул бы вход и фильтр как до последней настройки.")
		}
		return 0
	}
	ok, err := u.ConfirmRemove(uninstallQuestion())
	if err != nil {
		return 2
	}
	if !ok {
		u.Println("Программу не трогаю.")
		return 0
	}

	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}

	st := state.Load()
	if st.StreetSSHOff {
		u.Println("Возвращаю обычный вход с улицы…")
		restoreStreetSSH(ctx, st.SSHPort)
	}

	hadBackup := backup.HasLast()
	if hadBackup {
		u.Println("Возвращаю настройки из снимка…")
		if _, err := backup.RestoreLast(); err != nil {
			lk.Close()
			u.Printf("Не смог откатить снимок: %v\nПрограмму не трогаю.\n", err)
			return 2
		}
		if backup.LastSkipsUFWRules() {
			u.Println("Старый снимок фильтра неполный. Правила входа не откатывал.")
		} else {
			applyFirewallRestore(ctx)
		}
		_, _, _ = oscmd.Run(ctx, 15*time.Second, "systemctl", "reload", "fail2ban")
	}

	u.Println("Снимаю сторожа и свои файлы…")
	stopWatch(ctx)
	removeOurFiles()
	_ = reloadSSH(ctx)
	forceSSHListener(ctx)

	lk.Close()

	u.Println("Удаляю пакет…")
	_ = removePackage(ctx)
	_ = os.Remove("/usr/local/bin/defendra")
	_ = os.Remove("/usr/bin/defendra")
	_ = os.RemoveAll(state.Dir)
	_ = os.RemoveAll("/etc/defendra")

	u.Println(`Готово. Defendra с сервера снята.

Пользователь admin на месте. Фильтр и защита от подбора пароля пакетами остались.
Проверьте вход с компьютера. Если что-то не так — консоль хостера.`)
	if hadBackup {
		u.Println("Настройки входа и фильтра — как в снимке до последней настройки.")
	}
	return 0
}

func stopWatch(ctx context.Context) {
	_, _, _ = oscmd.Run(ctx, 15*time.Second, "systemctl", "disable", "--now", "defendra-watch.timer")
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "stop", "defendra-watch.service")
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemctl", "reset-failed", "defendra-watch.timer")
	_, _, _ = oscmd.Run(ctx, 8*time.Second, "systemctl", "reset-failed", "defendra-watch.service")
	disarmSSHWatchdog(ctx)
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "daemon-reload")
}

func removeOurFiles() {
	for _, p := range backup.OurFiles() {
		_ = os.Remove(p)
	}
}

func removePackage(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, "apt-get", "remove", "-y", "-qq", "defendra")
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=1",
	)
	_, err := cmd.CombinedOutput()
	return err
}
