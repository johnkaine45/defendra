package protect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/johnkaine/defendra/internal/audit"
	"github.com/johnkaine/defendra/internal/backup"
	"github.com/johnkaine/defendra/internal/check"
	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/report"
	"github.com/johnkaine/defendra/internal/sshkey"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
)

func Run(ctx context.Context, hi host.Info, opt Options) int {
	u := opt.UI
	if opt.User == "" {
		opt.User = "admin"
	}
	if !validUnixUser(opt.User) {
		u.Println("Такое имя пользователя не подойдёт. Обычно достаточно:\n\n  sudo defendra protect")
		return 2
	}
	if skipQuestions(opt) {
		u.NoPrompt = true
	}

	st := state.Load()
	wasLocked := st.SSHLocked
	snap := facts.Collect(ctx, hi)
	_ = check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)

	key := opt.SSHKey
	if !check.HasSudoKey(snap) && key == "" && !skipQuestions(opt) {
		u.Println("Сейчас на сервер пускают по паролю. Так его взламывают за ночь.")
		u.Println("Чтобы закрыть пароль, нужен ключ с вашего компьютера.")
		u.Println("")
		u.Println("На каком компьютере вы сейчас сидите?")
		u.Println("")
		u.Println("  1 — Windows")
		u.Println("  2 — Mac")
		u.Println("  3 — ключ уже есть, просто вставлю")
		u.Println("  4 — пока без ключа, сделайте что можно")
		u.Println("")
		line, err := u.ReadLine()
		if err != nil {
			u.Print(ui.Interrupted())
			return 2
		}
		line = strings.TrimSpace(line)
		switch line {
		case "1":
			u.Println(`
НА СВОЁМ КОМПЬЮТЕРЕ откройте другое окно PowerShell
(это окно сервера не трогайте) и вставьте:

  ssh-keygen -t ed25519 -N "" -f $env:USERPROFILE\.ssh\id_ed25519

Enter, если спросит перезаписать — напишите n (нет), если ключ уже был.
Потом:

  type $env:USERPROFILE\.ssh\id_ed25519.pub

Скопируйте ОДНУ строку, она начинается с ssh-ed25519.
Вернитесь СЮДА и вставьте её. Enter.`)
			key = readKey(u)
		case "2":
			u.Println(`
НА СВОЁМ КОМПЬЮТЕРЕ, в другом окне:

  ssh-keygen -t ed25519 -N ""
  cat ~/.ssh/id_ed25519.pub

Вставьте СЮДА одну строку, которая начинается с ssh-ed25519.`)
			key = readKey(u)
		case "3":
			u.Println("Вставьте строку ключа (начинается с ssh-ed25519):")
			key = readKey(u)
		default:
			u.Println(`Сделаю файрвол и защиту от подбора. Пароль SSH пока останется.
Это лучше, чем ничего, но сервер ещё не закрыт.
Когда будет ключ — снова запустите: sudo defendra protect`)
		}
		if key == "abort" {
			return 2
		}
	}

	if opt.Yes {
		u.NoPrompt = true
		if st.HasProtect {
			u.Println("Проверяю защиту. Сайты и программы не трогаю.")
		} else {
			u.Println("Настраиваю сервер…")
		}
	} else if !opt.DryRun {
		ok, err := u.Confirm(`Настрою этот сервер.

С улицы не подберут пароль и не полезут в базы.
Будет пользователь ` + opt.User + `. Вход — по ключу, если ключ есть.
Уже работающие сайты и программы не трогаю.

Это не щит от атаки на канал. Её включает хостер в панели.`)
		if err != nil {
			u.Print(ui.Interrupted())
			return 2
		}
		if !ok {
			u.Println("Ничего не менял.")
			return 0
		}
	}

	allowPanel := 0
	if len(snap.Panels) > 0 {
		p := snap.Panels[0]
		if opt.Yes || opt.DryRun {
			allowPanel = p.Port
		} else {
			yes, err := u.Confirm(fmt.Sprintf(`На сервере есть панель управления (заходите в неё через браузер),
порт %d.

Оставить к ней доступ из интернета?
Если не знаете — нажмите Enter (да). Иначе панель перестанет открываться.`, p.Port))
			if err != nil {
				u.Print(ui.Interrupted())
				return 2
			}
			if yes {
				allowPanel = p.Port
			}
		}
	}

	if opt.DryRun {
		u.Println("Ничего не меняю (только показ). Было бы:")
		u.Println("  • пользователь " + opt.User)
		u.Println("  • фильтр входящих подключений, порт входа открыт")
		if allowPanel != 0 {
			u.Println("  • порт панели " + strconv.Itoa(allowPanel) + " открыт")
		} else if len(snap.Panels) > 0 {
			u.Println("  • порт панели " + strconv.Itoa(snap.Panels[0].Port) + " с улицы закрою")
		}
		u.Println("  • защита от подбора пароля")
		u.Println("  • автообновления безопасности")
		keep := plannedKeep(st, snap, allowPanel)
		if len(keep) > 0 {
			u.Println("  • уже открытые порты проектов оставлю: " + joinPorts(keep))
		}
		if check.HasSudoKey(snap) || key != "" {
			if snap.SSH.PasswordAuth != "" && !strings.EqualFold(snap.SSH.PasswordAuth, "yes") {
				u.Println("  • вход по паролю SSH останется выключенным")
			} else {
				u.Println("  • вход по паролю SSH выключится")
			}
		} else {
			u.Println("  • пароль SSH останется — нет ключа")
		}
		if snap.NetBird.Installed && snap.NetBird.Connected && !st.StreetSSHOff {
			u.Println("  • вход через NetBird есть — обычную службу с улицы выключает: sudo defendra netbird")
		}
		return 0
	}

	keep := plannedKeep(st, snap, allowPanel)
	if alreadyQuiet(st, snap, keep) {
		return finishQuiet(ctx, hi, u, st, snap, keep, opt.User)
	}

	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	signal.Ignore(syscall.SIGHUP)
	audit.Event("protect", "start", "")

	_ = backup.Rotate()
	snapPaths := []string{
		sshdDropin, sshdDropinLegacy, sysctlDropin, fail2banJail, sudoersFile, motdFile,
		autoUpgrades, "/etc/apt/apt.conf.d/51defendra-unattended",
		watchUnit, watchTimer,
		"/etc/ssh/sshd_config", "/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules",
		"/etc/redis/redis.conf", "/etc/mysql/mysql.conf.d/mysqld.cnf",
		"/etc/mongod.conf", "/etc/elasticsearch/elasticsearch.yml",
	}
	if extra, err := filepath.Glob("/etc/ssh/sshd_config.d/*.conf"); err == nil {
		snapPaths = append(snapPaths, extra...)
	}
	if pg, err := filepath.Glob("/etc/postgresql/*/main/postgresql.conf"); err == nil {
		snapPaths = append(snapPaths, pg...)
	}
	_ = backup.Snapshot(snapPaths...)
	if !st.HasProtect {
		_ = backup.SealOriginFromLast()
	}

	total := 9
	var sudoPW string

	existed := userExists(opt.User)
	if existed {
		u.Progress(1, total, "Проверяю пользователя "+opt.User+"…")
	} else {
		u.Progress(1, total, "Создаю пользователя "+opt.User+"…")
	}
	pw, err := ensureUser(ctx, opt.User, key, !st.HasProtect)
	if err != nil {
		u.Printf("Не получилось создать пользователя: %v\n", err)
		printPasswordBox(u, pw)
		return 2
	}
	sudoPW = pw
	if existed && sudoPW != "" {
		u.Println("Задал новый пароль для команды sudo. Старый больше не подойдёт.")
	}
	if sudoPW == "" && !st.HasProtect {
		if b, err := os.ReadFile(firstLogin); err == nil {
			sudoPW = strings.TrimSpace(string(b))
		}
		if sudoPW == "" {
			u.Println("Пользователь " + opt.User + " уже был, новый пароль не задавал.")
			u.Println("Если не помните пароль sudo — консоль хостера и: defendra password")
		}
	}

	if st.HasProtect {
		u.Progress(2, total, "Проверяю защиту от подбора пароля…")
	} else {
		u.Progress(2, total, "Ставлю защиту от подбора пароля…")
	}
	if !(snap.Packages.UFW && snap.Packages.Fail2ban && snap.Packages.Unattended) {
		if err := aptInstall(ctx); err != nil {
			u.Println("Не получилось поставить пакеты. Сеть или репозиторий Ubuntu. Попробуйте через 5 минут: sudo defendra protect")
			u.Printf("(%v)\n", err)
			u.Println("SSH и фильтр не трогаю.")
			printPasswordBox(u, sudoPW)
			return 2
		}
		ensureSSHListener(ctx)
	}

	if st.HasProtect {
		u.Progress(3, total, "Проверяю фильтр входящих подключений…")
	} else {
		u.Progress(3, total, "Включаю фильтр входящих подключений…")
	}
	armSSHWatchdog(ctx, snap.Host.SSHPort)
	if err := setupUFW(ctx, snap.Host.SSHPort, snap, allowPanel, keep); err != nil {
		u.Printf("Не получилось включить фильтр: %v\nSSH не закрываю.\n", err)
		printPasswordBox(u, sudoPW)
		return 2
	}

	u.Progress(4, total, "Проверяю защиту от подбора пароля…")
	banOK := true
	if err := setupFail2ban(ctx, hi.SSHClient, snap.Host.SSHPort); err != nil {
		banOK = false
		u.Println("Не запустилась защита от подбора пароля. Пароль SSH не закрываю.")
		u.Println("Повторите позже: sudo defendra protect")
	}

	u.Progress(5, total, "Проверяю автообновления безопасности…")
	_ = setupUnattended(snap.Packages.UnattendedEnabled)

	u.Progress(6, total, "Проверяю, не торчат ли базы…")
	_ = hideDatabases(ctx, snap, u, opt.Yes)

	u.Progress(7, total, "Проверяю защиту от мелкого флуда…")
	_ = setupSysctl(ctx)

	locked := false
	u.Progress(8, total, "Проверяю, можно ли закрыть пароль SSH…")
	snap2 := facts.Collect(ctx, hi)
	sshUsers := sshAllowUsers(snap2, opt.User)
	canLock := banOK && (check.UserHasKeys(snap2, opt.User) || key != "")
	if skipped := passwordOnlyLogins(snap2, opt.User); len(skipped) > 0 {
		u.Println("Пользователь " + strings.Join(skipped, ", ") + " входит только по паролю.")
		u.Println("После закрытия пароля он не зайдёт по SSH. Добавьте ему ключ или заходите как " + opt.User + ".")
		if canLock && lockBlockedByPasswordOnly(opt.Yes, skipped) {
			canLock = false
			u.Println("Пароль SSH не закрывал: есть пользователь только с паролем. Добавьте ключ или запустите без --yes.")
		} else if canLock {
			okLock, err := u.Confirm("Закрыть пароль SSH? " + strings.Join(skipped, ", ") + " больше не войдёт.")
			if err != nil || !okLock {
				canLock = false
				u.Println("Пароль SSH не закрывал.")
			}
		}
	}
	if canLock {
		if err := lockSSH(ctx, opt.User, sshUsers, hi.SSHClient); err != nil {
			u.Printf("Не закрыл пароль SSH: %v\nТекущий вход должен работать.\n", err)
		} else {
			locked = true
		}
	}

	if st.StreetSSHOff && !snap.NetBird.Ready() {
		restoreStreetSSH(ctx, snap.Host.SSHPort)
		st.StreetSSHOff = false
		u.Println("Вход через NetBird пропал. Обычную службу входа вернул, чтобы не потерять доступ.")
	} else if st.StreetSSHOff && snap.SSH.ListenerActive {
		if err := disableStreetSSH(ctx, snap.Host.SSHPort); err != nil {
			u.Printf("Обычная служба входа снова включилась, выключить не смог: %v\n", err)
		} else {
			u.Println("Обычная служба входа снова включилась сама. Снова выключил.")
		}
	}

	if !st.StreetSSHOff {
		ensureSSHListener(ctx)
	}

	u.Progress(9, total, "Сохраняю памятку…")
	_ = hardenPerms()
	_ = setupMotdWatch(ctx)

	st.HasProtect = true
	now := time.Now().UTC()
	st.ProtectedAt = &now
	st.User = opt.User
	st.SSHLocked = locked
	st.PublicIP = snap.Host.PublicIP
	st.SSHPort = snap.Host.SSHPort
	if snap.NetBird.IP != "" {
		st.NetBirdIP = snap.NetBird.IP
	}
	if allowPanel != 0 {
		st.PanelPort = allowPanel
	}
	st.KeepPorts = keep
	st.SSHUsers = sshUsers
	if listening(snap, 80) || listening(snap, 443) || snap.Firewall.AllowsPort(80) {
		st.SiteAllowed = true
	}
	snap3 := facts.Collect(ctx, hi)
	fs := check.Run(snap3, st.SiteAllowed, true, st.KeepPorts)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	st.Reason = report.Reason(fs)
	_ = state.Save(st)
	saveScan(snap3, fs)

	ip := snap.Host.PublicIP
	code := exitIfNotGreen(st.Level)
	if locked {
		audit.Event("protect", "ok", "ssh_locked")
		if wasLocked {
			u.Println("Готово. Пароль SSH выключен.")
			if st.StreetSSHOff {
				printNetBirdLogin(u, opt.User, st.NetBirdIP)
			} else {
				u.Printf("\nВход:\n\n  ssh %s@%s\n", opt.User, ip)
			}
			if code != 0 {
				u.Print("\n" + ui.PaintFirstLine(report.StatusText(snap3, fs, ip, opt.User), st.Level, u.Color))
			}
			return code
		}
		u.Print("\n" + ui.FirstLockRitual(ip, opt.User))
		printPasswordBox(u, sudoPW)
		u.Print("\n" + ui.PasswordRoles())
		u.Print("\n" + ui.FirstLockNext())
		if code != 0 {
			u.Print("\n" + ui.PaintFirstLine(report.StatusText(snap3, fs, ip, opt.User), st.Level, u.Color))
		}
		return code
	}
	if !banOK {
		audit.Event("protect", "partial", "auth_guard_failed")
		u.Println(`
Фильтр включён, но защита от подбора пароля не запустилась.
Пароль SSH не закрывал.

Повторите:
  sudo defendra protect`)
		if sudoPW != "" {
			printPasswordBox(u, sudoPW)
		}
		return 1
	}
	audit.Event("protect", "partial", "ssh_password_still_on")
	u.Println(`
Частично готово. Подбор пароля уже усложнён, файрвол включён.
Вход по паролю ещё работает — сервер не закрыт до конца.

Когда будет ключ:
  sudo defendra protect`)
	if sudoPW != "" {
		printPasswordBox(u, sudoPW)
	}
	return 1
}

func readKey(u *ui.IO) string {
	for i := 0; i < 3; i++ {
		line, err := u.ReadLine()
		if err != nil {
			return "abort"
		}
		k, why := sshkey.ParsePublic(line)
		switch why {
		case "private":
			u.Println("Это закрытый ключ. Его нельзя никому показывать и нельзя класть на сервер.")
			u.Println("Нужна другая строка, из файла .pub — она короткая и начинается с ssh-ed25519.")
		case "short":
			u.Println("Похоже, строка обрезалась. Скопируйте её целиком ещё раз.")
		case "invalid":
			u.Println("Это не похоже на ключ. Строка должна начинаться с ssh-ed25519 или ssh-rsa.")
		default:
			if fp := sshkey.Fingerprint(k); fp != "" {
				u.Println("Ключ принят: " + fp + " (это не пароль)")
			} else {
				u.Println("Ключ принят.")
			}
			return k
		}
		if i < 2 {
			u.Println("Вставьте строку ключа ещё раз.")
		}
	}
	return ""
}

func printPasswordBox(u *ui.IO, pw string) {
	box := ui.PasswordBox(pw)
	if box == "" {
		return
	}
	u.Print("\n" + u.Paint(ui.Bold, box))
}

func aptInstall(ctx context.Context) error {
	env := append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"NEEDRESTART_MODE=l",
		"NEEDRESTART_SUSPEND=1",
	)
	run := func(args ...string) error {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(cctx, args[0], args[1:]...)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("apt-get", "update", "-qq"); err != nil {
		return err
	}
	return run("apt-get", "install", "-y", "-qq", "ufw", "fail2ban", "unattended-upgrades")
}

func setupUFW(ctx context.Context, sshPort int, snap facts.Snapshot, panel int, keep []int) error {
	if sshPort == 0 {
		sshPort = 22
	}
	cur, _, _ := oscmd.Run(ctx, 10*time.Second, "ufw", "status", "verbose")
	have := facts.ParseUFW(cur)
	want := check.MergePorts([]int{sshPort, 22}, keep)
	if keepStreetOff(state.Load()) {
		want = withoutPorts(want, []int{sshPort, 22})
	}
	if listening(snap, 80) || listening(snap, 443) {
		want = check.MergePorts(want, []int{80, 443})
	}
	if panel != 0 {
		want = check.MergePorts(want, []int{panel})
	}
	declined := declinedPanelPorts(snap, panel)
	want = check.MergePorts(want, leftoverPublicPorts(snap, want, "tcp", declined))
	for _, p := range want {
		if have.AllowsProto(p, "tcp") {
			continue
		}
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "allow", strconv.Itoa(p)+"/tcp"); err != nil {
			return err
		}
	}
	for _, p := range leftoverPublicPorts(snap, nil, "udp", nil) {
		if have.AllowsProto(p, "udp") {
			continue
		}
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "allow", strconv.Itoa(p)+"/udp"); err != nil {
			return err
		}
	}
	for _, p := range declined {
		if !have.AllowsProto(p, "tcp") {
			continue
		}
		_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "delete", "allow", strconv.Itoa(p)+"/tcp")
	}
	if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "default", "allow", "outgoing"); err != nil {
		return err
	}
	if have.DefaultIn != "deny" {
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "default", "deny", "incoming"); err != nil {
			return err
		}
	}
	if !have.Active {
		if !keepStreetOff(state.Load()) {
			_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "allow", "OpenSSH")
		}
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "--force", "enable"); err != nil {
			return err
		}
	}
	if keepStreetOff(state.Load()) {
		closeStreetUFW(ctx, sshPort)
	}
	ensureSSHListener(ctx)
	out, _, _ := oscmd.Run(ctx, 10*time.Second, "ufw", "status")
	if !strings.Contains(strings.ToLower(out), "status: active") {
		return fmt.Errorf("фильтр не включился")
	}
	return nil
}

func listening(s facts.Snapshot, port int) bool {
	for _, p := range s.Ports {
		if p.Port == port && p.Public() {
			return true
		}
	}
	return false
}

func setupFail2ban(ctx context.Context, clientIP string, sshPort int) error {
	ignore := "127.0.0.1/8 ::1"
	if clientIP != "" {
		ignore += " " + clientIP
	}
	for _, ip := range establishedSSHPeers(ctx, sshPort) {
		if ip == "" || ip == clientIP {
			continue
		}
		ignore += " " + ip
	}
	if sshPort <= 0 || sshPort > 65535 {
		sshPort = 22
	}
	body := fmt.Sprintf(`[sshd]
enabled = true
backend = systemd
port = %d
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = %s
`, sshPort, ignore)
	changed, err := writeIfChanged(fail2banJail, body, 0640)
	if err != nil {
		return err
	}
	out, _, err := oscmd.Run(ctx, 8*time.Second, "systemctl", "is-active", "fail2ban")
	if err == nil && strings.TrimSpace(out) == "active" {
		if changed {
			_, _, _ = oscmd.Run(ctx, 15*time.Second, "fail2ban-client", "reload")
		}
		return nil
	}
	_, _, _ = oscmd.Run(ctx, 20*time.Second, "systemctl", "unmask", "fail2ban")
	_, _, _ = oscmd.Run(ctx, 20*time.Second, "systemctl", "enable", "--now", "fail2ban")
	for i := 0; i < 6; i++ {
		time.Sleep(400 * time.Millisecond)
		out, _, err := oscmd.Run(ctx, 8*time.Second, "systemctl", "is-active", "fail2ban")
		if err == nil && strings.TrimSpace(out) == "active" {
			return nil
		}
	}
	return fmt.Errorf("служба защиты от подбора пароля не запустилась")
}

func leftoverPublicPorts(snap facts.Snapshot, already []int, proto string, skip []int) []int {
	if proto == "" {
		proto = "tcp"
	}
	have := map[int]bool{}
	for _, p := range already {
		have[p] = true
	}
	for _, p := range skip {
		have[p] = true
	}
	var extra []int
	for _, p := range snap.Ports {
		if !p.Public() || p.Proto != proto {
			continue
		}
		if check.IsDBPort(p.Port) || have[p.Port] {
			continue
		}
		if p.NetBird() && (p.Port == 22 || p.Port == 22022) {
			continue
		}
		have[p.Port] = true
		extra = append(extra, p.Port)
	}
	return extra
}

func declinedPanelPorts(snap facts.Snapshot, allowPanel int) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range snap.Panels {
		if p.Port <= 0 || p.Port == allowPanel || seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		out = append(out, p.Port)
	}
	return out
}

func withoutPorts(ports, skip []int) []int {
	if len(skip) == 0 {
		return ports
	}
	drop := map[int]bool{}
	for _, p := range skip {
		drop[p] = true
	}
	var out []int
	for _, p := range ports {
		if !drop[p] {
			out = append(out, p)
		}
	}
	return out
}

func setupUnattended(alreadyOn bool) error {
	body := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
`
	if !alreadyOn {
		if _, err := writeIfChanged(autoUpgrades, body, 0644); err != nil {
			return err
		}
	}
	onlySec := `Unattended-Upgrade::Allowed-Origins {
        "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
`
	_, err := writeIfChanged("/etc/apt/apt.conf.d/51defendra-unattended", onlySec, 0644)
	return err
}

func setupSysctl(ctx context.Context) error {
	body := `net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_max_syn_backlog=4096
`
	changed, err := writeIfChanged(sysctlDropin, body, 0644)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	_, _, err = oscmd.Run(ctx, 15*time.Second, "sysctl", "--system")
	return err
}

func hideDatabases(ctx context.Context, snap facts.Snapshot, u *ui.IO, yes bool) error {
	type job struct {
		name, unit, hint string
		apply            func() bool
	}
	jobs := map[int]job{
		6379: {"Redis", "redis-server", "sudo systemctl restart redis-server", func() bool {
			ok, _ := setConfigLine("/etc/redis/redis.conf", "bind", "bind 127.0.0.1 -::1")
			return ok
		}},
		5432: {"PostgreSQL", "postgresql", "sudo systemctl restart postgresql", func() bool {
			return patchListenAddresses()
		}},
		3306: {"MySQL", "mysql", "sudo systemctl restart mysql", func() bool {
			return patchBindAddress()
		}},
		27017: {"MongoDB", "mongod", "sudo systemctl restart mongod", func() bool {
			ok, _ := setConfigLine("/etc/mongod.conf", "bindIp", "  bindIp: 127.0.0.1")
			return ok
		}},
		9200: {"Elasticsearch", "elasticsearch", "sudo systemctl restart elasticsearch", func() bool {
			ok, _ := setConfigLine("/etc/elasticsearch/elasticsearch.yml", "network.host", "network.host: 127.0.0.1")
			return ok
		}},
	}
	seen := map[int]bool{}
	for _, p := range snap.Ports {
		if !p.Public() || dockerishProc(p.Process) || seen[p.Port] {
			continue
		}
		j, ok := jobs[p.Port]
		if !ok {
			continue
		}
		seen[p.Port] = true
		if !j.apply() {
			u.Println(j.name + " слушает всех. Фильтр с улицы его не пускает. Лучше, чтобы программа слушала только на сервере.")
			continue
		}
		if yes {
			u.Println("Записал " + j.name + " на localhost в файле. С улицы он ещё открыт, пока не сделаете: " + j.hint)
			continue
		}
		okRestart, err := u.Confirm("Перезапущу " + j.name + ", чтобы закрыть его с улицы.\nЕсли сайт на этой базе — на секунды моргнёт.")
		if err != nil || !okRestart {
			u.Println("Настройку записал. С улицы ещё открыт, пока не сделаете: " + j.hint)
			continue
		}
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "systemctl", "restart", j.unit); err != nil {
			u.Println("Не перезапустил " + j.name + ". Сделайте сами: " + j.hint)
		}
	}
	return nil
}

func dockerishProc(proc string) bool {
	p := strings.ToLower(proc)
	return strings.Contains(p, "docker") || strings.Contains(p, "containerd")
}

func setConfigLine(path, key, replacement string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(b), "\n")
	found := false
	changed := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		k := trim
		if j := strings.IndexAny(k, " \t=:"); j >= 0 {
			k = k[:j]
		}
		if strings.EqualFold(k, key) {
			found = true
			if lines[i] != replacement {
				lines[i] = replacement
				changed = true
			}
		}
	}
	if !found {
		lines = append(lines, replacement)
		changed = true
	}
	if !changed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func replaceConfigLine(path, key, replacement string) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(b), "\n")
	found := false
	changed := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		k := trim
		if j := strings.IndexAny(k, " \t=:"); j >= 0 {
			k = k[:j]
		}
		if strings.EqualFold(k, key) {
			found = true
			if lines[i] != replacement {
				lines[i] = replacement
				changed = true
			}
		}
	}
	if !found || !changed {
		return false, nil
	}
	return true, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func patchListenAddresses() bool {
	changed := false
	matches, _ := filepath.Glob("/etc/postgresql/*/main/postgresql.conf")
	for _, f := range matches {
		if patchListenAddressesFile(f) {
			changed = true
		}
	}
	return changed
}

func patchListenAddressesFile(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	lines := strings.Split(string(b), "\n")
	changed := false
	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		key := trim
		if j := strings.IndexAny(key, " \t="); j >= 0 {
			key = key[:j]
		}
		if !strings.EqualFold(key, "listen_addresses") {
			continue
		}
		low := strings.ToLower(trim)
		if strings.Contains(low, "localhost") || strings.Contains(low, "127.0.0.1") {
			continue
		}
		if lines[i] != "listen_addresses = 'localhost'" {
			lines[i] = "listen_addresses = 'localhost'"
			changed = true
		}
	}
	if !changed {
		return false
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644) == nil
}

func patchBindAddress() bool {
	return patchBindAddressIn(
		[]string{"/etc/mysql/mysql.conf.d/*.cnf", "/etc/mysql/mariadb.conf.d/*.cnf"},
		[]string{"/etc/mysql/mysql.conf.d", "/etc/mysql/mariadb.conf.d", "/etc/mysql/conf.d"},
	)
}

func patchBindAddressIn(globs, dropinDirs []string) bool {
	changed := false
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, f := range matches {
			ok, _ := replaceConfigLine(f, "bind-address", "bind-address = 127.0.0.1")
			if ok {
				changed = true
			}
		}
	}
	if changed {
		return true
	}
	return writeMySQLBindDropin(dropinDirs)
}

func writeMySQLBindDropin(dirs []string) bool {
	body := "[mysqld]\nbind-address = 127.0.0.1\n"
	for _, dir := range dirs {
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		path := filepath.Join(dir, "zz-defendra.cnf")
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			continue
		}
		return true
	}
	return false
}

func hardenPerms() error {
	_ = os.Chmod("/etc/shadow", 0640)
	_ = os.Chmod("/etc/gshadow", 0640)
	if st, err := os.Stat("/etc/sudoers"); err == nil && st.Mode().Perm()&0002 != 0 {
		_ = os.Chmod("/etc/sudoers", 0440)
	}
	if st, err := os.Stat("/etc/ssh/sshd_config"); err == nil && st.Mode().Perm()&0002 != 0 {
		_ = os.Chmod("/etc/ssh/sshd_config", 0644)
	}
	_ = os.Chmod(firstLogin, 0600)
	_ = os.Chmod(fail2banJail, 0640)
	_ = os.Chmod(sshdDropin, 0644)
	if p, err := os.Executable(); err == nil {
		_ = os.Chmod(p, 0755)
	}
	homes, _ := filepath.Glob("/home/*/.ssh")
	for _, dir := range homes {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		name := filepath.Base(filepath.Dir(dir))
		if !validUnixUser(name) {
			continue
		}
		_ = os.Chmod(dir, 0700)
		_ = os.Chmod(filepath.Join(dir, "authorized_keys"), 0600)
		_, _, _ = oscmd.Run(context.Background(), 5*time.Second, "chown", "-R", name+":"+name, dir)
	}
	if st, err := os.Stat("/root/.ssh"); err == nil && st.IsDir() {
		_ = os.Chmod("/root/.ssh", 0700)
		_ = os.Chmod("/root/.ssh/authorized_keys", 0600)
	}
	return nil
}

func lockSSH(ctx context.Context, user string, allow []string, clientIP string) error {
	ak := filepath.Join("/home", user, ".ssh", "authorized_keys")
	b, err := os.ReadFile(ak)
	if err != nil || !sshkey.HasAny(string(b)) {
		return fmt.Errorf("у %s нет ключа, пароль SSH не закрываю", user)
	}
	_ = os.Chmod(filepath.Dir(ak), 0700)
	_ = os.Chmod(ak, 0600)
	st, err := os.Stat(ak)
	if err == nil && st.Mode().Perm()&0002 != 0 {
		return fmt.Errorf("ключ %s доступен всем на запись, пароль SSH не закрываю", user)
	}
	if len(allow) == 0 {
		allow = []string{user}
	}
	body := sshDropinBody(allow)
	if b, err := os.ReadFile(sshdDropin); err == nil && string(b) == body {
		if sshLooksLocked(ctx, user, allow, clientIP) {
			return nil
		}
	}
	rollback, err := snapshotSSHDropins()
	if err != nil {
		return err
	}
	mainPath := "/etc/ssh/sshd_config"
	mainOrig, mainErr := os.ReadFile(mainPath)
	undo := func() {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		if mainErr == nil {
			mode := os.FileMode(0644)
			if st, err := os.Stat(mainPath); err == nil {
				mode = st.Mode().Perm()
			}
			_ = os.WriteFile(mainPath, mainOrig, mode)
		}
	}
	if err := writeFile(sshdDropin, body, 0644); err != nil {
		return err
	}
	_ = os.Remove(sshdDropinLegacy)
	if err := neutralizeOtherSSHDropins(); err != nil {
		undo()
		return err
	}
	if err := neutralizeSSHMain(); err != nil {
		undo()
		return err
	}
	if err := reloadSSH(ctx); err != nil {
		undo()
		_ = reloadSSH(ctx)
		return err
	}
	out, _, err := oscmd.Run(ctx, 10*time.Second, "sshd", "-T")
	if err != nil {
		out, _, err = oscmd.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T")
	}
	if err != nil {
		undo()
		_ = reloadSSH(ctx)
		return fmt.Errorf("не смог проверить настройку входа, пароль не закрываю")
	}
	eff := facts.ParseSSHDT(out)
	if !factLooksLocked(eff) || !allowUsersApplied(eff.AllowUsers, allow) {
		undo()
		_ = reloadSSH(ctx)
		return fmt.Errorf("настройка SSH не применилась, вход не меняю")
	}
	if !sshMatchLooksLocked(ctx, user, allow, clientIP) {
		undo()
		_ = reloadSSH(ctx)
		return fmt.Errorf("настройка SSH для пользователя не применилась, вход не меняю")
	}
	return nil
}

func sshDropinBody(allow []string) string {
	if len(allow) == 0 {
		allow = []string{"admin"}
	}
	return fmt.Sprintf(`PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
UseDNS no
GSSAPIAuthentication no
ClientAliveInterval 60
ClientAliveCountMax 3
MaxAuthTries 3
AllowUsers %s
`, strings.Join(allow, " "))
}

func factLooksLocked(eff facts.SSHFact) bool {
	return !strings.EqualFold(eff.PasswordAuth, "yes") && !strings.EqualFold(eff.PermitRootLogin, "yes")
}

func sshLooksLocked(ctx context.Context, user string, allow []string, clientIP string) bool {
	eff, err := effectiveSSH(ctx)
	if err != nil || !factLooksLocked(eff) || !allowUsersApplied(eff.AllowUsers, allow) {
		return false
	}
	return sshMatchLooksLocked(ctx, user, allow, clientIP)
}

func sshMatchLooksLocked(ctx context.Context, user string, allow []string, clientIP string) bool {
	okCount := 0
	unlocked := false
	for _, spec := range sshMatchSpecs(user, clientIP) {
		match, err := effectiveSSHMatch(ctx, spec)
		if err != nil {
			continue
		}
		okCount++
		if !factLooksLocked(match) || !allowUsersApplied(match.AllowUsers, allow) {
			unlocked = true
			break
		}
	}
	return sshMatchVerified(okCount, unlocked)
}

func sshMatchVerified(okCount int, unlocked bool) bool {
	if unlocked {
		return false
	}
	return okCount > 0
}

func sshMatchSpecs(user, clientIP string) []string {
	if !validUnixUser(user) {
		return nil
	}
	seen := map[string]bool{}
	var specs []string
	add := func(addr string) {
		addr = sshMatchAddr(addr)
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		specs = append(specs, "user="+user+",host="+addr+",addr="+addr)
	}
	add("127.0.0.1")
	add(clientIP)
	specs = append(specs, "user="+user)
	return specs
}

func sshMatchAddr(ip string) string {
	ip = strings.TrimSpace(strings.Trim(ip, "[]"))
	if ip == "" || ip == "*" || ip == "0.0.0.0" || ip == "::" {
		return ""
	}
	for _, c := range ip {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '.' || c == ':'
		if !ok {
			return ""
		}
	}
	return ip
}

func sshEffectiveLocked(ctx context.Context) bool {
	eff, err := effectiveSSH(ctx)
	if err != nil {
		return false
	}
	return factLooksLocked(eff)
}

func effectiveSSH(ctx context.Context) (facts.SSHFact, error) {
	out, _, err := oscmd.Run(ctx, 10*time.Second, "sshd", "-T")
	if err != nil {
		out, _, err = oscmd.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T")
	}
	if err != nil {
		return facts.SSHFact{}, err
	}
	return facts.ParseSSHDT(out), nil
}

func effectiveSSHMatch(ctx context.Context, spec string) (facts.SSHFact, error) {
	if spec == "" || strings.ContainsAny(spec, " \t\n") {
		return facts.SSHFact{}, fmt.Errorf("bad match")
	}
	out, _, err := oscmd.Run(ctx, 10*time.Second, "sshd", "-T", "-C", spec)
	if err != nil {
		out, _, err = oscmd.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T", "-C", spec)
	}
	if err != nil {
		return facts.SSHFact{}, err
	}
	return facts.ParseSSHDT(out), nil
}

func effectiveAllowUsers(ctx context.Context) []string {
	eff, err := effectiveSSH(ctx)
	if err != nil {
		return nil
	}
	return eff.AllowUsers
}

func allowUsersApplied(got, want []string) bool {
	if len(want) == 0 {
		return true
	}
	if len(got) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, n := range got {
		have[strings.ToLower(n)] = true
	}
	for _, n := range want {
		if !have[strings.ToLower(n)] {
			return false
		}
	}
	return true
}

func setupMotdWatch(ctx context.Context) error {
	motd := "#!/bin/sh\n[ -f /var/lib/defendra/motd.txt ] && cat /var/lib/defendra/motd.txt\n"
	changed, _ := writeIfChanged(motdFile, motd, 0755)
	bin, _ := os.Executable()
	if bin == "" {
		bin = "/usr/bin/defendra"
	}
	unit := `[Unit]
Description=Defendra daily check
[Service]
Type=oneshot
ExecStart=` + bin + ` watch
`
	timer := `[Unit]
Description=Defendra daily check timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
`
	if c, _ := writeIfChanged(watchUnit, unit, 0644); c {
		changed = true
	}
	if c, _ := writeIfChanged(watchTimer, timer, 0644); c {
		changed = true
	}
	en, _, _ := oscmd.Run(ctx, 8*time.Second, "systemctl", "is-enabled", "defendra-watch.timer")
	if !changed && strings.TrimSpace(en) == "enabled" {
		return nil
	}
	if changed {
		_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "daemon-reload")
	}
	_, _, _ = oscmd.Run(ctx, 10*time.Second, "systemctl", "enable", "--now", "defendra-watch.timer")
	return nil
}

func saveScan(snap facts.Snapshot, fs []check.Finding) {
	doc := report.Build(snap, fs)
	_ = os.MkdirAll(state.ScansDir(), 0700)
	b, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(filepath.Join(state.ScansDir(), time.Now().UTC().Format("20060102T150405Z")+".json"), b, 0600)
}

func AllowSite(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool) int {
	if yes || dry {
		u.NoPrompt = true
	}
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	if !snap.Firewall.Active {
		u.Println("Сначала sudo defendra protect, потом открывайте сайт.")
		return 2
	}
	if snap.Firewall.AllowsPort(80) && snap.Firewall.AllowsPort(443) {
		u.Println("Сайт уже открыт (порты 80 и 443).")
		st.SiteAllowed = true
		_ = state.Save(st)
		return 0
	}
	ok, err := u.Confirm("Открою сайту порты 80 и 443. Фильтр останется включённым.\nSSH не трогаю.")
	if err != nil {
		return 2
	}
	if !ok {
		return 0
	}
	if dry {
		u.Println("Было бы: открыть сайту порты 80 и 443. Сервер не меняю.")
		return 0
	}
	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "allow", "80/tcp"); err != nil {
		u.Printf("Не получилось открыть сайт: %v\n", err)
		return 2
	}
	_, _, _ = oscmd.Run(ctx, 20*time.Second, "ufw", "allow", "443/tcp")
	st.SiteAllowed = true
	_ = state.Save(st)
	u.Println(`Готово. Сайт из интернета может принимать посетителей.
Если страницы ещё нет — сначала поставьте nginx/caddy,
потом обновите DNS у регистратора. Это не Defendra.`)
	return 0
}

func Undo(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool) int {
	if yes || dry {
		u.NoPrompt = true
	}
	if !backup.HasLast() {
		u.Println("Нечего откатывать. Снимка последней настройки нет.")
		return 2
	}
	if dry {
		u.Println("Ничего не меняю (только показ). Вернул бы настройки входа и фильтра как до последней команды protect.")
		return 0
	}
	ok, err := u.Confirm("Верну настройки входа и фильтра как до последней команды protect.")
	if err != nil || !ok {
		return 2
	}
	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	restored, err := backup.RestoreLast()
	if err != nil {
		u.Printf("Откат не полностью: %v\n", err)
		return 2
	}
	_ = reloadSSH(ctx)
	if backup.LastSkipsUFWRules() {
		u.Println("Старый снимок фильтра неполный. Правила входа не откатывал, чтобы не закрыть SSH.")
	} else {
		applyFirewallRestore(ctx)
	}
	_, _, _ = oscmd.Run(ctx, 15*time.Second, "systemctl", "reload", "fail2ban")
	_ = restored
	st := state.Load()
	wasStreetOff := st.StreetSSHOff
	if wasStreetOff {
		restoreStreetSSH(ctx, st.SSHPort)
		st.StreetSSHOff = false
	} else {
		forceSSHListener(ctx)
	}
	st.SSHLocked = sshEffectiveLocked(ctx)
	snap := facts.Collect(ctx, hi)
	fs := check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	st.Reason = report.Reason(fs)
	_ = state.Save(st)
	u.Println("Откат сделан. Проверьте вход.")
	if wasStreetOff {
		u.Println("Обычную службу входа с улицы вернул.")
	}
	if st.SSHLocked {
		u.Println("Вход по паролю SSH по-прежнему выключен — как в снимке.")
	} else {
		u.Println("Если пароль SSH был включён раньше — он мог вернуться.")
	}
	return 0
}

func Watch(ctx context.Context, hi host.Info) int {
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	fs := check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	st.Reason = report.Reason(fs)
	_ = state.Save(st)
	saveScan(snap, fs)
	fails := 0
	for _, f := range fs {
		if f.Status == check.Fail || f.Status == check.Warn {
			fails++
		}
	}
	audit.Watch(st.Level, fails)
	if st.Level == "green" {
		return 0
	}
	return 1
}

func sshAllowUsers(snap facts.Snapshot, admin string) []string {
	seen := map[string]bool{}
	var names []string
	add := func(name string) {
		if !validUnixUser(name) || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	add(admin)
	for _, u := range snap.Users {
		if u.UID < 1000 || u.UID == 65534 {
			continue
		}
		if !u.HasKeys || nologinShell(u.Shell) {
			continue
		}
		add(u.Name)
	}
	return names
}

func validUnixUser(name string) bool {
	if name == "" || name == "root" || name == "nobody" {
		return false
	}
	for i, c := range name {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
		if i == 0 {
			ok = (c >= 'a' && c <= 'z') || c == '_'
		}
		if !ok {
			return false
		}
	}
	return true
}

func nologinShell(shell string) bool {
	s := strings.ToLower(shell)
	return strings.Contains(s, "nologin") || strings.HasSuffix(s, "/false")
}

func joinPorts(ports []int) string {
	ss := make([]string, len(ports))
	for i, p := range ports {
		ss[i] = strconv.Itoa(p)
	}
	return strings.Join(ss, ", ")
}

func plannedKeep(st state.State, snap facts.Snapshot, panel int) []int {
	keep := check.MergePorts(st.KeepPorts, check.ProjectPorts(snap))
	keep = withoutPorts(keep, declinedPanelPorts(snap, panel))
	if st.SiteAllowed || listening(snap, 80) || listening(snap, 443) || snap.Firewall.AllowsPort(80) {
		keep = check.MergePorts(keep, []int{80, 443})
	}
	if panel != 0 {
		keep = check.MergePorts(keep, []int{panel})
	}
	return keep
}

func passwordOnlyLogins(snap facts.Snapshot, admin string) []string {
	var names []string
	for _, u := range snap.Users {
		if u.Name == admin || u.UID < 1000 || u.UID == 65534 {
			continue
		}
		if u.HasKeys || nologinShell(u.Shell) || !validUnixUser(u.Name) {
			continue
		}
		names = append(names, u.Name)
	}
	return names
}

func exitIfNotGreen(level string) int {
	if level == "green" {
		return 0
	}
	return 1
}

func skipQuestions(opt Options) bool {
	return opt.Yes || opt.DryRun
}

func alreadyQuiet(st state.State, snap facts.Snapshot, keep []int) bool {
	if !st.HasProtect || !st.SSHLocked {
		return false
	}
	if !snap.Firewall.Active || !snap.Fail2ban.Active || !snap.Packages.UnattendedEnabled {
		return false
	}
	if strings.EqualFold(snap.SSH.PasswordAuth, "yes") || strings.EqualFold(snap.SSH.PermitRootLogin, "yes") {
		return false
	}
	if snap.SSH.MaxAuthTries != "" && snap.SSH.MaxAuthTries != "3" {
		return false
	}
	if hostDBExposed(snap) {
		return false
	}
	if firewallGaps(snap) {
		return false
	}
	if keepPortsMissing(snap, keep) {
		return false
	}
	wantUsers := sshAllowUsers(snap, st.User)
	if !allowUsersApplied(snap.SSH.AllowUsers, wantUsers) {
		return false
	}
	if streetNeedsWork(st, snap) {
		return false
	}
	return samePorts(st.KeepPorts, keep)
}

func firewallGaps(snap facts.Snapshot) bool {
	if !snap.Firewall.Active {
		return true
	}
	for _, p := range snap.Ports {
		if !p.Public() || check.IsDBPort(p.Port) {
			continue
		}
		if p.NetBird() && (p.Port == 22 || p.Port == 22022) {
			continue
		}
		proto := p.Proto
		if proto == "" {
			proto = "tcp"
		}
		if !snap.Firewall.AllowsProto(p.Port, proto) {
			return true
		}
	}
	return false
}

// keepPortsMissing is true when state/planned keep ports are not open in UFW
// (e.g. after undo restored an older filter while keep_ports still remembers them).
func keepPortsMissing(snap facts.Snapshot, keep []int) bool {
	if !snap.Firewall.Active {
		return len(keep) > 0
	}
	for _, p := range keep {
		if p <= 0 {
			continue
		}
		if !snap.Firewall.AllowsPort(p) {
			return true
		}
	}
	return false
}

func hostDBExposed(snap facts.Snapshot) bool {
	for _, p := range snap.Ports {
		if p.Public() && check.IsDBPort(p.Port) && !dockerishProc(p.Process) {
			return true
		}
	}
	return false
}

func samePorts(a, b []int) bool {
	a = check.MergePorts(a)
	b = check.MergePorts(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func finishQuiet(_ context.Context, _ host.Info, u *ui.IO, st state.State, snap facts.Snapshot, keep []int, user string) int {
	_ = hardenPerms()
	st.KeepPorts = keep
	st.PublicIP = snap.Host.PublicIP
	st.SSHPort = snap.Host.SSHPort
	st.SSHLocked = true
	st.HasProtect = true
	if listening(snap, 80) || listening(snap, 443) || snap.Firewall.AllowsPort(80) {
		st.SiteAllowed = true
	}
	fs := check.Run(snap, st.SiteAllowed, true, st.KeepPorts)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	st.Reason = report.Reason(fs)
	_ = state.Save(st)
	saveScan(snap, fs)
	if st.Level == "green" {
		audit.Event("protect", "ok", "unchanged")
		u.Println("Проверил. Менять нечего.")
	} else {
		audit.Event("protect", "warn", "unchanged_"+st.Level)
		u.Println(quietNotGreenLead(fs))
	}
	u.Print(ui.PaintFirstLine(report.StatusText(snap, fs, snap.Host.PublicIP, user), st.Level, u.Color))
	return exitIfNotGreen(st.Level)
}

func quietNotGreenLead(fs []check.Finding) string {
	for _, f := range fs {
		if f.ID == "NET-DB-EXPOSED" && f.Status == check.Fail && f.Fix == "none" {
			return "Проверил. Контейнеры не трогал — так вы сами пробросили порт.\nС улицы база видна. Фильтр это не закроет."
		}
	}
	return "Проверил. Часть защиты ещё не зелёная."
}
