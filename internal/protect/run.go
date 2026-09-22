package protect

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
		u.Println("Чтобы закрыть пароль, нужен ключ с ВАШЕГО компьютера.")
		u.Println("")
		u.Println("На каком компьютере вы сейчас сидите?")
		u.Println("  1 — Windows")
		u.Println("  2 — Mac")
		u.Println("  3 — ключ уже есть, просто вставлю")
		u.Println("  4 — пока без ключа, сделайте что можно")
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
		ok, err := u.Confirm(`Настрою этот сервер так, чтобы с улицы не подбирали пароль
и не лезли в базы.

Будет пользователь ` + opt.User + `. Вход — по ключу, если ключ есть.
Фильтр входящих подключений включу.
Уже работающие сайты и программы не трогаю.

Это не щит от большой атаки на канал. Её включает хостер в панели.`)
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
	audit.Event("protect", "start", "")

	_ = backup.Rotate()
	snapPaths := []string{
		sshdDropin, sshdDropinLegacy, sysctlDropin, fail2banJail, sudoersFile, motdFile,
		autoUpgrades, "/etc/apt/apt.conf.d/51defendra-unattended",
		watchUnit, watchTimer,
		"/etc/ssh/sshd_config", "/etc/ufw/user.rules", "/etc/ufw/user6.rules",
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

	total := 9
	var sudoPW string

	if userExists(opt.User) {
		u.Progress(1, total, "Проверяю пользователя "+opt.User+"…")
	} else {
		u.Progress(1, total, "Создаю пользователя "+opt.User+"…")
	}
	pw, err := ensureUser(ctx, opt.User, key, u)
	if err != nil {
		u.Printf("Не получилось создать пользователя: %v\n", err)
		return 2
	}
	sudoPW = pw

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
			return 2
		}
	}

	if st.HasProtect {
		u.Progress(3, total, "Проверяю фильтр входящих подключений…")
	} else {
		u.Progress(3, total, "Включаю фильтр входящих подключений…")
	}
	if err := setupUFW(ctx, snap.Host.SSHPort, snap, allowPanel, keep); err != nil {
		u.Printf("Не получилось включить фильтр: %v\nSSH не закрываю.\n", err)
		return 2
	}

	u.Progress(4, total, "Проверяю защиту от подбора пароля…")
	banOK := true
	if err := setupFail2ban(ctx, hi.SSHClient); err != nil {
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
	if skipped := passwordOnlyLogins(snap2, opt.User); len(skipped) > 0 {
		u.Println("Пользователь " + strings.Join(skipped, ", ") + " входит только по паролю.")
		u.Println("После закрытия пароля он не зайдёт по SSH. Добавьте ему ключ или заходите как " + opt.User + ".")
	}
	if banOK && (check.UserHasKeys(snap2, opt.User) || key != "") {
		if err := lockSSH(ctx, opt.User, sshUsers); err != nil {
			u.Printf("Не закрыл пароль SSH: %v\nТекущий вход должен работать.\n", err)
		} else {
			locked = true
		}
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
	_ = state.Save(st)
	saveScan(snap3, fs)

	ip := snap.Host.PublicIP
	code := exitIfNotGreen(st.Level)
	if locked {
		audit.Event("protect", "ok", "ssh_locked")
		u.Println("Готово. Пароль SSH выключен.")
		if wasLocked {
			u.Printf("Вход: ssh %s@%s\n", opt.User, ip)
			if code != 0 {
				u.Print(ui.PaintFirstLine(report.StatusText(snap3, fs, ip, opt.User), st.Level, u.Color))
			}
			return code
		}
		u.Println("")
		u.Println("1. ЭТО ОКНО НЕ ЗАКРЫВАЙТЕ.")
		u.Println("2. Откройте ДРУГОЕ окно на своём компьютере (не в панели хостера).")
		u.Println("3. Введите:")
		u.Println("")
		u.Printf("   ssh %s@%s\n\n", opt.User, ip)
		u.Println("Если вошли — это окно можно закрыть.")
		u.Println("Если не вошли — см. ниже, не перезагружайте сервер.")
		u.Println("")
		printPasswordBox(u, sudoPW)
		u.Print("\n" + ui.HowToLogin(ip, opt.User, true))
		if code != 0 {
			u.Print(ui.PaintFirstLine(report.StatusText(snap3, fs, ip, opt.User), st.Level, u.Color))
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
	if pw == "" {
		return
	}
	u.Println(u.Paint(ui.Bold, "┌─ пароль для sudo, один раз ─────────────┐"))
	u.Printf("%s\n", u.Paint(ui.Bold, "│  "+pw))
	u.Println("│  запишите и храните как пароль от почты │")
	u.Println("└─────────────────────────────────────────┘")
	u.Println("через SSH этот пароль не спрашивают. Он нужен, когда на сервере пишете sudo.")
}

func aptInstall(ctx context.Context) error {
	env := append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
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
	want := check.MergePorts([]int{sshPort}, keep)
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
		if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "--force", "enable"); err != nil {
			return err
		}
	}
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

func setupFail2ban(ctx context.Context, clientIP string) error {
	ignore := "127.0.0.1/8 ::1"
	if clientIP != "" {
		ignore += " " + clientIP
	}
	body := fmt.Sprintf(`[sshd]
enabled = true
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = %s
`, ignore)
	changed, err := writeIfChanged(fail2banJail, body, 0644)
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
			ok, _ := setConfigLine("/etc/mysql/mysql.conf.d/mysqld.cnf", "bind-address", "bind-address = 127.0.0.1")
			return ok
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

func patchListenAddresses() bool {
	changed := false
	matches, _ := filepath.Glob("/etc/postgresql/*/main/postgresql.conf")
	for _, f := range matches {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := string(b)
		n := s
		for _, old := range []string{
			"listen_addresses = '*'",
			"listen_addresses='*'",
			`listen_addresses = "*"`,
			`listen_addresses="*"`,
		} {
			n = strings.ReplaceAll(n, old, "listen_addresses = 'localhost'")
		}
		if n == s {
			continue
		}
		if err := os.WriteFile(f, []byte(n), 0644); err == nil {
			changed = true
		}
	}
	return changed
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

func lockSSH(ctx context.Context, user string, allow []string) error {
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
	body := fmt.Sprintf(`PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
UseDNS no
GSSAPIAuthentication no
ClientAliveInterval 60
ClientAliveCountMax 3
MaxAuthTries 6
AllowUsers %s
`, strings.Join(allow, " "))
	if b, err := os.ReadFile(sshdDropin); err == nil && string(b) == body {
		if sshEffectiveLocked(ctx) && allowUsersApplied(effectiveAllowUsers(ctx), allow) {
			return nil
		}
	}
	rollback, err := snapshotSSHDropins()
	if err != nil {
		return err
	}
	if err := writeFile(sshdDropin, body, 0644); err != nil {
		return err
	}
	_ = os.Remove(sshdDropinLegacy)
	if err := neutralizeOtherSSHDropins(); err != nil {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		return err
	}
	if err := reloadSSH(ctx); err != nil {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		_ = reloadSSH(ctx)
		return err
	}
	out, _, err := oscmd.Run(ctx, 10*time.Second, "sshd", "-T")
	if err != nil {
		out, _, err = oscmd.Run(ctx, 10*time.Second, "/usr/sbin/sshd", "-T")
	}
	if err != nil {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		_ = reloadSSH(ctx)
		return fmt.Errorf("не смог проверить настройку входа, пароль не закрываю")
	}
	eff := facts.ParseSSHDT(out)
	if strings.EqualFold(eff.PasswordAuth, "yes") || strings.EqualFold(eff.PermitRootLogin, "yes") {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		_ = reloadSSH(ctx)
		return fmt.Errorf("настройка SSH не применилась, вход не меняю")
	}
	if !allowUsersApplied(eff.AllowUsers, allow) {
		_ = restoreSSHDropins(rollback)
		_ = os.Remove(sshdDropin)
		_ = reloadSSH(ctx)
		return fmt.Errorf("список пользователей входа не применился, вход не меняю")
	}
	return nil
}

func sshEffectiveLocked(ctx context.Context) bool {
	eff, err := effectiveSSH(ctx)
	if err != nil {
		return false
	}
	return !strings.EqualFold(eff.PasswordAuth, "yes") && !strings.EqualFold(eff.PermitRootLogin, "yes")
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

func Undo(ctx context.Context, hi host.Info, u *ui.IO, yes bool) int {
	if yes {
		u.NoPrompt = true
	}
	if !backup.HasLast() {
		u.Println("Нечего откатывать. Снимка последней настройки нет.")
		return 2
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
	_ = restored
	st := state.Load()
	st.SSHLocked = sshEffectiveLocked(ctx)
	snap := facts.Collect(ctx, hi)
	fs := check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	_ = state.Save(st)
	u.Println("Откат сделан. Проверьте вход.")
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
	if listening(snap, 80) || listening(snap, 443) || snap.Firewall.AllowsPort(80) {
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
	if hostDBExposed(snap) {
		return false
	}
	if firewallGaps(snap) {
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
	_ = state.Save(st)
	saveScan(snap, fs)
	if st.Level == "green" {
		audit.Event("protect", "ok", "unchanged")
	} else {
		audit.Event("protect", "warn", "unchanged_"+st.Level)
	}
	u.Println("Проверил. Менять нечего.")
	u.Print(ui.PaintFirstLine(report.StatusText(snap, fs, snap.Host.PublicIP, user), st.Level, u.Color))
	return exitIfNotGreen(st.Level)
}
