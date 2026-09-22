package check

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/johnkaine/defendra/internal/facts"
)

var dbPorts = map[int]string{
	5432:  "PostgreSQL",
	3306:  "MySQL",
	6379:  "Redis",
	27017: "MongoDB",
	9200:  "Elasticsearch",
	2375:  "Docker API",
}

var suidAllow = map[string]bool{
	"passwd": true, "sudo": true, "su": true, "newgrp": true, "mount": true, "umount": true,
	"chsh": true, "chfn": true, "gpasswd": true, "fusermount": true, "fusermount3": true,
	"pkexec": true, "ping": true, "ping6": true, "pppd": true, "ntfs-3g": true,
	"dbus-daemon-launch-helper": true, "unix_chkpwd": true, "crontab": true, "ssh-keysign": true,
	"polkit-agent-helper-1": true, "expiry": true,
}

func Run(s facts.Snapshot, siteAllowed bool, afterProtect bool, keepPorts []int) []Finding {
	var out []Finding
	out = append(out, sshChecks(s)...)
	out = append(out, fwChecks(s, siteAllowed)...)
	out = append(out, netChecks(s, afterProtect, siteAllowed, keepPorts)...)
	out = append(out, authChecks(s)...)
	out = append(out, pkgChecks(s)...)
	out = append(out, sysChecks(s)...)
	out = append(out, userChecks(s)...)
	out = append(out, permChecks(s)...)
	out = append(out, suidChecks(s)...)
	if afterProtect && !s.Firewall.Active {
		out = append(out, f("WATCH-UFW-OFF", "Фильтр входящих подключений выключен",
			SevHigh, Fail, "Защиту сняли. С улицы снова видны лишние порты.", "protect", true, nil, nil))
	} else {
		out = append(out, f("WATCH-UFW-OFF", "Фильтр на месте", SevInfo, Pass, "", "protect", true, nil, nil))
	}
	return out
}

func sshChecks(s facts.Snapshot) []Finding {
	root := strings.ToLower(strings.TrimSpace(s.SSH.PermitRootLogin))
	st := Pass
	plain := "Вход под root по SSH закрыт."
	switch root {
	case "yes":
		st = Fail
		plain = "Сейчас можно войти как root по SSH. Так чаще всего взламывают новый сервер."
	case "prohibit-password", "without-password":
		st = Fail
		plain = "Root ещё может войти по SSH с ключом. Для обычного VDS лучше входить как admin."
	case "no":
	case "":
		st = Fail
		plain = "Не удалось прочитать, открыт ли вход под root."
	}
	a := []Finding{
		f("SSH-ROOT-LOGIN", "Вход под root по SSH", SevHigh, st, plain, "protect", true, []string{"admin_has_ssh_key"}, s.SSH.PermitRootLogin),
	}
	pst := Pass
	pplain := "Вход по паролю SSH выключен."
	if s.SSH.PasswordAuth == "" {
		pst, pplain = Fail, "Не удалось прочитать, включён ли вход по паролю SSH."
	} else if yes(s.SSH.PasswordAuth) {
		pst = Fail
		pplain = "Сейчас к серверу можно подобрать пароль. Нужен ваш SSH-ключ, потом Defendra выключит пароль."
	}
	a = append(a, f("SSH-PASSWORD", "Вход по паролю SSH", SevHigh, pst, pplain, "protect", true, []string{"admin_has_ssh_key"}, s.SSH.PasswordAuth))

	hasKey := false
	for _, u := range s.Users {
		if u.Sudo && u.HasKeys {
			hasKey = true
			break
		}
	}
	kst, kplain := Pass, "Есть ключ у пользователя с правами администратора."
	if !hasKey {
		kst, kplain = Fail, "Нет SSH-ключа. Без него нельзя безопасно выключить пароль."
	}
	a = append(a, f("SSH-NO-KEY", "SSH-ключ администратора", SevHigh, kst, kplain, "none", false, nil, nil))

	est := Pass
	eplain := "Пустые пароли запрещены."
	if yes(s.SSH.EmptyPasswords) {
		est, eplain = Fail, "Разрешены пустые пароли SSH. Так зайти может кто угодно."
	}
	a = append(a, f("SSH-EMPTY-PASS", "Пустые пароли SSH", SevCritical, est, eplain, "protect", true, nil, s.SSH.EmptyPasswords))
	return a
}

func fwChecks(s facts.Snapshot, siteAllowed bool) []Finding {
	st, plain := Pass, "Фильтр входящих подключений включён."
	if !s.Firewall.Active {
		st, plain = Fail, "Фильтр входящих подключений выключен. С улицы видны все открытые программы."
	}
	out := []Finding{f("FW-DISABLED", "Фильтр входящих подключений", SevHigh, st, plain, "protect", true, nil, s.Firewall.Active)}

	sst, splain := Pass, "Порт входа разрешён в фильтре."
	if s.Firewall.Active && !s.Firewall.AllowsPort(s.Host.SSHPort) {
		sst, splain = Fail, "Фильтр включён, но порт входа не разрешён. Так можно потерять доступ."
	}
	if !s.Firewall.Active {
		sst = Skipped
		splain = "Фильтр ещё выключен."
	}
	out = append(out, f("FW-SSH-MISSING", "Порт входа в фильтре", SevCritical, sst, splain, "protect", true, nil, s.Host.SSHPort))

	webListen := listening(s, 80) || listening(s, 443)
	webAllowed := s.Firewall.AllowsPort(80) || s.Firewall.AllowsPort(443) || siteAllowed
	wst, wplain := Pass, "Сайт либо не запущен, либо фильтр его пускает."
	if webListen && s.Firewall.Active && !webAllowed {
		wst, wplain = Fail, "Сайт запущен, но фильтр его не пускает. Выполните sudo defendra allow-site"
	}
	out = append(out, f("FW-WEB-BLOCKED", "Сайт и фильтр", SevMedium, wst, wplain, "allow-site", false, nil, nil))
	return out
}

func netChecks(s facts.Snapshot, afterProtect, siteAllowed bool, keepPorts []int) []Finding {
	var exposed []string
	dockerDB := false
	for _, p := range s.Ports {
		if !p.Public() {
			continue
		}
		if name, ok := dbPorts[p.Port]; ok {
			if dockerish(p.Process) {
				dockerDB = true
				exposed = append(exposed, name+" (Docker) на порту "+strconv.Itoa(p.Port))
			} else {
				exposed = append(exposed, name+" на порту "+strconv.Itoa(p.Port))
			}
		}
	}
	st, plain := Pass, "Базы из интернета не видны."
	auto := true
	fix := "protect"
	if len(exposed) > 0 {
		st = Fail
		if dockerDB {
			auto = false
			fix = "none"
			plain = "Docker выставил базу в интернет: " + strings.Join(exposed, ", ") + ". Контейнер не трогаю, чтобы не сломать проект. Уберите проброс порта или слушайте только 127.0.0.1."
		} else {
			plain = "С улицы видна база: " + strings.Join(exposed, ", ") + ". Так часто воруют данные."
		}
	}
	out := []Finding{f("NET-DB-EXPOSED", "Базы в интернет", SevHigh, st, plain, fix, auto, nil, exposed)}

	if afterProtect {
		expected := map[int]bool{s.Host.SSHPort: true}
		if siteAllowed || s.Firewall.AllowsPort(80) {
			expected[80], expected[443] = true, true
		}
		for _, pan := range s.Panels {
			expected[pan.Port] = true
		}
		for _, p := range keepPorts {
			expected[p] = true
		}
		var extra []string
		for _, p := range s.Ports {
			if !p.Public() || p.Proto != "tcp" {
				continue
			}
			if expected[p.Port] || dbPorts[p.Port] != "" {
				continue
			}
			if p.Port == 22 || p.Port == 80 || p.Port == 443 {
				continue
			}
			extra = append(extra, strconv.Itoa(p.Port))
		}
		nst, nplain := Pass, "Новых публичных портов нет."
		if len(extra) > 0 {
			nst, nplain = Fail, "Появился открытый порт "+strings.Join(extra, ", ")+". Если это ваш проект — sudo defendra protect (порт оставлю). Если не запускали — разберитесь."
		}
		out = append(out, f("NET-UNEXPECTED-PORT", "Новый порт с улицы", SevHigh, nst, nplain, "protect", false, nil, extra))
	} else {
		out = append(out, f("NET-UNEXPECTED-PORT", "Новый порт с улицы", SevInfo, Skipped, "Ещё нет эталона после настройки.", "none", false, nil, nil))
	}
	return out
}

func dockerish(proc string) bool {
	p := strings.ToLower(proc)
	return strings.Contains(p, "docker") || strings.Contains(p, "containerd")
}

func IsDBPort(port int) bool {
	_, ok := dbPorts[port]
	return ok
}

func ProjectPorts(s facts.Snapshot) []int {
	seen := map[int]bool{}
	var out []int
	for _, p := range s.Ports {
		if !p.Public() || p.Proto != "tcp" {
			continue
		}
		if p.Port == s.Host.SSHPort || p.Port == 22 {
			continue
		}
		if IsDBPort(p.Port) {
			continue
		}
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		out = append(out, p.Port)
	}
	return out
}

func MergePorts(lists ...[]int) []int {
	seen := map[int]bool{}
	var out []int
	for _, list := range lists {
		for _, p := range list {
			if p <= 0 || p > 65535 || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Ints(out)
	return out
}

func authChecks(s facts.Snapshot) []Finding {
	st, plain := Pass, "Защита от подбора пароля работает."
	if !s.Fail2ban.Active {
		st, plain = Fail, "Нет защиты от подбора пароля. Её поставит Defendra."
	}
	return []Finding{f("AUTH-FAIL2BAN", "Защита от подбора пароля", SevMedium, st, plain, "protect", true, nil, s.Fail2ban.Active)}
}

func pkgChecks(s facts.Snapshot) []Finding {
	st, plain := Pass, "Обновления безопасности ставятся сами."
	if !s.Packages.Unattended || !s.Packages.UnattendedEnabled {
		st, plain = Fail, "Автообновления безопасности выключены. Их включит Defendra."
	}
	return []Finding{f("PKG-UNATTENDED", "Автообновления", SevMedium, st, plain, "protect", true, nil, nil)}
}

func sysChecks(s facts.Snapshot) []Finding {
	v := s.Sysctl["net.ipv4.tcp_syncookies"]
	st, plain := Pass, "Базовая защита от мелкого флуда включена."
	if v != "1" {
		st, plain = Fail, "Выключена простая защита от мелкого сетевого флуда."
	}
	return []Finding{f("SYS-SYNCOOKIES", "Защита от мелкого флуда", SevLow, st, plain, "protect", true, nil, v)}
}

func userChecks(s facts.Snapshot) []Finding {
	extras := 0
	for _, u := range s.Users {
		if u.UID == 0 && u.Name != "root" {
			extras++
		}
	}
	st, plain := Pass, "Второй суперпользователь не найден."
	if extras > 0 {
		st, plain = Fail, "Есть ещё один пользователь с правами root. Defendra это сама не исправит — разберитесь, кто это."
	}
	out := []Finding{f("USER-UID0", "Второй root", SevCritical, st, plain, "none", false, nil, extras)}
	nst, nplain := Pass, "Широкий NOPASSWD в sudo не найден."
	if s.Sudo.NOPASSWDAll {
		nst, nplain = Warn, "У кого-то sudo без пароля на все команды. В этой версии это не меняем, но это слабо."
	}
	out = append(out, f("USER-NOPASSWD-ALL", "sudo без пароля", SevMedium, nst, nplain, "none", false, nil, nil))
	return out
}

func permChecks(s facts.Snapshot) []Finding {
	bad := []string{}
	self := []string{}
	for _, p := range s.Perms {
		m := os.FileMode(p.Perm)
		switch p.Path {
		case "/etc/shadow", "/etc/gshadow":
			if m&0007 != 0 {
				bad = append(bad, p.Path)
			}
		case "/etc/sudoers", "/etc/ssh/sshd_config":
			if m&0002 != 0 {
				bad = append(bad, p.Path)
			}
		case "/var/lib/defendra/first-login.txt":
			if m&0007 != 0 {
				self = append(self, p.Path)
			}
		default:
			base := filepath.Base(p.Path)
			if (base == "authorized_keys" || base == ".ssh") && m&0077 != 0 {
				bad = append(bad, p.Path)
				break
			}
			if strings.Contains(p.Path, "defendra") && m&0002 != 0 {
				self = append(self, p.Path)
			}
		}
	}
	st, plain := Pass, "Права на важные файлы в порядке."
	if len(bad) > 0 {
		st, plain = Fail, "Плохие права на "+strings.Join(bad, ", ")
	}
	out := []Finding{f("PERM-SHADOW", "Права важных файлов", SevHigh, st, plain, "protect", true, nil, bad)}
	sst, splain := Pass, "Файлы Defendra закрыты от посторонних."
	if len(self) > 0 {
		sst, splain = Fail, "Файл защиты доступен всем на запись. Запустите sudo defendra protect"
	}
	out = append(out, f("WATCH-SELF-PERMS", "Файлы Defendra", SevHigh, sst, splain, "protect", true, nil, self))
	return out
}

func suidChecks(s facts.Snapshot) []Finding {
	var unusual []string
	for _, p := range s.SUID {
		base := filepath.Base(p)
		if !suidAllow[base] {
			unusual = append(unusual, p)
		}
	}
	st, plain := Pass, "Необычных SUID-файлов нет."
	if len(unusual) > 0 {
		st, plain = Warn, "Найдены необычные SUID-файлы. Сами не удаляем."
	}
	return []Finding{f("SUID-UNUSUAL", "Необычные SUID", SevLow, st, plain, "none", false, nil, unusual)}
}

func yes(v string) bool {
	return strings.EqualFold(v, "yes")
}

func listening(s facts.Snapshot, port int) bool {
	for _, p := range s.Ports {
		if p.Port == port && p.Public() {
			return true
		}
	}
	return false
}

func HasSudoKey(s facts.Snapshot) bool {
	for _, u := range s.Users {
		if u.Sudo && u.HasKeys {
			return true
		}
	}
	return false
}

func UserHasKeys(s facts.Snapshot, name string) bool {
	for _, u := range s.Users {
		if u.Name == name && u.HasKeys {
			return true
		}
	}
	return false
}
