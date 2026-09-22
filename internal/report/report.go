package report

import (
	"encoding/json"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/check"
	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/version"
)

type Document struct {
	SchemaVersion   int             `json:"schema_version"`
	DefendraVersion string          `json:"defendra_version"`
	Hostname        string          `json:"hostname"`
	OS              string          `json:"os"`
	ScannedAt       time.Time       `json:"scanned_at"`
	Counts          map[string]int  `json:"counts"`
	Findings        []check.Finding `json:"findings"`
	FactsHash       string          `json:"facts_hash"`
}

func Build(s facts.Snapshot, fs []check.Finding) Document {
	c := map[string]int{}
	for _, f := range fs {
		c[string(f.Status)]++
		if f.Status == check.Fail || f.Status == check.Warn {
			c[string(f.Severity)]++
		}
	}
	raw, _ := json.Marshal(s)
	h := fnv.New64a()
	_, _ = h.Write(raw)
	return Document{
		SchemaVersion:   1,
		DefendraVersion: version.Version,
		Hostname:        s.Host.Hostname,
		OS:              s.Host.PrettyOS,
		ScannedAt:       s.CollectedAt,
		Counts:          c,
		Findings:        fs,
		FactsHash:       strconv.FormatUint(h.Sum64(), 16),
	}
}

func Level(fs []check.Finding) string {
	red := map[string]bool{
		"NET-DB-EXPOSED": true, "USER-UID0": true, "NET-UNEXPECTED-PORT": true,
		"WATCH-UFW-OFF": true, "PERM-SHADOW": true, "SSH-EMPTY-PASS": true,
		"WATCH-SELF-PERMS": true, "FW-SSH-MISSING": true, "SSH-STREET": true,
	}
	yellow := false
	for _, f := range fs {
		if f.Status != check.Fail {
			continue
		}
		if red[f.ID] {
			return "red"
		}
		yellow = true
	}
	if yellow {
		return "yellow"
	}
	return "green"
}

func Primary(fs []check.Finding) *check.Finding {
	order := []string{
		"NET-DB-EXPOSED", "USER-UID0", "WATCH-UFW-OFF", "FW-SSH-MISSING", "SSH-STREET", "PERM-SHADOW", "WATCH-SELF-PERMS",
		"FW-WEB-BLOCKED", "SSH-NO-KEY", "SSH-PASSWORD", "SSH-ROOT-LOGIN",
		"FW-DISABLED", "AUTH-FAIL2BAN", "PKG-UNATTENDED", "NET-UNEXPECTED-PORT",
	}
	idx := map[string]int{}
	for i, id := range order {
		idx[id] = i
	}
	var best *check.Finding
	bestN := 99
	for i := range fs {
		f := &fs[i]
		if f.Status != check.Fail && f.Status != check.Warn {
			continue
		}
		n, ok := idx[f.ID]
		if !ok {
			n = 50
		}
		if n < bestN {
			bestN = n
			best = f
		}
	}
	return best
}

func StatusText(s facts.Snapshot, fs []check.Finding, ip, user string) string {
	lvl := Level(fs)
	var b strings.Builder
	switch lvl {
	case "green":
		b.WriteString("Defendra • порядок\n\n")
	case "red":
		b.WriteString("Defendra • опасно\n\n")
		if p := Primary(fs); p != nil {
			b.WriteString(p.Plain + "\n\n")
			if p.Fix == "allow-site" {
				b.WriteString("  sudo defendra allow-site\n")
			} else if p.Fix == "protect" {
				b.WriteString("  sudo defendra protect\n")
			}
			return b.String()
		}
	default:
		b.WriteString("Defendra • не полностью\n\n")
		if p := Primary(fs); p != nil {
			b.WriteString(p.Plain + "\n\n")
			if p.Fix == "allow-site" {
				b.WriteString("  sudo defendra allow-site\n")
			} else {
				b.WriteString("  sudo defendra protect\n")
			}
			b.WriteString("\nЗачем: defendra help\n")
			return b.String()
		}
	}

	entry := "по ключу"
	if yesSSHPassword(fs) {
		entry = "ещё по паролю"
	}
	if s.NetBird.Ready() && s.SSH.ListenerKnown && !s.SSH.ListenerActive {
		entry = "через NetBird"
	}
	if user == "" {
		user = "root"
	}
	b.WriteString("  Вход           " + entry + ", пользователь " + user + "\n")
	fw := "выключен"
	if s.Firewall.Active {
		shown := prettyAllows(s.Firewall.Allows)
		if shown == "" {
			fw = "включён"
		} else {
			fw = "включён, снаружи: " + shown
		}
	}
	b.WriteString("  Фильтр         " + fw + "\n")
	ban := "не работает"
	if s.Fail2ban.Active {
		ban = "сегодня отбито " + ruCount(s.Fail2ban.SSHBanned, "попытка", "попытки", "попыток")
	}
	b.WriteString("  Подбор пароля  " + ban + "\n")
	upd := "не включены"
	if s.Packages.UnattendedEnabled {
		upd = "ставятся сами"
	}
	b.WriteString("  Обновления     " + upd + "\n")
	b.WriteString("  Базы           ")
	if dbExposed(fs) {
		b.WriteString("видны из интернета\n")
	} else {
		b.WriteString("из интернета не видны\n")
	}
	if s.Packages.RebootRequired {
		b.WriteString("  Перезапуск     Ubuntu просит после обновлений ядра. В панели хостера — перезагрузить.\n")
	}
	if len(s.Panels) > 0 {
		p := s.Panels[0]
		b.WriteString("  Панель         порт " + strconv.Itoa(p.Port) + " открыт снаружи. Пароль панели должен быть сложным.\n")
	}
	b.WriteString("\n  DDoS канала    это не Defendra. В панели VDS включите защиту хостера.\n")
	if ip == "" {
		ip = s.Host.PublicIP
	}
	if s.NetBird.Ready() && s.SSH.ListenerKnown && !s.SSH.ListenerActive {
		nb := s.NetBird.IP
		if nb == "" {
			nb = "АДРЕС_NETBIRD"
		}
		b.WriteString("\nКак заходить:  ssh " + user + "@" + nb + "  (через NetBird)\n")
	} else if ip != "" {
		b.WriteString("\nКак заходить:  ssh " + user + "@" + ip + "\n")
	}
	b.WriteString("Справка:       defendra help\n")
	return b.String()
}

func Motd(fs []check.Finding) string {
	switch Level(fs) {
	case "green":
		return "Defendra: сервер в порядке"
	case "red":
		if p := Primary(fs); p != nil && strings.Contains(p.Plain, "порт") {
			return "Defendra: " + p.Plain + " — sudo defendra status"
		}
		return "Defendra: опасно — sudo defendra status"
	default:
		return "Defendra: защита неполная — sudo defendra status"
	}
}

func yesSSHPassword(fs []check.Finding) bool {
	for _, f := range fs {
		if f.ID == "SSH-PASSWORD" && f.Status == check.Fail {
			return true
		}
	}
	return false
}

func prettyAllows(allows []string) string {
	seen := map[string]bool{}
	var out []string
	for _, a := range allows {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if n, rest, ok := strings.Cut(a, "/"); ok {
			if rest == "tcp" {
				a = n
			}
		}
		if seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return strings.Join(out, ", ")
}

func dbExposed(fs []check.Finding) bool {
	for _, f := range fs {
		if f.ID == "NET-DB-EXPOSED" && f.Status == check.Fail {
			return true
		}
	}
	return false
}

func ruCount(n int, one, few, many string) string {
	if n < 0 {
		n = -n
	}
	word := many
	n100 := n % 100
	n10 := n % 10
	if n100 < 11 || n100 > 14 {
		switch n10 {
		case 1:
			word = one
		case 2, 3, 4:
			word = few
		}
	}
	return strconv.Itoa(n) + " " + word
}
