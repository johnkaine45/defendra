package protect

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/check"
	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/oscmd"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
)

func parsePortSpec(s string) (port int, proto string, err error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, " ", "")
	if s == "" {
		return 0, "", fmt.Errorf("empty")
	}
	proto = "tcp"
	if i := strings.IndexByte(s, '/'); i >= 0 {
		switch s[i+1:] {
		case "tcp":
			proto = "tcp"
		case "udp":
			proto = "udp"
		default:
			return 0, "", fmt.Errorf("proto")
		}
		s = s[:i]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, "", fmt.Errorf("port")
	}
	return n, proto, nil
}

func refuseAllowPort(port int, streetOff bool) string {
	if check.IsDBPort(port) {
		if port == 2375 || port == 2376 {
			return fmt.Sprintf("Порт %d — это управление Docker с улицы. Открывать нельзя.", port)
		}
		return fmt.Sprintf("Порт %d — это база. С улицы её открывать нельзя: так часто воруют данные.", port)
	}
	if port == 22 || port == 22022 {
		if streetOff {
			return "Обычный вход с улицы выключен. Вернуть его:\n\n  sudo defendra street\n\nОтдельно этот порт не открываю."
		}
		return "Это порт входа. Он уже открыт. Отдельно его открывать не нужно."
	}
	return ""
}

func allowPortQuestion(port int, proto string) string {
	what := fmt.Sprintf("порт %d", port)
	if proto == "udp" {
		what = fmt.Sprintf("порт %d (необычный, не как у сайта)", port)
	}
	return fmt.Sprintf(`Открою %s с улицы.

Это слабое место. Любой в интернете сможет стучаться в этот порт.
Базы так открывать нельзя — их Defendra не откроет.
Для сайта есть отдельная команда: sudo defendra allow-site`, what)
}

func AllowPort(ctx context.Context, hi host.Info, u *ui.IO, yes, dry bool, extra string) int {
	if yes {
		u.Println("Свой порт --yes не открывает. Запустите в терминале:\n\n  sudo defendra allow-port")
		return 2
	}
	if dry {
		u.NoPrompt = true
	}
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	if !snap.Firewall.Active {
		u.Println("Сначала sudo defendra protect, потом открывайте порт.")
		return 2
	}
	spec := strings.TrimSpace(extra)
	if spec == "" && !dry {
		u.Println("Какой порт открыть с улицы?")
		u.Println("Напишите число, например 8080.")
		line, err := u.ReadLine()
		if err != nil && strings.TrimSpace(line) == "" {
			u.Println("Нужен номер порта от 1 до 65535. Например: 8080")
			return 2
		}
		spec = line
	}
	if dry && spec == "" {
		u.Println("Ничего не меняю (только показ). Спросил бы номер порта и открыл бы его в фильтре, если это не база.")
		return 0
	}
	port, proto, err := parsePortSpec(spec)
	if err != nil {
		u.Println("Нужен номер порта от 1 до 65535. Например: 8080")
		return 2
	}
	if reason := refuseAllowPort(port, st.StreetSSHOff); reason != "" {
		u.Println(reason)
		return 2
	}
	already := snap.Firewall.AllowsProto(port, proto)
	if already {
		rememberPort(st, port)
		u.Printf("Порт %d уже открыт с улицы.\n", port)
		return 0
	}
	if dry {
		u.Printf("Ничего не меняю (только показ). Открыл бы порт %d с улицы. Это слабое место.\n", port)
		return 0
	}
	ok, err := u.ConfirmDanger(allowPortQuestion(port, proto))
	if err != nil {
		return 2
	}
	if !ok {
		u.Println("Порт не открываю.")
		return 0
	}
	lk, err := lock()
	if err != nil {
		u.Println(err.Error())
		return 2
	}
	defer lk.Close()
	arg := strconv.Itoa(port) + "/" + proto
	if _, _, err := oscmd.Run(ctx, 20*time.Second, "ufw", "allow", arg); err != nil {
		u.Println("Не получилось открыть порт. Фильтр не выключаю.")
		return 2
	}
	rememberPort(st, port)
	u.Printf(`Готово. Порт %d с улицы открыт.

Это слабое место: в этот порт может стучаться кто угодно.
Фильтр остался включённым. Остальные порты не трогал.
`, port)
	return 0
}

func rememberPort(st state.State, port int) {
	st.KeepPorts = check.MergePorts(st.KeepPorts, []int{port})
	if port == 80 || port == 443 {
		st.SiteAllowed = true
	}
	_ = state.Save(st)
}
