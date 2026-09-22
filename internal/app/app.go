package app

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/johnkaine/defendra/internal/audit"
	"github.com/johnkaine/defendra/internal/check"
	"github.com/johnkaine/defendra/internal/facts"
	"github.com/johnkaine/defendra/internal/host"
	"github.com/johnkaine/defendra/internal/protect"
	"github.com/johnkaine/defendra/internal/report"
	"github.com/johnkaine/defendra/internal/state"
	"github.com/johnkaine/defendra/internal/ui"
	"github.com/johnkaine/defendra/internal/update"
)

func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	u := ui.New(stdin, stdout, stderr)
	cmd, flags := parse(args)

	switch cmd {
	case "", "menu":
		st := state.Load()
		if st.HasProtect {
			u.Print(ui.PaintFirstLine(ui.MenuAfter(st.Level), st.Level, u.Color))
		} else {
			u.Print(ui.PaintFirstLine(ui.MenuFresh(), "green", u.Color))
		}
		return 0
	case "help":
		u.Print(ui.Help())
		return 0
	case "version":
		u.Print(ui.VersionLine())
		return 0
	case "how-to-login":
		st := state.Load()
		u.Print(ui.FormatHowToLogin(ui.LoginHint{
			IP: st.PublicIP, User: st.User, SSHLocked: st.SSHLocked,
			StreetOff: st.StreetSSHOff, NetBirdIP: st.NetBirdIP,
		}))
		return 0
	}

	hi := host.Detect()

	needRoot := cmd == "protect" || cmd == "status" || cmd == "scan" || cmd == "allow-site" || cmd == "undo" || cmd == "watch" || cmd == "explain" || cmd == "password" || cmd == "update" || cmd == "netbird" || cmd == "street"
	if needRoot {
		if !hi.Root {
			u.Print(ui.NeedSudo(cmd))
			return 2
		}
		if !hi.UbuntuOK && cmd != "watch" && cmd != "password" {
			u.Print(ui.NotUbuntu(hi.Pretty))
			return 2
		}
		asks := cmd == "protect" || cmd == "undo" || cmd == "allow-site" || cmd == "update" || cmd == "netbird" || cmd == "street"
		if asks && !flags.yes && !flags.dry && !isTTY(stdin) {
			if cmd == "netbird" {
				u.Println("Без окна терминала не спрашиваю. Запустите в терминале:\n\n  sudo defendra netbird")
				return 2
			}
			u.Println("Без окна терминала Defendra сама не спрашивает. Напишите:\n\n  sudo defendra " + cmd + " --yes")
			return 2
		}
		if hi.Desktop && cmd == "protect" {
			if flags.yes {
				u.Println(`Похоже, это не VDS, а обычный компьютер с Ubuntu.
--yes здесь не сработает: можно закрыть себе вход.
Если это всё-таки сервер — запустите без --yes и подтвердите.`)
				return 2
			}
			ok, _ := u.Confirm(`Похоже, это не VDS, а обычный компьютер с Ubuntu.
Defendra для облачного сервера. Здесь запускать не нужно:
можно закрыть себе вход.

Если это всё-таки сервер — напишите да.`)
			if !ok {
				return 0
			}
		}
	}

	ctx := context.Background()

	switch cmd {
	case "status":
		code := cmdStatus(ctx, hi, u, false)
		audit.Event("status", exitWord(code), "")
		return code
	case "scan":
		code := cmdStatus(ctx, hi, u, flags.json)
		audit.Event("scan", exitWord(code), "")
		return code
	case "protect":
		return protect.Run(ctx, hi, protect.Options{User: flags.user, Yes: flags.yes, DryRun: flags.dry, UI: u})
	case "allow-site":
		return protect.AllowSite(ctx, hi, u, flags.yes, flags.dry)
	case "undo":
		code := protect.Undo(ctx, hi, u, flags.yes, flags.dry)
		audit.Event("undo", exitWord(code), "")
		return code
	case "watch":
		return protect.Watch(ctx, hi)
	case "motd":
		if b, err := os.ReadFile(state.MotdPath()); err == nil && len(b) > 0 {
			u.Print(string(b))
			return 0
		}
		st := state.Load()
		if st.Motd != "" {
			u.Println(st.Motd)
		}
		return 0
	case "explain":
		return cmdExplain(ctx, hi, u, flags.extra)
	case "password":
		code := protect.ShowPassword(u)
		audit.Event("password", exitWord(code), "")
		return code
	case "update":
		code := update.Run(ctx, update.Options{Yes: flags.yes, DryRun: flags.dry, UI: u})
		audit.Event("update", exitWord(code), "")
		return code
	case "netbird":
		code := protect.StreetOff(ctx, hi, u, flags.yes, flags.dry)
		audit.Event("netbird", exitWord(code), "")
		return code
	case "street":
		code := protect.StreetOn(ctx, hi, u, flags.yes, flags.dry)
		audit.Event("street", exitWord(code), "")
		return code
	default:
		u.Print(ui.UnknownCommand())
		return 2
	}
}

func exitWord(code int) string {
	if code == 0 {
		return "ok"
	}
	if code == 1 {
		return "warn"
	}
	return "fail"
}

func isTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

type flags struct {
	yes, dry, json bool
	user           string
	extra          string
}

func parse(args []string) (string, flags) {
	var f flags
	f.user = "admin"
	var cmd string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			return "help", f
		case a == "-v" || a == "--version":
			return "version", f
		case a == "--yes" || a == "-y":
			f.yes = true
		case a == "--dry-run":
			f.dry = true
		case a == "--format" && i+1 < len(args):
			i++
			f.json = strings.EqualFold(args[i], "json")
		case strings.HasPrefix(a, "--format="):
			f.json = strings.EqualFold(strings.TrimPrefix(a, "--format="), "json")
		case a == "--user" && i+1 < len(args):
			i++
			f.user = args[i]
		case strings.HasPrefix(a, "--user="):
			f.user = strings.TrimPrefix(a, "--user=")
		case strings.HasPrefix(a, "-"):
			continue
		default:
			if cmd == "" {
				cmd = a
			} else if f.extra == "" {
				f.extra = a
			}
		}
	}
	return cmd, f
}

func cmdStatus(ctx context.Context, hi host.Info, u *ui.IO, asJSON bool) int {
	st := state.Load()
	var snap facts.Snapshot
	if asJSON {
		snap = facts.CollectFull(ctx, hi)
	} else {
		snap = facts.Collect(ctx, hi)
	}
	fs := check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)
	doc := report.Build(snap, fs)
	_ = os.MkdirAll(state.ScansDir(), 0700)
	b, _ := json.MarshalIndent(doc, "", "  ")
	_ = os.WriteFile(filepath.Join(state.ScansDir(), time.Now().UTC().Format("20060102T150405Z")+".json"), b, 0600)
	st.Level = report.Level(fs)
	st.Motd = report.Motd(fs)
	st.PublicIP = snap.Host.PublicIP
	st.SSHPort = snap.Host.SSHPort
	if snap.NetBird.IP != "" {
		st.NetBirdIP = snap.NetBird.IP
	}
	_ = state.Save(st)
	if asJSON {
		u.Println(string(b))
		if st.Level == "green" {
			return 0
		}
		return 1
	}
	user := st.User
	if !st.HasProtect {
		user = "root"
	}
	u.Print(ui.PaintFirstLine(report.StatusText(snap, fs, snap.Host.PublicIP, user), st.Level, u.Color))
	if st.Level == "green" {
		return 0
	}
	return 1
}

func cmdExplain(ctx context.Context, hi host.Info, u *ui.IO, id string) int {
	if id == "" {
		u.Println("Напишите: defendra explain SSH-PASSWORD")
		return 2
	}
	st := state.Load()
	snap := facts.Collect(ctx, hi)
	fs := check.Run(snap, st.SiteAllowed, st.HasProtect, st.KeepPorts)
	id = strings.ToUpper(id)
	for _, f := range fs {
		if f.ID == id {
			u.Println(f.Title)
			if f.Plain != "" {
				u.Println(f.Plain)
			}
			if f.Status == check.Fail || f.Status == check.Warn {
				if f.Fix == "protect" {
					u.Println("\nДальше: sudo defendra protect")
				}
				if f.Fix == "allow-site" {
					u.Println("\nДальше: sudo defendra allow-site")
				}
			}
			return 0
		}
	}
	u.Println("Нет такой проверки: " + id)
	return 1
}
