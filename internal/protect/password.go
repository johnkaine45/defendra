package protect

import (
	"os"
	"strings"

	"github.com/johnkaine/defendra/internal/ui"
)

func ShowPassword(u *ui.IO) int {
	b, err := os.ReadFile(firstLogin)
	pw := ""
	if err == nil {
		pw = strings.TrimSpace(string(b))
	}
	if pw == "" {
		u.Println(`Пароль на диске не сохранился.

Откройте консоль в панели хостера и войдите как root
(пароль из письма хостера, буквы не видны).

Задайте новый пароль пользователю admin:

  passwd admin

Два раза один и тот же пароль, Enter. Буквы снова не видны.`)
		return 1
	}
	printPasswordBox(u, pw)
	u.Println("Это пароль для команды sudo на сервере. Через SSH его не спрашивают.")
	return 0
}
