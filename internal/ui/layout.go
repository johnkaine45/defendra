package ui

import (
	"strings"
	"unicode/utf8"
)

func visLen(s string) int {
	return utf8.RuneCountInString(s)
}

func padRight(s string, n int) string {
	if visLen(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visLen(s))
}

func PasswordBox(pw string) string {
	if pw == "" {
		return ""
	}
	title := "пароль для sudo, один раз"
	rows := []string{
		"  " + pw,
		"  запишите как пароль от почты",
	}
	w := visLen(title) + 2
	for _, row := range rows {
		if visLen(row)+2 > w {
			w = visLen(row) + 2
		}
	}
	if w < 36 {
		w = 36
	}
	dash := w - visLen(title) - 2
	if dash < 1 {
		dash = 1
	}
	var b strings.Builder
	b.WriteString("┌─" + title + " " + strings.Repeat("─", dash) + "┐\n")
	for _, row := range rows {
		b.WriteString("│" + padRight(row, w) + "│\n")
	}
	b.WriteString("└" + strings.Repeat("─", w) + "┘\n")
	b.WriteString("Через SSH его не спрашивают. Нужен, когда на сервере пишете sudo.\n")
	return b.String()
}

func FirstLockRitual(ip, user string, port int) string {
	if ip == "" {
		ip = "IP_СЕРВЕРА"
	}
	if user == "" {
		user = "admin"
	}
	return "Готово. Пароль SSH выключен.\n\n" +
		"1. ЭТО ОКНО НЕ ЗАКРЫВАЙТЕ.\n" +
		"2. На своём компьютере откройте другое окно\n" +
		"   (не в панели хостера).\n" +
		"3. Введите:\n\n" +
		"    " + SSHCommand(user, ip, port) + "\n\n" +
		"Если вошли — это окно можно закрыть.\n" +
		"Если не вошли — не перезагружайте сервер.\n"
}

func PasswordRoles() string {
	return "Какой пароль для чего\n\n" +
		"  Войти по SSH     только ключ, пароль не нужен\n" +
		"  Команда sudo     пароль в рамке выше\n" +
		"  Консоль хостера  пароль root из письма\n"
}

func FirstLockNext() string {
	return "Не вошли или забыли пароль sudo:\n\n  defendra how-to-login\n"
}
