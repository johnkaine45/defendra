package ui

import "github.com/johnkaine/defendra/internal/version"

func MenuFresh() string {
	return `Defendra — защита Ubuntu-сервера

Сейчас нужно одно:
  sudo defendra protect

Справка, если застряли:
  defendra help
`
}

func MenuAfter(level string) string {
	title := "Defendra — сервер защищён не полностью"
	if level == "green" {
		title = "Defendra — сервер в порядке"
	}
	if level == "red" {
		title = "Defendra — сервер в опасности"
	}
	body := title + `

Что обычно нужно:
  sudo defendra status         всё ли в порядке
`
	if level != "green" {
		body += "  sudo defendra protect        дожать защиту\n"
	}
	body += `  sudo defendra allow-site     открыть сайт (порты 80 и 443)
  defendra how-to-login        как заходить
  defendra help                если не входит, нет сайта, забыли пароль
`
	return body
}

func Help() string {
	return `Defendra — если застряли

Не вхожу по SSH
  Root по SSH мог быть закрыт. Входите так:
    ssh admin@IP
  с того компьютера, где делали ключ.
  Спросят yes/no про отпечаток сервера — напишите yes, Enter.
  Permission denied (publickey) — ключ не тот или другой компьютер.
  Если не выходит: консоль в панели хостера (VNC / «консоль в браузере»),
  пароль root ИЗ ПИСЬМА хостера (буквы не видны — так и надо),
  затем: sudo defendra undo

Буквы пароля не печатаются
  Так и должно быть. Вводите вслепую и нажмите Enter.

Какой из двух паролей
  Войти по SSH                 пароль НЕ нужен, только ключ
  Команда sudo на сервере      пароль, который показала Defendra
  Консоль в браузере у хостера пароль root из письма хостера
                               его Defendra не меняла

Забыли пароль для sudo
  SSH при этом работает. Сервер не потерян.
  Откройте консоль в панели хостера, войдите как root
  (пароль из письма). Затем:
    defendra password
  Если пароль на диске не сохранился:
    passwd admin
  Два раза новый пароль, буквы снова не видны.

Сайт не открывается
  Не выключайте фильтр. На сервере:
    sudo defendra allow-site
  Если страницы ещё нет — сначала поставьте nginx или caddy.

Случайно закрыл окно после настройки
  Попробуйте: ssh admin@IP
  Не выходит — консоль хостера и sudo defendra undo

Ключ, Windows, PuTTY, Termius
  Нужна строка из файла .pub (короткая, начинается с ssh-ed25519).
  Закрытый ключ (BEGIN PRIVATE KEY) вставлять нельзя.
  Ключ нужно сделать НА СВОЁМ КОМПЬЮТЕРЕ. Ключ, созданный на сервере,
  не поможет войти с компьютера.
  Windows PowerShell: type $env:USERPROFILE\.ssh\id_ed25519.pub
  Ключ лежит в C:\Users\ВАШЕ_ИМЯ\.ssh\ — другой пользователь Windows = другой ключ.
  PuTTY: в PuTTYgen Conversion → Export OpenSSH key, публичная строка сверху.
  Termius: тот же ключ, хост admin@IP.

Поставить Defendra
  curl или wget, файл .deb, потом:
    sudo apt install ./defendra.deb
  Нет curl: sudo apt install curl
  Процессор ARM (uname -m пишет aarch64): нужен defendra_arm64.deb

Не выключайте фильтр входящих подключений.
Не ищите в интернете, как его выключить — для сайта есть:
  sudo defendra allow-site
`
}

func HowToLogin(ip, user string, sshLocked bool) string {
	if ip == "" {
		ip = "IP_СЕРВЕРА"
	}
	if user == "" {
		user = "admin"
	}
	body := "Как заходить на сервер\n\n"
	if sshLocked {
		body += "Вход только по ключу, пользователь " + user + ":\n\n"
		body += "  ssh " + user + "@" + ip + "\n\n"
		body += "Пароль SSH выключен. Если Permission denied — это не тот ключ или другой компьютер.\n\n"
	} else {
		body += "Пока можно входить как раньше (пароль ещё работает).\n"
		body += "Чтобы закрыть пароль, нужен ключ и снова: sudo defendra protect\n\n"
	}
	body += `Какой пароль для чего

  Войти по SSH с компьютера     пароль НЕ нужен, только ключ
  Команда sudo на сервере       пароль, который показала Defendra
                                (запишите в блокнот, не в Telegram)
  Консоль в браузере у хостера  пароль root ИЗ ПИСЬМА хостера
                                его Defendra не меняла

Забыли пароль для sudo
  Консоль хостера, вход как root (пароль из письма), затем:
    defendra password

Не входите с компьютера?

1. Откройте панель хостера (сайт, где покупали сервер).
2. Найдите «консоль», «VNC», «KVM», «browser console».
3. Войдите как root, пароль ИЗ ПИСЬМА хостера (буквы снова не видны).
4. Выполните:  sudo defendra undo
5. Снова:     ssh root@` + ip + `   с паролем из письма
`
	return body
}

func NeedSudo(cmd string) string {
	if cmd == "password" {
		return `Пароль для sudo показывают из консоли хостера, как root:

  defendra password

Если вы уже вошли как admin и пароль помните:

  sudo defendra password
`
	}
	return "Эту команду нужно запустить так:\n\n  sudo defendra " + cmd + "\n"
}

func NotUbuntu(pretty string) string {
	return "Defendra пока умеет только Ubuntu 22.04 и 24.04.\nСейчас на этой машине: " + pretty + ".\nСтавить защиту сюда нельзя — можно сломать вход.\n"
}

func UnknownCommand() string {
	return "Нет такой команды. Напишите:\n\n  defendra help\n"
}

func VersionLine() string {
	return "Defendra " + version.Version + "\n"
}

func Interrupted() string {
	return `Остановлено. Настройка могла остаться наполовину.
Это не страшно. Запустите ещё раз:

  sudo defendra protect

Повторять безопасно. Если вдруг не входите по SSH —
консоль в панели хостера и команда: sudo defendra undo
`
}
