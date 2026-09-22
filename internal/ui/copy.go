package ui

import "github.com/johnkaine/defendra/internal/version"

func menuVersion() string {
	v := version.Version
	if v == "" {
		v = "неизвестна"
	}
	return "Версия " + v
}

func MenuFresh() string {
	return `Defendra — защита Ubuntu-сервера
` + menuVersion() + `

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
	body := title + "\n" + menuVersion() + `

Что обычно нужно:
  sudo defendra status         всё ли в порядке
`
	if level != "green" {
		body += "  sudo defendra protect        дожать защиту\n"
	}
	body += `  sudo defendra allow-site     открыть сайт (порты 80 и 443)
  sudo defendra allow-port     открыть свой порт — это слабое место
  sudo defendra netbird        вход только через NetBird
  sudo defendra street         вернуть обычный вход с улицы
  sudo defendra update         новая версия программы
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
  Дальше с компьютера: ssh admin@IP с ключом.   Root по SSH не открываем.


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

Нужен другой порт
  Не выключайте фильтр. Это слабое место: порт станет виден всем в интернете.
  На сервере:
    sudo defendra allow-port
  или сразу: sudo defendra allow-port 8080
  Enter — не открывать. Нужно явно написать да.
  --yes этот шаг не делает. Базы не откроет.


База видна из интернета, хотя фильтр включён
  Часто это Docker: контейнер сам пробросил порт наружу.
  Defendra контейнер не трогает. Уберите проброс или слушайте
  только на сервере. Команда: sudo defendra status

Как обновить
  На сервере:
    sudo defendra update
  Программа сама скачает новую версию, проверит файл и что внутри
  именно Defendra, и поставит. Вход и сайт не сбросятся. Старую не ставит.

Вход через NetBird
  Выключить обычную службу входа с улицы:
    sudo defendra netbird
  --yes это не делает. Enter — оставить как есть.
  С публичного адреса зайти будет нельзя.
  На своём компьютере NetBird тоже должен быть включён.

  Вернуть обычную службу входа:
    sudo defendra street
  Вход через NetBird при этом останется.
  Если NetBird пропал — повторный protect сам вернёт обычный вход.

protect --yes не закрыл пароль SSH
  Есть другой пользователь, который входит только по паролю.
  Добавьте ему ключ или запустите без --yes и ответьте на вопрос.

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
  На сервере:
    curl -fsSL https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb -o defendra_amd64.deb
    curl -fsSL https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb.sha256 -o defendra_amd64.deb.sha256
    sha256sum -c defendra_amd64.deb.sha256
    sudo apt install ./defendra_amd64.deb
  Нет curl:
    wget -O defendra_amd64.deb https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb
    wget -O defendra_amd64.deb.sha256 https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb.sha256
    sha256sum -c defendra_amd64.deb.sha256
    sudo apt install ./defendra_amd64.deb
  Процессор ARM (uname -m пишет aarch64): в имени файла arm64, не amd64.

Не выключайте фильтр входящих подключений.
Не ищите в интернете, как его выключить — для сайта есть:
  sudo defendra allow-site
Для своего порта (осторожно, это слабое место):
  sudo defendra allow-port
`
}

type LoginHint struct {
	IP, User, NetBirdIP  string
	SSHLocked, StreetOff bool
}

func HowToLogin(ip, user string, sshLocked bool) string {
	return FormatHowToLogin(LoginHint{IP: ip, User: user, SSHLocked: sshLocked})
}

func FormatHowToLogin(h LoginHint) string {
	ip := h.IP
	if ip == "" {
		ip = "IP_СЕРВЕРА"
	}
	user := h.User
	if user == "" {
		user = "admin"
	}
	body := "Как заходить на сервер\n\n"
	if h.StreetOff {
		nb := h.NetBirdIP
		if nb == "" {
			nb = "АДРЕС_NETBIRD"
		}
		body += "Обычный вход с улицы выключен.\n"
		body += "Заходите через NetBird. На своём компьютере он тоже должен быть включён.\n\n"
		body += "  ssh " + user + "@" + nb + "\n\n"
		body += "или:\n\n"
		body += "  netbird ssh " + user + "@" + nb + "\n\n"
		body += "С публичного адреса сервера зайти нельзя.\n"
		body += "Вернуть обычный вход:  sudo defendra street\n\n"
	} else if h.SSHLocked {
		body += "Вход только по ключу, пользователь " + user + ":\n\n"
		body += "  ssh " + user + "@" + ip + "\n\n"
		body += "Пароль SSH выключен.\n"
		body += "Permission denied — не тот ключ или другой компьютер.\n\n"
	} else {
		body += "Пока можно входить как раньше (пароль ещё работает).\n\n"
		body += "Чтобы закрыть пароль, нужен ключ и снова:\n\n"
		body += "  sudo defendra protect\n\n"
	}
	body += PasswordRoles()
	body += `
Забыли пароль для sudo

  Консоль хостера, вход как root (пароль из письма), затем:

    defendra password

Не входите с компьютера?

  1. Панель хостера — «консоль», VNC или KVM.
  2. Войдите как root, пароль из письма (буквы не видны).
  3. Команда:  sudo defendra undo
  4. С компьютера, где ключ, после отката:

    ssh ` + user + `@` + ip + `

  Root по SSH после защиты закрыт. Вы уже в консоли хостера —
  сервер не потерян.
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
	return "Defendra пока умеет только Ubuntu 22.04, 24.04 и 26.04.\nСейчас на этой машине: " + pretty + ".\nСтавить защиту сюда нельзя — можно сломать вход.\n"
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
