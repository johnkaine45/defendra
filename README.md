<p align="center">
  <img src="docs/logo.svg" width="88" height="88" alt="Defendra">
</p>

<h1 align="center">Defendra</h1>

<p align="center">
  Защита свежего Ubuntu VDS для человека, который не админ.<br>
  Одна команда, русский язык, без облака и телеметрии.
</p>

<p align="center">
  <img alt="Релиз" src="https://img.shields.io/github/v/release/johnkaine45/defendra?color=10b981">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.23-00ADD8?logo=go&logoColor=white">
  <img alt="Ubuntu" src="https://img.shields.io/badge/Ubuntu-22.04%20%2F%2024.04%20%2F%2026.04-E95420?logo=ubuntu&logoColor=white">
  <img alt="Лицензия" src="https://img.shields.io/badge/license-MIT-64748b">
  <img alt="CI" src="https://github.com/johnkaine45/defendra/actions/workflows/ci.yml/badge.svg">
</p>

<p align="center">
  <img src="docs/og.png" width="720" alt="Defendra — защита Ubuntu VDS одной командой">
</p>

```text
sudo apt install ./defendra.deb
sudo defendra protect
```

Через минуту вход по паролю SSH закрыт, root с улицы не пускают, фильтр портов включён, базы не торчат в интернет. Уже работающие TCP и UDP (сайт, Docker, VPN) остаются открытыми. Если Docker сам пробросил базу на `0.0.0.0`, фильтр её не закроет — статус станет «опасно», контейнер не трогаем.

## Что делает

| Проблема свежего VDS | Что делает Defendra |
|---|---|
| Подбор пароля SSH за ночь | Ключ, потом пароль выключается |
| Вход под `root` с улицы | Только пользователь `admin` |
| Открытый Redis / Postgres / MySQL | Прячет на localhost, контейнеры не трогает |
| Нет файрвола | Включает фильтр, оставляет 22 и уже работающие порты сайта |
| Забыли открыть сайт | `sudo defendra allow-site` — не гуглите, как выключить фильтр |

Повторный запуск безопасен. Ctrl+C посредине — снова `sudo defendra protect`.

Если на сервере уже работает вход через NetBird, в меню есть `sudo defendra netbird` — выключить обычный вход с улицы. Вернуть службу: `sudo defendra street`. `--yes` выключение не делает.

## Честно не делает

Большую атаку на канал (гигабиты мусора до сервера) программа на машине не остановит. Это защита хостера в панели VDS и Cloudflare. В статусе это написано прямо, не мелким шрифтом.

Не меняет SSH-порт, не ставит 2FA, не перезагружает сервер сама.

## Как поставить

Нужен Ubuntu 22.04, 24.04 или 26.04, amd64. Команды — **на сервере**, кроме входа по SSH.

**1.** Войдите с компьютера (пароль из письма хостера, буквы не печатаются):

```bash
ssh root@СЮДА_IP_ИЗ_ПИСЬМА
```

**2.** Поставьте пакет **на сервере**:

```bash
curl -fsSL https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb -o defendra_amd64.deb
curl -fsSL https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb.sha256 -o defendra_amd64.deb.sha256
sha256sum -c defendra_amd64.deb.sha256
sudo apt install ./defendra_amd64.deb
```

Нет `curl`:

```bash
wget -O defendra_amd64.deb https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb
wget -O defendra_amd64.deb.sha256 https://github.com/johnkaine45/defendra/releases/latest/download/defendra_amd64.deb.sha256
sha256sum -c defendra_amd64.deb.sha256
sudo apt install ./defendra_amd64.deb
```

Процессор ARM (`uname -m` пишет `aarch64`) — в имени файла `arm64`, не `amd64`.

**3.** Включите защиту:

```bash
sudo defendra protect
```

Ключ делают **на своём компьютере**, в другом окне. Вставляют строку из `.pub` (короткая, начинается с `ssh-ed25519`). Закрытый ключ вставлять нельзя.

**4.** Это окно не закрывайте. В другом окне у себя:

```bash
ssh admin@СЮДА_IP
```

Вошли — первое окно можно закрыть. Не вошли — консоль в панели хостера (VNC), пароль root **из письма**, затем `sudo defendra undo`.

Пароль, который покажет Defendra — только для `sudo` на сервере. Для SSH он не нужен.

**5.** Сайт на второй день — не выключайте фильтр:

```bash
sudo defendra allow-site
```

## Как обновить

На уже закрытом сервере:

```bash
ssh admin@СЮДА_IP
sudo defendra update
```

Программа сама скачает новую версию, проверит файл и поставит. Вход и сайт не сбросятся. Если новее нет — так и скажет. Потом можно `sudo defendra protect` — на закрытом сервере это «проверил, менять нечего».

## Как выглядит статус

<p align="center">
  <img src="docs/status.png" width="720" alt="sudo defendra status — порядок">
</p>

Три слова вместо светофора: **порядок** / **не полностью** / **опасно**. Одна причина, одна команда. Повторный `protect` на уже закрытом сервере пишет «проверил, менять нечего» и не гоняет девять шагов. Если при этом статус не «порядок» (например Docker выставил базу), команда выходит с кодом 1 — скрипт это увидит.

Панель управления: Enter оставляет порт, «нет» закрывает его с улицы. Защита от подбора пароля должна запуститься, иначе пароль SSH не выключаем.

## Команды

| Команда | Зачем |
|---|---|
| `defendra` | Меню: что делать дальше |
| `sudo defendra protect` | Настроить или дожать защиту |
| `sudo defendra status` | Всё ли в порядке |
| `sudo defendra allow-site` | Открыть сайту 80 и 443 |
| `sudo defendra update` | Новая версия программы |
| `sudo defendra undo` | Откатить последний protect |
| `defendra how-to-login` | Как заходить, два пароля, консоль хостера |
| `defendra help` | FAQ: не вхожу, забыли пароль, нет сайта |
| `sudo defendra password` | Показать пароль sudo, если забыли |

Для скриптов: `--yes`, `--dry-run`, `scan --format json`. `--dry-run` ничего не спрашивает и не читает stdin. В меню новичка этих флагов нет.

## Принципы

- Говорит по-русски, без жаргона вроде UFW и fail2ban
- Сначала гарантирует следующий вход, потом закрывает дыры
- Не останавливает Docker, не сбрасывает фильтр, не меняет порт SSH
- Пароль root из письма хостера не трогает — им открывают консоль, если что-то пошло не так
- Не ходит «домой», нет кабинета и телеметрии

## Документы

- [UX.md](UX.md) — экраны и фразы
- [SPEC.md](SPEC.md) — что именно настраивается
- [ARCHITECTURE.md](ARCHITECTURE.md) — как устроен код
- [SECURITY.md](SECURITY.md) — как сообщить об уязвимости

## Разработка

Нужен Go 1.23+.

```bash
make test
make linux          # bin/defendra-linux-amd64
make deb            # dist/defendra_VERSION_amd64.deb
```

Деплой на свой стенд:

```bash
export DEFENDRA_HOST=admin@203.0.113.10
export DEFENDRA_KEY=~/.ssh/id_ed25519
make deploy
```

## Лицензия

[MIT](LICENSE)
