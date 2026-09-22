# Defendra — устройство проекта

Этот документ — карта реализации. Поведение продукта описано в `SPEC.md`. Здесь: пакеты, потоки данных, порядок шагов, что можно трогать на диске.

Язык: Go 1.23+, модуль `github.com/johnkaine/defendra` (путь уточним при создании репо). Сборка: один бинарник `defendra`, CGO выключен.

## 1. Карта каталогов

```
cmd/defendra/main.go                 # только flags → app.Run
internal/
  app/                             # маршрутизация команд, exit codes
  ui/                              # русский текст, меню, help, прогресс, ритуал
  host/                            # Ubuntu, root, desktop-detect, SSH_CONNECTION
  facts/                           # сбор фактов, без политики
    ssh.go
    users.go
    ports.go
    firewall.go
    packages.go
    fail2ban.go
    sysctl.go
    databases.go
    panel.go                       # FastPanel, ISPmanager, …
  check/                           # facts → []Finding
    catalog.go
    ssh.go
    firewall.go
    network.go
    auth.go
    packages.go
  protect/
    plan.go
    run.go
    steps/
      user.go
      packages.go
      firewall.go
      fail2ban.go
      unattended.go
      sysctl.go
      databases.go
      ssh.go
      motd.go
      watch.go
    gates.go
  backup/
  state/
  apt/
  service/
  watch/
  report/
testdata/facts/
dist/systemd/
Makefile
```

Зависимости: стандартная библиотека + `spf13/cobra` (или свой маленький parser — предпочтителен cobra, команд мало). Запрещены: SSH на другие хосты, HTTP-клиенты кроме будущего updater, который в v1 не существует.

## 2. Слои

```
CLI  →  protect/status/scan     политика и тексты
         ↓
       check                    факты → находки
         ↓
       facts                    чтение /proc, файлов, команд
         ↓
       host / apt / service     узкие обёртки над ОС
```

Правила:

- `facts` не знает, плохо это или хорошо. Он возвращает структуры.
- `check` не запускает команды, только смотрит на `facts.Snapshot`.
- `protect` единственный пишет в систему, и только через `backup` + узкие обёртки.
- `ui` единственный знает русский язык сообщений пользователю. Check каталог держит `plain`-строки как данные. На экране новичка нет имён пакетов и демонов.

## 3. Главные типы

```go
type Snapshot struct {
    CollectedAt time.Time
    Host        Host
    SSH         SSHFact
    Users       []User
    Ports       []Listen
    Firewall    Firewall
    Packages    Packages
    Fail2ban    Fail2ban
    Sysctl      map[string]string
}

type Finding struct {
    ID        string    `json:"id"`
    Title     string    `json:"title"`
    Severity  Severity  `json:"severity"`
    Status    Status    `json:"status"`
    Plain     string    `json:"plain"`
    Fix       string    `json:"fix"`       // "protect" | "allow-site" | "none"
    Automatic bool      `json:"automatic"`
    Gates     []string  `json:"gates"`
    Evidence  any       `json:"evidence"`
}

type Plan struct {
    User        string
    SSHKey      string // если вставили в этом запуске
    Steps       []Step
    WillLockSSH bool
    SummaryRU   []string
}

type Step interface {
    Name() string
    Needed(Snapshot, []Finding, Plan) bool
    Preview(Snapshot, Plan) []FileDiff // для dry-run
    Apply(ctx, Snapshot, Plan) error
    Verify(Snapshot) error
}
```

`status` = агрегат findings: есть critical/high fail → красный; есть fail/warn или пропущен SSH-lock → жёлтый; иначе зелёный.

## 4. Пайплайн protect

Каждый шаг: Needed? → Preview → (если apply) backup затронутых путей → Apply → Verify. Ошибка Verify на шаге SSH или UFW — откат **этого шага** сразу. Ошибка на «поставить fail2ban» — статус жёлтый, SSH не закрываем.

```
detect host
collect facts
run checks
need key? → ask or skip SSH-lock
build plan
print summary RU
confirm (unless --yes)
lock /var/lib/defendra/apply.lock
snapshot → backups/last
  1 user+key
  2 apt packages
  3 ufw rules then enable
  4 fail2ban
  5 unattended-upgrades
  6 sysctl
  7 databases listen/localhost
  8 ssh drop-in (only if gates; reload, не restart; не passwd -l root)
  9 motd + timer
  10 re-collect + checks
unlock
print how-to-login + ритуал второго окна, если SSH закрыли
```

Отдельная команда `allow-site` не входит в пайплайн protect: те же обёртки UFW, тот же lock, пишет `site_allowed` в state. Если UFW не active — exit 2 без «тихо включить».

Идемпотентность: `Needed()` смотрит на факты. Уже есть `admin` с ключом — шаг user не создаёт второго. UFW уже allow 22 — не дублировать.

## 5. Как трогаем конфиги

| Что | Как |
|---|---|
| SSH | только `/etc/ssh/sshd_config.d/99-defendra.conf`. Не переписывать основной файл хостера |
| sysctl | `/etc/sysctl.d/99-defendra.conf` |
| fail2ban | `/etc/fail2ban/jail.d/defendra.conf` |
| UFW | команды `ufw`, не ручные iptables |
| sudo | `/etc/sudoers.d/defendra-admin` через запись во временный файл + `visudo -c` |
| MOTD | `/etc/update-motd.d/99-defendra` |
| watch | unit-файлы в `/etc/systemd/system/` |

Запрещённые пути для записи: `/etc/ssh/sshd_config` (кроме чтения), `/etc/sudoers`, `/etc/shadow` напрямую, `/etc/passwd` через echo (только `useradd`/`usermod`).

Запрещённые команды: `passwd -l root`, `usermod -L root`, `passwd -d root`. Root в консоли хостера должен остаться рабочим.

Патч баз: маленькие известные шаблоны (PostgreSQL `listen_addresses`, Redis `bind`, MySQL `bind-address`). Если файл не похож на шаблон — не трогаем, полагаемся на UFW.

## 6. Команды ОС

Белый список. Никакого `bash -c` с конкатенацией пользовательского ввода в shell.

- `sshd -t -f <path>`
- `systemctl is-active|reload|enable --now`
- `ufw status verbose`, `ufw allow …`, `ufw --force enable`, `ufw default …`
- `ss -lntupH` или чтение `/proc/net/tcp` (предпочтительно `ss`, с таймаутом)
- `useradd`, `usermod -aG sudo`, `install -m 700/600` для authorized_keys
- `apt-get -y install` с `DEBIAN_FRONTEND=noninteractive`
- `fail2ban-client status sshd`
- `visudo -c -f`
- `sysctl --system`

Таймаут на внешнюю команду: 60s, на apt: 5m. Stdout/stderr в audit.log.

## 7. Тесты

- Unit: парсеры sshd, ufw status, ss, каталог check на фикстурах из `testdata/facts`.
- Gates: нет ключа → шаг SSH не входит в apply.
- Protect dry-run на фикстурах не вызывает `exec`.
- Integration (Makefile `test-vm`): cloud-init VM Ubuntu 24.04. Сценарии из SPEC §14, плюс: root не `L` в `passwd -S`; allow-site открывает только 80/443. Без VM в CI можно пропускать тег `integration`.

Не тестировать на машине разработчика с настоящим sshd.

## 8. Сборка и поставка

```
make build          # go build -trimpath -ldflags "-s -w -X version=..."
make deb            # nfpm или dpkg-deb: /usr/bin/defendra
make test
```

Версия: git tag. В v1 updater нет: человек ставит новый `.deb` сам. README содержит ровно две команды установки с URL `releases/latest/download/…`, без Go.

## 9. Порядок файлов, когда будем кодить

Не начинать с HTML и JSON-схемы отчётов. Порядок как SPEC §15:

1. `cmd/defendra` + `host` + `ui` (меню, help, Enter=да)
2. `facts` + печать сырого снимка (`defendra scan --debug-facts`, скрытый флаг)
3. `check` + `status` экраны из UX.md
4. `backup` + `protect/steps` без ssh-lock, прогресс, панели, валидация ключа
5. ssh-lock + ритуал + два пароля + motd + watch
6. `allow-site` + `undo` + UX-приёмка SPEC §14
