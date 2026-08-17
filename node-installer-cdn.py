#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
node-installer-cdn.py — установщик прокси-инфраструктуры за российским CDN (v1.0)

ЧТО ЭТО
-------
Самодостаточный установщик: разворачивает панель + ноду + CDN-обвязку и
связывает их между собой. Никуда не «звонит», кроме официальных репозиториев
(docker, xray, 3x-ui, remnawave, letsencrypt) и ваших серверов по SSH.
Конфиги (nginx, Caddy, docker-compose, systemd, sysctl, SQL) вшиты как есть.

ЧТО ДЕЛАЕТ
----------
Разворачивает XHTTP(packet-up)-прокси за российским CDN. Режимы:
  1  Панель + нода на этом сервере
  2  Панель здесь + нода на другом сервере (по SSH)
  3  Нода + CDN к уже существующей панели
  4  Только панель      5  Только нода      6  Только CDN-origin
Панель: Remnawave 3.x или 3x-ui. CDN: VK Cloud / Yandex Cloud / Beeline(CDNvideo)
/ Timeweb. Опционально — каскад (relay в РФ -> exit за рубежом).

ЗАПУСК
------
    sudo python3 node-installer-cdn.py                 # интерактивно
    sudo python3 node-installer-cdn.py --mode 1 --panel 1 --cdn 1 --domain example.com

ТРЕБОВАНИЯ: Ubuntu/Debian, root. Для режима 2/3 и каскада — sshpass (ставится сам).

ВНИМАНИЕ: работает под root и меняет сеть/сервисы. Обкатывайте на одноразовом VPS
со снапшотом. Ответственность за использование — на запускающем.
"""

import os
import sys
import re
import json
import time
import uuid as _uuid
import base64
import random
import string
import shlex
import getpass
import argparse
import subprocess

# ─────────────────────────────────────────────────────────────────────────────
#  Константы
# ─────────────────────────────────────────────────────────────────────────────

INSTALLER_VERSION = "1.0"             # версия установщика, печатается в баннере

XRAY_MIN_VERSION = "26.7.28"          # xray-core, тянется на ноду (актуальный релиз)
REMNAWAVE_IMAGE  = "remnawave/backend:3"       # мажорный тег 3.x (офиц. compose)
REMNANODE_IMAGE  = "ghcr.io/remnawave/node:latest"
XUI_VERSION      = "v3.6.0"
POSTGRES_IMAGE   = "postgres:18.4"             # как в офиц. compose Remnawave 3.x
VALKEY_IMAGE     = "valkey/valkey:9-alpine"    # 3.x: redis через unix-сокет

# Валидация пользовательского ввода: значения попадают в шелл-строки и конфиги
RE_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
RE_XPATH  = re.compile(r"^/[A-Za-z0-9._~/-]{1,120}$")

CDN_CRT = "/etc/nginx/ssl/cdn.crt"
CDN_KEY = "/etc/nginx/ssl/cdn.key"

# Reality dest/sni кандидаты
REALITY_DEST = "www.microsoft.com:443"
REALITY_SNI  = "www.microsoft.com"
REALITY_DEST_ALT = "www.google.com:443"

# packet-up / padding параметры xhttp
PU_PADDING       = "100-1000"
PU_SC_MAXBYTES   = "500000-1000000"
PU_SC_MININT     = "50-150"
PU_XMUX_CONC     = "60-180"          # xmux maxConcurrency
PU_XMUX_REUSE    = "600-900"

# Русские geo-правила роутинга (для standalone xray на exit/ноде)
RU_GEOIP   = "ext:geoip_RU.dat:ru"
RU_GEOSITE = "ext:geosite_RU.dat:ru-available-only-inside"
RU_REGEX   = [r"regexp:.*\.ru$", r"regexp:.*\.su$", r"regexp:.*\.xn--p1ai$"]

RU_GEO_URL = ("https://github.com/runetfreedom/russia-v2ray-rules-dat"
              "/releases/latest/download")

# sysctl BBR-тюнинг
SYSCTL_TUNING = """net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.ip_local_port_range = 1024 65535
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_fin_timeout = 15
fs.file-max = 1048576
vm.swappiness = 10
"""

LIMITS_NOFILE = """* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
"""

# Минимальный nginx.conf (пишется, если nginx-common не доложил свой)
NGINX_MINIMAL_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 16384; }
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    server_names_hash_bucket_size 128;
    types_hash_max_size 2048;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
"""

NGINX_MINIMAL_MIME = """types {
    text/html html htm shtml;
    text/css css;
    application/javascript js;
    application/json json;
    image/png png;
    image/jpeg jpg jpeg;
    image/svg+xml svg;
    application/octet-stream bin exe;
}
"""

# Страница-заглушка ("A simple website. Coming Soon.")
DECOY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{domain} | Website</title>
  <style>
    body {{ margin: 0; height: 100vh; display: flex; justify-content: center; align-items: center; background-color: #2c2825; color: #e3d9c6; font-family: 'Georgia', serif; }}
    .container {{ text-align: center; padding: 60px 80px; background: #1f1b18; border-radius: 6px; box-shadow: 0 15px 40px rgba(0,0,0,0.6); border-left: 4px solid #8b5a2b; }}
    h1 {{ font-weight: normal; letter-spacing: 2px; margin-bottom: 15px; font-size: 2.2em; }}
    p {{ color: #a89f91; font-size: 16px; font-style: italic; letter-spacing: 1px; margin: 0; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>{domain}</h1>
    <p>A simple website. Coming Soon.</p>
  </div>
</body>
</html>
"""

# docker-compose панели Remnawave 3.x (по офиц. docker-compose-prod.yml).
# Отличия от 2.8: valkey через unix-сокет (общий том valkey-socket, --port 0),
# postgres 18, отдельный порт метрик 3001, healthcheck по /health.
# {pg_pass} подставляется на исполнении.
REMNAWAVE_COMPOSE = """x-common: &common
  restart: always
  networks:
    - remnawave-network
  ulimits:
    nofile:
      soft: 1048576
      hard: 1048576

services:
  remnawave:
    image: {backend}
    container_name: remnawave
    hostname: remnawave
    <<: *common
    env_file:
      - .env
    volumes:
      - valkey-socket:/var/run/valkey
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:3001:3001"
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:3001/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
    depends_on:
      remnawave-db:
        condition: service_healthy
      remnawave-redis:
        condition: service_healthy

  remnawave-db:
    image: {postgres}
    container_name: remnawave-db
    hostname: remnawave-db
    <<: *common
    shm_size: 512mb
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: {{pg_pass}}
      POSTGRES_DB: postgres
      TZ: UTC
    volumes:
      - remnawave-db-data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d postgres"]
      interval: 3s
      timeout: 10s
      retries: 3

  remnawave-redis:
    image: {valkey}
    container_name: remnawave-redis
    hostname: remnawave-redis
    <<: *common
    volumes:
      - valkey-socket:/var/run/valkey
    command: >
      valkey-server
      --save ""
      --appendonly no
      --maxmemory-policy noeviction
      --loglevel warning
      --unixsocket /var/run/valkey/valkey.sock
      --unixsocketperm 777
      --port 0
    healthcheck:
      test: ["CMD", "valkey-cli", "-s", "/var/run/valkey/valkey.sock", "ping"]
      interval: 3s
      timeout: 3s
      retries: 3

volumes:
  remnawave-db-data:
  valkey-socket:

networks:
  remnawave-network:
    name: remnawave-network
    driver: bridge
""".format(backend=REMNAWAVE_IMAGE, postgres=POSTGRES_IMAGE, valkey=VALKEY_IMAGE)

# docker-compose ноды remnanode (host network)
REMNANODE_COMPOSE = """services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: %s
    network_mode: host
    restart: always
    cap_add:
      - NET_ADMIN
    ulimits:
      nofile:
        soft: 1048576
        hard: 1048576
    volumes:
      - /etc/nginx/ssl:/etc/nginx/ssl:ro
      - /opt/remnanode/xray-custom:/usr/local/bin/xray
    env_file:
      - .env
""" % REMNANODE_IMAGE


# ─────────────────────────────────────────────────────────────────────────────
#  Мелкие утилиты вывода
# ─────────────────────────────────────────────────────────────────────────────

def rand(n=16, alphabet=string.ascii_letters + string.digits):
    return "".join(random.choice(alphabet) for _ in range(n))

def rand_password(n=28):
    """Пароль под требования Remnawave: >=24 символов, есть A-Z, a-z и 0-9.

    Панель проверяет ^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{24,}$ — случайной
    строки мало, нужно гарантировать каждый класс символов.
    """
    n = max(n, 24)
    chars = [random.choice(string.ascii_uppercase),
             random.choice(string.ascii_lowercase),
             random.choice(string.digits)]
    pool = string.ascii_letters + string.digits
    chars += [random.choice(pool) for _ in range(n - 3)]
    random.shuffle(chars)
    return "".join(chars)


def rand_path():
    """Random path for panel/CDN access."""
    return "/" + rand(random.randint(8, 14),
                      "abcdefghijklmnopqrstuvwxyz0123456789-_")

# ─────────────────────────────────────────────────────────────────────────────
#  UI / тема оформления
#
#  Единый визуальный слой: рамки со скруглёнными углами, левый акцент-рельс,
#  нумерованные шаги, карточки key/value. Цвет включается только для TTY
#  (или при FORCE_COLOR); в пайпах/логах остаётся чистый текст. Отключить —
#  NO_COLOR=1, узкие рамки — UI_WIDTH=<n>.
# ─────────────────────────────────────────────────────────────────────────────

_TTY = (sys.stdout.isatty() and os.environ.get("NO_COLOR") is None) \
       or os.environ.get("FORCE_COLOR") == "1"
try:
    UI_W = max(48, min(100, int(os.environ.get("UI_WIDTH", "64"))))
except ValueError:
    UI_W = 64

# 256-цветная палитра
C_TITLE, C_OK, C_WARN, C_ERR = "38;5;44", "38;5;78", "38;5;214", "38;5;203"
C_DIM, C_ACC, C_VAL = "38;5;244", "38;5;177", "38;5;252"
_STEP_N = 0

def _c(code, s):
    """ANSI-цвет (только для TTY)."""
    return "\033[%sm%s\033[0m" % (code, s) if _TTY else s

def _pad(s, w):
    """Обрезать/дополнить видимую строку до ширины w (по len без ANSI)."""
    return s[:w] if len(s) > w else s + " " * (w - len(s))

def say(msg):
    print(msg, flush=True)

def ok(msg):
    print("   " + _c(C_OK,   "✔") + "  " + msg, flush=True)

def warn(msg):
    print("   " + _c(C_WARN, "▲") + "  " + msg, flush=True)

def err(msg):
    print("   " + _c(C_ERR,  "✖") + "  " + msg, flush=True)

def step(msg):
    """Нумерованный заголовок секции с левым акцент-рельсом."""
    global _STEP_N
    _STEP_N += 1
    print("", flush=True)
    print(_c(C_ACC, "▍") + _c(C_TITLE, " ШАГ %02d " % _STEP_N)
          + _c(C_TITLE, "· " + msg), flush=True)
    print(_c(C_DIM, "  " + "╌" * (UI_W - 3)), flush=True)

def hr():
    print(_c(C_DIM, "  " + "╌" * (UI_W - 3)), flush=True)

def card(title, rows, color=C_TITLE):
    """Рамка-карточка со скруглёнными углами: заголовок + строки key/value.

    rows — список (label, value) или готовых строк. Значения печатаются
    без ANSI внутри рамки, чтобы выравнивание не «поехало»."""
    inner = UI_W - 2
    print("", flush=True)
    print(_c(color, "╭" + "─" * inner + "╮"), flush=True)
    print(_c(color, "│") + _c(color, _pad(" " + title, inner)) + _c(color, "│"),
          flush=True)
    print(_c(color, "├" + "─" * inner + "┤"), flush=True)
    for row in rows:
        if isinstance(row, tuple):
            label, value = row
            body = "  %s %s" % (_pad(label, 9), value)
        else:
            body = "  " + row
        print(_c(color, "│") + _pad(body, inner) + _c(color, "│"), flush=True)
    print(_c(color, "╰" + "─" * inner + "╯"), flush=True)

def banner():
    """Стартовая рамка."""
    inner = UI_W - 2
    lines = [("VPN · CDN · INSTALLER", "1;" + C_TITLE),
             ("XHTTP packet-up через российский CDN", C_DIM),
             ("v" + INSTALLER_VERSION, C_ACC)]
    print("", flush=True)
    print(_c(C_TITLE, "╭" + "─" * inner + "╮"), flush=True)
    for text, col in lines:
        left = (inner - len(text)) // 2
        right = inner - len(text) - left
        print(_c(C_TITLE, "│") + " " * left + _c(col, text) + " " * right
              + _c(C_TITLE, "│"), flush=True)
    print(_c(C_TITLE, "╰" + "─" * inner + "╯"), flush=True)

def callout(title, lines, color=C_ACC):
    """Врезка с левым рельсом (для DNS-записей, подсказок)."""
    print("", flush=True)
    print(_c(color, "  ┃ ") + _c("1;" + color, title), flush=True)
    for ln in lines:
        print(_c(color, "  ┃ ") + _c(C_VAL, ln), flush=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Выполнение команд: локально и по SSH
# ─────────────────────────────────────────────────────────────────────────────

def nap(seconds):
    """Пауза."""
    time.sleep(seconds)

def _oneline(cmd):
    s = " ".join(cmd.split())
    return s if len(s) <= 300 else s[:297] + "..."


def shq(value):
    """Экранировать значение для вставки в шелл-строку."""
    return shlex.quote(str(value))


# Кириллические буквы, неотличимые от латинских в терминале. Один такой символ
# в домене — и вместо внятного отказа получаешь непонятную ошибку сертификата.
HOMOGLYPHS = {
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i",
    "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "З": "3", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S",
    "І": "I", "Ј": "J",
}

def homoglyph_hint(value):
    """Объяснить, что во вводе кириллица вместо латиницы. '' — если не она."""
    letters = [ch for ch in value if ch.isalpha()]
    cyr = [ch for ch in letters if "Ѐ" <= ch <= "ӿ"]
    # Домен целиком кириллицей — это не опечатка, а IDN: подсказываем punycode,
    # потому что nginx и certbot работают только с ним.
    if letters and len(cyr) == len(letters):
        try:
            puny = value.encode("idna").decode()
        except Exception:
            puny = ""
        return ("это кириллический домен. Панель, nginx и certbot понимают "
                "только punycode" + (" — введи '%s'" % puny if puny else ""))
    twins = [(i, ch) for i, ch in enumerate(value, 1) if ch in HOMOGLYPHS]
    if twins:
        where = ", ".join("'%s' в позиции %d" % (ch, i) for i, ch in twins[:4])
        fixed = "".join(HOMOGLYPHS.get(ch, ch) for ch in value)
        return ("похоже, кириллица вместо латиницы: %s. Скорее всего нужно '%s' "
                "— перенабери в английской раскладке" % (where, fixed))
    other = [(i, ch) for i, ch in enumerate(value, 1) if ord(ch) > 127]
    if other:
        return ("не-латинские символы: "
                + ", ".join("'%s' (U+%04X) в позиции %d" % (ch, ord(ch), i)
                            for i, ch in other[:4]))
    return ""


def run(cmd, timeout=600, env_extra=None):
    """Run a shell command with clean env (no bundled LD_LIBRARY_PATH).

    env_extra — переменные окружения для дочернего процесса (пароль для
    sshpass передаётся так, чтобы не светиться в ps).
    Возвращает (stdout, rc). stderr сливается в stdout.
    """
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, shell=True, env=env, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return p.stdout.decode("utf-8", "replace").strip(), p.returncode
    except subprocess.TimeoutExpired:
        return "", 124
    except Exception as e:
        return str(e), 1


SSH_KNOWN_HOSTS = "/root/.ssh/known_hosts_installer"
_ssh_dir_ready = False

def _ensure_ssh_dir():
    """~/.ssh с правами 700 под known_hosts установщика (создаётся один раз)."""
    global _ssh_dir_ready
    if _ssh_dir_ready:
        return
    d = os.path.dirname(SSH_KNOWN_HOSTS)
    try:
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o700)
    except OSError:
        pass
    _ssh_dir_ready = True


def _ssh_prefix(cred):
    """sshpass/ssh префикс по учётке {ip,user,pass|key,port}.

    Отпечаток хоста запоминается в known_hosts при первом подключении
    (accept-new): подмена сервера на последующих шагах даст отказ, а не
    молчаливую отправку пароля чужому хосту.
    """
    _ensure_ssh_dir()
    user = cred.get("user") or "root"
    port = cred.get("port") or 22
    opts = ("-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s "
            "-o ConnectTimeout=15 -p %d" % (SSH_KNOWN_HOSTS, port))
    if cred.get("key"):
        return "ssh -i %s %s %s@%s " % (shq(cred["key"]), opts, shq(user), cred["ip"])
    # пароль уходит в окружение (SSHPASS), а не в argv — ps его не покажет
    return "sshpass -e ssh %s %s@%s " % (opts, shq(user), cred["ip"])


def run_remote(cred, cmd, timeout=600):
    """Run command on remote server via SSH (password or key)."""
    safe = cmd.replace("'", "'\\''")
    env_extra = None if cred.get("key") else {"SSHPASS": cred.get("pass", "") or ""}
    return run(_ssh_prefix(cred) + "'" + safe + "'", timeout=timeout,
               env_extra=env_extra)


def write_remote(cred, path, content, mode=None):
    """Write file to remote server via base64 over SSH."""
    b = base64.b64encode(content.encode()).decode()
    cmd = "echo '%s' | base64 -d > %s" % (b, shq(path))
    if mode is not None:
        cmd += " && chmod %o %s" % (mode, shq(path))
    return run_remote(cred, cmd)


def write_file(path, content, mode=None):
    """Записать файл; mode=0o600 для всего, что содержит секреты."""
    os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
    with open(path, "w") as f:
        f.write(content)
    if mode is not None:
        os.chmod(path, mode)


# ─────────────────────────────────────────────────────────────────────────────
#  Сеть / окружение
# ─────────────────────────────────────────────────────────────────────────────

IP_SERVICES = ["ifconfig.me", "icanhazip.com", "api.ipify.org",
               "ipinfo.io/ip", "checkip.amazonaws.com"]

def get_ip(cred=None):
    """Get server's public IP (local or remote)."""
    runner = (lambda c: run_remote(cred, c)) if cred else run
    for svc in IP_SERVICES:
        out, rc = runner("curl -s4 --max-time 5 %s" % svc)
        ip = "".join(ch for ch in out if ch in "0123456789.")
        if ip.count(".") == 3:
            return ip
    out, _ = runner("hostname -I 2>/dev/null | awk '{print $1}'")
    return out.strip()


def get_country(ip=None):
    """2-letter country code of ip (or this server). '' on failure."""
    url = "https://ipinfo.io/%s/country" % ip if ip else "https://ipinfo.io/country"
    out, rc = run("curl -s --max-time 8 %s" % url)
    return out.strip().upper()[:2] if rc == 0 else ""


def check_ubuntu():
    """Exit if OS is not Ubuntu/Debian."""
    _, rc = run("which apt-get")
    if rc != 0:
        err("Поддерживается только Ubuntu/Debian!")
        say("  Переустанови сервер с Ubuntu 22.04/24.04")
        sys.exit(1)


def check_disk(need_gb, cred=None):
    """Предупредить, если под docker-образы не хватает места на /.

    Панель тянет postgres + valkey + remnawave + subscription-page: на диске
    ~5 ГБ это упирается в «no space left on device» уже на docker compose pull,
    поэтому лучше сказать об этом до установки, а не через 5 минут ожидания.
    """
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    out, rc = runner("df -Pm / | awk 'NR==2 {print $4}'")
    try:
        free_gb = int(out.strip()) / 1024.0
    except ValueError:
        return True
    if free_gb >= need_gb:
        return True
    warn("Свободно всего %.1f ГБ на / — нужно ~%d ГБ под образы Docker"
         % (free_gb, need_gb))
    say("  Освободи место (docker system prune -af; apt-get clean) "
        "или возьми диск побольше")
    if sys.stdin.isatty() and ask("Всё равно продолжить? (y/N)", "n").lower() not in ("y", "yes", "д"):
        sys.exit(1)
    return False


def fix_dns(cred=None):
    """Fix broken DNS (systemd-resolved stub) by writing direct nameservers."""
    cmd = ("nslookup google.com >/dev/null 2>&1 && exit 0; "
           "systemctl disable --now systemd-resolved 2>/dev/null; "
           "rm -f /etc/resolv.conf; "
           "printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf; "
           "nslookup google.com >/dev/null 2>&1 && echo DNS_FIXED || echo DNS_STILL_BROKEN")
    out, _ = (run_remote(cred, cmd) if cred else run(cmd))
    if "DNS_FIXED" in out:
        ok("DNS исправлен (8.8.8.8 / 1.1.1.1)")
    elif "DNS_STILL_BROKEN" in out:
        warn("DNS всё ещё не работает")


_APT_MIRROR_FIXED = set()

def ensure_apt_mirror(cred=None):
    """Если apt-зеркало недоступно — переключить на archive.ubuntu.com.

    Приватные образы VPS (Fornex, Beget) часто ставят своё зеркало, которое
    отваливается -> падает apt install и get.docker.com. Ubuntu-only, no-op на
    прочих ОС и при рабочем зеркале. Кешируется per-host.
    """
    host = cred["ip"] if cred else "local"
    if host in _APT_MIRROR_FIXED:
        return
    _APT_MIRROR_FIXED.add(host)
    script = r'''set +e
. /etc/os-release 2>/dev/null
[ "$ID" = "ubuntu" ] || exit 0
CN=${VERSION_CODENAME:-$(lsb_release -cs 2>/dev/null)}
[ -n "$CN" ] || exit 0
UPD=$(timeout 25 apt-get update -o Acquire::Retries=1 2>&1)
echo "$UPD" | grep -qiE 'Failed to fetch|Unable to connect|Could not connect|Could not resolve|No route to host|Connection refused|Connection timed out|Network is unreachable|Cannot initiate|Temporary failure|Connection failed|Hash Sum mismatch' || exit 0
echo "  apt-зеркало недоступно -> переключаю на archive.ubuntu.com"
TS=$(date +%s)
for f in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] || continue
  case "$f" in */ubuntu.sources) continue;; esac
  grep -qiE 'fornex|beget' "$f" && mv "$f" "$f.disabled.$TS" 2>/dev/null
done
if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
  cp -a /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources.bak.$TS 2>/dev/null
  cat > /etc/apt/sources.list.d/ubuntu.sources <<EOF
Types: deb
URIs: http://archive.ubuntu.com/ubuntu
Suites: $CN $CN-updates $CN-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: $CN-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF
else
  [ -f /etc/apt/sources.list ] && cp -a /etc/apt/sources.list /etc/apt/sources.list.bak.$TS 2>/dev/null
  cat > /etc/apt/sources.list <<EOF
deb http://archive.ubuntu.com/ubuntu $CN main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CN-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu $CN-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu $CN-security main restricted universe multiverse
EOF
fi
[ -f /etc/apt/sources.list ] && sed -i -E '/fornex|beget/ s/^[[:space:]]*deb/#deb/' /etc/apt/sources.list
timeout 90 apt-get update -o Acquire::Retries=3 2>&1 | tail -3
exit 0
'''
    run_remote(cred, script) if cred else run(script)


def pkg_install(packages, cred=None):
    """Установить пакеты apt: чинит DNS, зеркало, снимает блокировки, повторяет."""
    fix_dns(cred)
    ensure_apt_mirror(cred)
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    runner("kill -9 $(pgrep -f unattended-upgr) 2>/dev/null; "
           "rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock "
           "/var/cache/apt/archives/lock 2>/dev/null; "
           "dpkg --configure -a 2>/dev/null", timeout=120)
    runner("apt-get update -qq", timeout=180)
    out, rc = runner("DEBIAN_FRONTEND=noninteractive apt-get install -y %s"
                     % packages, timeout=600)
    if rc != 0:
        say("  Повторная попытка установки...")
        runner("apt-get --fix-broken install -y 2>/dev/null; "
               "apt-get update --fix-missing", timeout=300)
        out, rc = runner("DEBIAN_FRONTEND=noninteractive apt-get install -y %s"
                         % packages, timeout=600)
    if rc != 0:
        err("Не удалось установить: %s" % packages)
        say("  Попробуй вручную: apt-get update && apt-get install -y %s" % packages)
    return rc == 0


def ensure_sshpass():
    """Гарантировать sshpass для SSH-по-паролю."""
    _, rc = run("which sshpass")
    if rc == 0:
        return True
    say("  sshpass не найден, устанавливаю...")
    if pkg_install("sshpass"):
        return True
    err("sshpass установить не удалось")
    say("     Вручную: apt-get update && apt-get install -y sshpass")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Docker
# ─────────────────────────────────────────────────────────────────────────────

def setup_docker_mirror(cred=None):
    """Configure Docker Hub mirror if registry-1.docker.io is blocked."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    code, _ = runner("curl -s -m 5 -w '%{http_code}' "
                     "https://registry-1.docker.io/v2/ 2>/dev/null | tail -c 3")
    if code.strip() == "200":
        return
    say("  Настраиваю зеркало Docker Hub...")
    runner('mkdir -p /etc/docker && echo \'{"registry-mirrors":'
           '["https://huecker.io","https://dockerhub.timeweb.cloud",'
           '"https://mirror.gcr.io"]}\' > /etc/docker/daemon.json '
           '&& systemctl restart docker')
    ok("Зеркало Docker Hub настроено")


def install_docker(cred=None):
    """Robustly install Docker: get.docker.com -> docker.io -> docker-ce -> static."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    def has_docker():
        _, rc = runner("docker --version")
        return rc == 0
    if has_docker():
        return True
    runner("curl -fsSL https://get.docker.com | sh 2>&1 | tail -5", timeout=600)
    if has_docker():
        setup_docker_mirror(cred); return True

    say("  get.docker.com не сработал, чиню apt-зеркало и ставлю docker.io...")
    ensure_apt_mirror(cred)
    runner("DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io 2>&1 | tail -5",
           timeout=600)
    if has_docker():
        setup_docker_mirror(cred); return True

    say("  пробую официальный репозиторий docker-ce...")
    runner('install -m 0755 -d /etc/apt/keyrings && '
           'curl -fsSL https://download.docker.com/linux/ubuntu/gpg '
           '-o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc && '
           'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] '
           'https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) '
           'stable" > /etc/apt/sources.list.d/docker.list && apt-get update -qq && '
           'DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli '
           'containerd.io docker-compose-plugin 2>&1 | tail -5', timeout=600)
    if has_docker():
        setup_docker_mirror(cred); return True

    say("  пробую статический бинарник docker...")
    runner('cd /tmp && A=$(uname -m) && curl -fsSL '
           'https://download.docker.com/linux/static/stable/$A/docker-27.3.1.tgz -o d.tgz && '
           'tar xzf d.tgz && cp docker/* /usr/bin/ && rm -rf docker d.tgz && '
           'cat > /etc/systemd/system/docker.service <<EOF\n'
           '[Unit]\nDescription=Docker\nAfter=network.target\n'
           '[Service]\nExecStart=/usr/bin/dockerd\nRestart=always\nLimitNOFILE=1048576\n'
           '[Install]\nWantedBy=multi-user.target\nEOF\n'
           'systemctl daemon-reload && systemctl enable --now docker && sleep 6',
           timeout=600)
    if has_docker():
        setup_docker_mirror(cred); return True
    return False


def ensure_compose(cred=None):
    """Гарантировать docker compose plugin."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    _, rc = runner("docker compose version 2>/dev/null")
    if rc == 0:
        return True
    say("  docker compose plugin не найден, устанавливаю...")
    runner('apt-get install -y -qq docker-compose-plugin 2>/dev/null || '
           'apt-get install -y -qq docker-compose-v2 2>/dev/null || '
           '(mkdir -p /usr/local/lib/docker/cli-plugins && '
           'curl -fsSL https://github.com/docker/compose/releases/latest/download/'
           'docker-compose-linux-$(uname -m) '
           '-o /usr/local/lib/docker/cli-plugins/docker-compose && '
           'chmod +x /usr/local/lib/docker/cli-plugins/docker-compose)', timeout=300)
    _, rc = runner("docker compose version 2>/dev/null")
    return rc == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Тюнинг ОС, swap, nginx-база, SSL, заглушка
# ─────────────────────────────────────────────────────────────────────────────

def tune_os(cred=None):
    """sysctl BBR + limits + swap 2G."""
    if cred:
        write_remote(cred, "/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
        write_remote(cred, "/etc/security/limits.d/99-nofile.conf", LIMITS_NOFILE)
        run_remote(cred, "sysctl --system > /dev/null 2>&1")
        run_remote(cred, "swapon --show | grep -q / || (fallocate -l 2G /swapfile && "
                   "chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && "
                   "grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab)")
    else:
        write_file("/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
        write_file("/etc/security/limits.d/99-nofile.conf", LIMITS_NOFILE)
        run("sysctl --system > /dev/null 2>&1")
        _, rc = run("swapon --show | grep -q /")
        if rc != 0:
            say("  Создание swap 2G...")
            run("fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && "
                "swapon /swapfile && grep -q swapfile /etc/fstab || "
                "echo '/swapfile none swap sw 0 0' >> /etc/fstab")
        else:
            ok("Swap уже есть")


def ensure_nginx_base(cred=None):
    """Гарантировать /etc/nginx/nginx.conf (битое зеркало / удалённый conffile)."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    runner("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled "
           "/etc/nginx/conf.d /etc/nginx/ssl /var/www/html")
    _, rc = runner("test -s /etc/nginx/nginx.conf")
    if rc == 0:
        return
    ensure_apt_mirror(cred)
    runner("DEBIAN_FRONTEND=noninteractive apt-get install -y nginx-common nginx-core "
           "2>&1 | tail -3", timeout=300)
    runner("DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "
           "-o Dpkg::Options::=--force-confmiss nginx-common 2>&1 | tail -3", timeout=300)
    _, rc = runner("test -s /etc/nginx/nginx.conf")
    if rc != 0:
        if cred:
            write_remote(cred, "/etc/nginx/nginx.conf", NGINX_MINIMAL_CONF)
            run_remote(cred, "[ -s /etc/nginx/mime.types ] || cat > /etc/nginx/mime.types <<'EOF'\n"
                       + NGINX_MINIMAL_MIME + "EOF")
        else:
            write_file("/etc/nginx/nginx.conf", NGINX_MINIMAL_CONF)
            if not os.path.exists("/etc/nginx/mime.types"):
                write_file("/etc/nginx/mime.types", NGINX_MINIMAL_MIME)
        say("  nginx.conf восстановлен (минимальный конфиг)")


def self_signed_cert(cn="cdn-origin", cred=None):
    """Создать self-signed cdn.crt/cdn.key если их нет (ключ — только root)."""
    cmd = ("mkdir -p /etc/nginx/ssl && chmod 700 /etc/nginx/ssl && test -f %s || "
           "openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
           "-keyout %s -out %s -subj '/CN=%s' 2>/dev/null; chmod 600 %s 2>/dev/null"
           % (CDN_CRT, CDN_KEY, CDN_CRT, cn, CDN_KEY))
    run_remote(cred, cmd) if cred else run(cmd)


def write_decoy(domain, cred=None):
    """Написать страницу-заглушку в /var/www/html/index.html."""
    html = DECOY_HTML.format(domain=domain)
    if cred:
        run_remote(cred, "mkdir -p /var/www/html")
        write_remote(cred, "/var/www/html/index.html", html)
    else:
        write_file("/var/www/html/index.html", html)


def nginx_write_conf(name, content):
    """Write nginx site config and enable symlink."""
    run("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled")
    path = "/etc/nginx/sites-available/%s" % name
    write_file(path, content)
    run("rm -f /etc/nginx/sites-enabled/%s && ln -s %s /etc/nginx/sites-enabled/%s"
        % (name, path, name))
    # server_names_hash_bucket_size + worker_connections
    run("sed -i 's/worker_connections[[:space:]]*[0-9]*/worker_connections 16384/' "
        "/etc/nginx/nginx.conf")
    out, rc = run("nginx -t && systemctl restart nginx")
    if rc != 0:
        warn("проблема с nginx:\n" + out)
        say("  Попробуй: nginx -t и systemctl restart nginx")
    return rc == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Xray: бинарник на ноду, x25519, RU-гео, инбаунды
# ─────────────────────────────────────────────────────────────────────────────

def _rng(spec):
    """'100-1000' -> случайное int в диапазоне; одиночное число -> оно же."""
    if "-" in spec:
        a, b = spec.split("-"); return random.randint(int(a), int(b))
    return int(spec)


def gen_x25519(cred=None):
    """Generate x25519 keypair for Reality. Returns (private, public) or (None,None)."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    variants = [
        "docker exec remnanode xray x25519 2>/dev/null",
        "xray x25519 2>/dev/null",
        "/usr/local/bin/xray x25519 2>/dev/null",
        "/usr/local/x-ui/bin/xray x25519 2>/dev/null",
        "docker run --rm %s xray x25519 2>/dev/null" % REMNANODE_IMAGE,
        # последний резерв — openssl
        "openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null",
    ]
    for cmd in variants:
        out, rc = runner(cmd)
        if not out:
            continue
        priv = pub = None
        for line in out.splitlines():
            low = line.lower()
            if "private" in low:
                priv = line.split(":")[-1].strip()
            elif "public" in low:
                pub = line.split(":")[-1].strip()
        # формат "xray x25519": "Private key: ...\nPublic key: ..."
        if priv and pub:
            return priv, pub
    err("Не удалось сгенерировать x25519 ключи")
    return None, None


def setup_xray_ru_geo(asset_dir="/usr/local/share/xray", cred=None):
    """Скачать geoip_RU.dat / geosite_RU.dat (runetfreedom). Без них xray не стартует."""
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    files = ["geoip.dat", "geoip_RU.dat", "geosite.dat", "geosite_RU.dat"]
    dl = " && ".join(
        "( curl -fsSL --max-time 900 -o %s %s/%s || "
        "curl -fsSL --max-time 900 -o %s https://gh-proxy.com/%s/%s )"
        % (f, RU_GEO_URL, f, f, RU_GEO_URL, f) for f in files)
    cmd = ("mkdir -p %s && cd %s && %s && test -s geoip_RU.dat && "
           "test -s geosite_RU.dat && echo GEO_OK" % (asset_dir, asset_dir, dl))
    out, _ = runner(cmd, timeout=1200)
    if "GEO_OK" not in out:
        warn("RU гео-файлы не скачались — xray может не стартовать (роутинг .ru)")
        return False
    # прописать XRAY_LOCATION_ASSET для systemd-xray
    runner("mkdir -p /etc/systemd/system/xray.service.d && "
           "printf '[Service]\\nEnvironment=XRAY_LOCATION_ASSET=%s\\n' "
           "> /etc/systemd/system/xray.service.d/asset.conf && systemctl daemon-reload"
           % asset_dir)
    return True


def build_xhttp_inbound(port, path, tag, uuid, host):
    """XHTTP packet-up inbound для xray-core (слушает 127.0.0.1:port, TLS снимает nginx).

    Ключи: mode=packet-up, xPaddingBytes, scMaxEachPostBytes,
    scMinPostsIntervalMs, noSSEHeader, xmux.
    """
    return {
        "tag": tag,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": uuid, "email": "user1"}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": {
                "host": host,
                "path": path,
                "mode": "packet-up",
                "noSSEHeader": True,
                "scMaxEachPostBytes": _rng(PU_SC_MAXBYTES),
                "scMinPostsIntervalMs": _rng(PU_SC_MININT),
                "xPaddingBytes": PU_PADDING,
                "xmux": {
                    "maxConcurrency": _rng(PU_XMUX_CONC),
                    "maxReuseTimes": _rng(PU_XMUX_REUSE),
                },
            },
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }


def build_hy2_inbound(port, uuid):
    """Hysteria2 inbound (UDP) для xray-core с cdn.crt/cdn.key."""
    return {
        "tag": "hy2-in-%d" % port,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "hysteria2",
        "settings": {"clients": [{"password": uuid, "email": "user1"}]},
        "streamSettings": {
            "security": "tls",
            "tlsSettings": {
                "certificates": [{"certificateFile": CDN_CRT, "keyFile": CDN_KEY}],
            },
        },
    }


def build_grpc_inbound(port, uuid, priv, pub, sid, service):
    """VLESS Reality gRPC inbound для xray-core."""
    return {
        "tag": "grpc-reality-%d" % port,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": uuid, "email": "user1", "flow": ""}],
            "decryption": "none",
        },
        "streamSettings": {
            "network": "grpc",
            "security": "reality",
            "realitySettings": {
                "dest": REALITY_DEST,
                "serverNames": [REALITY_SNI],
                "privateKey": priv,
                "shortIds": [sid],
                "fingerprint": "random",
            },
            "grpcSettings": {"serviceName": service},
        },
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }


def cert_sha256(cred=None):
    """SHA256 hex сертификата cdn.crt (для HY2 pinning)."""
    cmd = "openssl x509 -in %s -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1" % CDN_CRT
    out, _ = (run_remote(cred, cmd) if cred else run(cmd))
    return out.strip().split()[0] if out else ""


# ─────────────────────────────────────────────────────────────────────────────
#  nginx CDN-origin конфиг (сердце XHTTP-фронтинга)
# ─────────────────────────────────────────────────────────────────────────────

def nginx_cdn_origin_config(port, path, style="prefix",
                            crt=CDN_CRT, key=CDN_KEY, ipv6=True):
    """Generate nginx CDN origin config.

    style:
      "prefix"  — path это каталог. Голый путь отдаёт 404, проксируется только
                  то, что под ним: активная проба ровно по <path> неотличима от
                  обращения к несуществующей странице, а xhttp всегда ходит на
                  <path>/<сессия>. (Снято с рабочей ноды на Yandex CDN.)
      "rewrite" — path это файл (/static/getFile/video/segment.ts): нужен ^~ и
                  rewrite, добавляющий слеш, иначе xhttp не матчится.
                  (Проверено автором на Beeline 28.07.2026.)
    """
    proxy_block = """        proxy_pass http://xray_xhttp;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;

        proxy_pass_request_headers on;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_cache off;
        proxy_max_temp_file_size 0;
        gzip off;

        proxy_connect_timeout 10s;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        send_timeout 1h;

        client_max_body_size 0;
        proxy_socket_keepalive on;

        add_header X-Accel-Buffering no always;
        add_header Cache-Control "no-store, no-cache" always;
        add_header CDN-Cache-Control "no-store" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        add_header Accept-Ranges none always;
"""
    if style == "rewrite":
        loc = ("    location ^~ %s {\n        rewrite ^%s/ break;\n%s    }\n\n"
               "    location = %s {\n        return 404;\n    }\n"
               % (path, path, proxy_block, path))
    else:
        loc = ("    location = %s {\n        return 404;\n    }\n\n"
               "    location %s/ {\n%s    }\n" % (path, path, proxy_block))

    v6_80  = "\n    listen [::]:80 default_server;" if ipv6 else ""
    v6_443 = "\n    listen [::]:443 ssl http2 default_server;" if ipv6 else ""
    return """upstream xray_xhttp {
    server 127.0.0.1:%d;
    keepalive 128;
}

server {
    listen 80 default_server;%s
    listen 443 ssl http2 default_server;%s
    server_name _;

    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location = /health {
        default_type application/json;
        return 200 '{"status":"ok","service":"media-gateway","version":"4.2.1"}';
    }

%s
    location / {
        root /var/www/html;
        index index.html;
        try_files $uri $uri/ =404;
    }
}
""" % (port, v6_80, v6_443, crt, key, loc)


# ─────────────────────────────────────────────────────────────────────────────
#  Remnawave API
# ─────────────────────────────────────────────────────────────────────────────

def rw_api_local(token, method, path, data=None):
    """Make API call to local Remnawave panel (127.0.0.1:3000)."""
    import urllib.request, urllib.error
    url = "http://127.0.0.1:3000/api/" + path.lstrip("/")
    # PANEL_DOMAIN как Host, чтобы пройти проверку origin панели
    rdom, _ = run('grep -oP "PANEL_DOMAIN=\\K.*" /opt/remnawave/.env 2>/dev/null')
    rdom = rdom.strip() or "localhost"
    hdr = {
        "Content-Type": "application/json",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        # JwtDefaultGuard пускает админский JWT только с этим заголовком, иначе
        # 403 «For API requests you must create own API-token». Для роли API
        # (постоянный токен) заголовок не проверяется, так что шлём всегда.
        "X-Remnawave-Client-Type": "browser",
        "Host": rdom,
    }
    if token:
        hdr["Authorization"] = "Bearer " + token
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode("utf-8", "replace")
            return (json.loads(raw) if raw else {}), r.status
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return json.loads(raw), e.code
        except Exception:
            return {"error": raw}, e.code
    except Exception as e:
        return {"error": str(e)}, 0


def rw_api_ssh(cred, token, method, path, data=None):
    """Make API call to Remnawave panel via SSH (curl to 127.0.0.1:3000)."""
    url = "http://127.0.0.1:3000/api/" + path.lstrip("/")
    base = ('RDOM=$(grep -oP "PANEL_DOMAIN=\\K.*" /opt/remnawave/.env 2>/dev/null); '
            'curl -s -X %s -H "Content-Type: application/json" '
            '-H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" '
            '-H "X-Real-IP: 127.0.0.1" -H "X-Remnawave-Client-Type: browser" '
            '-H "Host: ${RDOM:-localhost}" ' % method)
    tok, _ = run_remote(cred, "cat /opt/remnawave/.panel_token 2>/dev/null")
    tok = (token or tok).strip()
    if tok:
        base += '-H "Authorization: Bearer %s" ' % tok
    if data is not None:
        b = base64.b64encode(json.dumps(data).encode()).decode()
        base += '-d "$(echo %s | base64 -d)" ' % b
    out, _ = run_remote(cred, base + '"%s"' % url)
    if not out.strip():
        return {"error": "empty response"}, 0
    try:
        return json.loads(out), 200
    except Exception:
        return {"error": "invalid JSON", "raw": out[:200]}, 0


def rw_login_ssh(cred, username, password):
    """Логин в Remnawave через SSH-curl на панели. Возвращает accessToken или ''."""
    resp, _ = rw_api_ssh(cred, "", "POST", "auth/login",
                         {"username": username, "password": password})
    return ((resp.get("response") or {}).get("accessToken")
            or resp.get("accessToken") or "")


def resolve_panel_token(cred, cfg):
    """Достать рабочий токен API панели: --panel-token → файл на панели → логин.

    Без токена все вызовы API вернут 401, а нода молча создастся без профиля,
    поэтому токен проверяется боевым запросом до начала установки.
    """
    tok = (cfg.get("panel_token") or "").strip()
    src = "--panel-token"
    if not tok:
        out, _ = run_remote(cred, "cat /opt/remnawave/.panel_token 2>/dev/null")
        cand = out.strip()
        if cand and "\n" not in cand and " " not in cand:
            tok, src = cand, "/opt/remnawave/.panel_token"
    if not tok:
        # тот же способ, что и локально: подписать API-JWT секретом панели.
        # Работает без логина/пароля, если у нас есть SSH к панели.
        cand = mint_api_token(lambda c, **k: run_remote(cred, c, **k))
        if cand:
            tok, src = cand, "APP_SECRET (self-signed)"
    if not tok:
        user, pwd = cfg.get("panel_user"), cfg.get("panel_pass")
        if not (user and pwd) and sys.stdin.isatty():
            warn("Токен панели не найден — панель ставил не этот установщик")
            say("  Введи логин админа панели (или Ctrl-C и запусти с --panel-token)")
            user = user or ask("Логин админа панели")
            pwd = pwd or ask_secret("Пароль админа панели")
        if user and pwd:
            tok, src = rw_login_ssh(cred, user, pwd), "auth/login"
    if not tok:
        err("Нет токена API панели — нода не сможет зарегистрироваться")
        say("  Передай --panel-token <JWT> или --panel-user/--panel-pass")
        return ""
    probe, _ = rw_api_ssh(cred, tok, "GET", "nodes")
    if "response" not in probe:
        err("Токен панели не принят (%s): %s"
            % (src, str(probe.get("error") or probe)[:120]))
        return ""
    ok("Токен API панели: OK (%s)" % src)
    return tok


def remnawave_register(username, password):
    """Регистрация первого админа. Возвращает JWT-токен логина или ''."""
    resp, code = rw_api_local(None, "POST", "auth/register",
                              {"username": username, "password": password})
    # code=0 — до HTTP не дошло: REST-инстанс панели ещё не слушает 3000 и
    # docker-proxy рвёт соединение. Ждать тут дешевле, чем падать.
    for attempt in range(6):
        if code != 0:
            break
        say("  Панель оборвала соединение, повтор через 5 с (%d/6)..." % (attempt + 1))
        nap(5)
        resp, code = rw_api_local(None, "POST", "auth/register",
                                  {"username": username, "password": password})
    if code in (200, 201):
        ok("Админ зарегистрирован")
    elif code in (400, 409):
        # 400 — это не только «уже зарегистрирован», но и отказ валидации
        # (пароль короче 24 символов либо без цифры/заглавной). Считать его
        # успехом нельзя: раньше установка доезжала до конца с пустым токеном
        # и 401 на каждом вызове API.
        say("  Регистрация вернула %s: %s"
            % (code, str(resp.get("message") or resp)[:160]))
    tok = (resp.get("response", {}) or {}).get("accessToken") or resp.get("accessToken")
    if not tok:
        resp, code = rw_api_local(None, "POST", "auth/login",
                                  {"username": username, "password": password})
        tok = (resp.get("response", {}) or {}).get("accessToken") or resp.get("accessToken")
        if not tok:
            err("Ни регистрация, ни вход не дали токен: %s"
                % str(resp.get("message") or resp)[:160])
    return tok or ""


def _sign_api_jwt(secret, uuid_str, days=365):
    """Подписать JWT роли API секретом панели (HS256).

    Панель проверяет ВСЕ токены секретом APP_SECRET (jwt.strategy.ts), а гвард
    для роли API не требует заголовка X-Remnawave-Client-Type — в отличие от
    ADMIN. Значит достаточно подписать {uuid, username, role:'API'} тем же
    секретом; проверено против эталона jwt.io побайтово.
    """
    import hmac, hashlib
    b = lambda x: base64.urlsafe_b64encode(x).rstrip(b"=")
    now = int(time.time())
    seg = (b(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
           + b"." + b(json.dumps({"uuid": uuid_str, "username": None, "role": "API",
                                  "iat": now, "exp": now + days * 86400},
                                 separators=(",", ":")).encode()))
    sig = b(hmac.new(secret.encode(), seg, hashlib.sha256).digest())
    return (seg + b"." + sig).decode()


def mint_api_token(runner, db="remnawave-db"):
    """Выпустить API-токен без обращения к /api/tokens.

    /api/tokens висит на роли ADMIN и без browser-заголовка отвечает 403, а
    login-JWT на остальных маршрутах панель тоже не принимает. Рабочий путь
    (как в оригинальном установщике): взять секрет из .env, вписать строку в
    api_tokens и самому подписать JWT роли API — гвард верифицирует его тем же
    секретом и находит uuid в таблице.

    runner(cmd) -> (out, rc); работает и локально, и по SSH на панели.
    """
    secret = ""
    for var in ("APP_SECRET", "JWT_API_TOKENS_SECRET", "JWT_AUTH_SECRET"):
        out, _ = runner('grep -oP "%s=\\K.*" /opt/remnawave/.env 2>/dev/null' % var)
        secret = (out or "").strip().strip('"')
        if secret:
            break
    if not secret:
        err("APP_SECRET не найден в /opt/remnawave/.env — токен не подписать")
        return ""
    tok_uuid = str(_uuid.uuid4())
    jwt = _sign_api_jwt(secret, tok_uuid)
    # запись токена в БД: SQL уходит через base64+stdin, чтобы кавычки и
    # массив scopes '{"*"}' не поломались в shell
    sql = ("DELETE FROM api_tokens WHERE name = 'installer-cdn';\n"
           "INSERT INTO api_tokens (uuid, name, created_at, updated_at, scopes, expire_at) "
           "VALUES ('%s', 'installer-cdn', NOW(), NOW(), '{\"*\"}', "
           "NOW() + INTERVAL '365 days') ON CONFLICT (uuid) DO NOTHING;" % tok_uuid)
    b64 = base64.b64encode(sql.encode()).decode()
    out, rc = runner("echo %s | base64 -d | docker exec -i %s psql -U postgres -v ON_ERROR_STOP=1"
                     % (b64, db))
    if rc != 0 or "ERROR" in (out or ""):
        err("Не удалось записать токен в БД: %s" % (out or "").strip()[:160])
        return ""
    return jwt


def remnawave_api_token(login_jwt):
    """Выпустить рабочий API-токен для локальной панели (роль API)."""
    jwt = mint_api_token(run)
    if jwt:
        probe, _ = rw_api_local(jwt, "GET", "nodes")
        if "response" in probe:
            ok("API-токен выпущен (self-signed, роль API)")
            return jwt
        warn("Self-signed токен не принят: %s"
             % str(probe.get("message") or probe)[:120])
    # запасной путь — штатный /api/tokens (нужен admin JWT + browser-заголовок)
    if login_jwt:
        run('docker exec remnawave-db psql -U postgres -c '
            '"DELETE FROM api_tokens WHERE name = \'installer\';" 2>/dev/null')
        resp, code = rw_api_local(login_jwt, "POST", "tokens",
                                  {"name": "installer",
                                   "description": "node-installer-cdn"})
        tok = (((resp.get("response") or {}).get("token") or {}).get("token") or "").strip()
        if tok:
            ok("API-токен выпущен через /api/tokens")
            return tok
        err("Панель не выдала API-токен (%s): %s"
            % (code, str(resp.get("message") or resp)[:160]))
    return ""


def _slug(prefix):
    return "%s-%s" % (prefix, rand(6, "abcdefghijklmnopqrstuvwxyz0123456789"))


def _leftovers(paths, containers, vol_filter=""):
    """Что осталось от прошлой установки: каталоги, контейнеры, тома."""
    found = [p for p in paths if os.path.exists(p)]
    names, _ = run("docker ps -a --format '{{.Names}}' 2>/dev/null")
    found += ["контейнер " + c for c in containers if c in names.split()]
    if vol_filter:
        vols, _ = run("docker volume ls -q --filter name=%s 2>/dev/null" % vol_filter)
        found += ["том " + v for v in vols.split()]
    return found


def wipe_previous(panel=False, node=False, assume_yes=False):
    """Снести прошлую установку до начала новой.

    Установщик ставит начисто, а остатки прежней попытки ломают новую: том
    базы хранит пароль от самой первой инициализации, и никакой .env его уже
    не восстановит (POSTGRES_PASSWORD применяется только один раз). Дешевле
    удалить, чем угадывать совместимость.
    """
    found = []
    if panel:
        found += _leftovers(["/opt/remnawave"],
                            ["remnawave", "remnawave-db", "remnawave-redis"],
                            "remnawave")
    if node:
        found += _leftovers(["/opt/remnanode"], ["remnanode"])
    if not found:
        return
    warn("Найдены остатки прошлой установки:")
    for f in found:
        say("    - %s" % f)
    say("  Вместе с ними удалится база панели (пользователи, ноды, подписки)")
    if not assume_yes and sys.stdin.isatty():
        if ask("Снести и поставить начисто? (Y/n)", "y").lower() in ("n", "no", "н", "нет"):
            say("  Оставляю как есть — установка продолжится поверх")
            return
    step("Удаление прошлой установки")
    if panel:
        run("cd /opt/remnawave && docker compose down -v --remove-orphans 2>/dev/null",
            timeout=120)
        run("docker rm -f remnawave remnawave-db remnawave-redis 2>/dev/null")
        run("docker volume ls -q --filter name=remnawave "
            "| xargs -r docker volume rm -f 2>/dev/null")
        run("rm -rf /opt/remnawave")
    if node:
        run("cd /opt/remnanode && docker compose down -v --remove-orphans 2>/dev/null",
            timeout=120)
        run("docker rm -f remnanode 2>/dev/null")
        run("rm -rf /opt/remnanode")
    ok("Прошлая установка удалена")


def resolve_pg_pass():
    """Пароль postgres, совместимый с уже существующим томом базы.

    POSTGRES_PASSWORD применяется только при ПЕРВОЙ инициализации кластера.
    Том remnawave-db-data переживает docker compose down, поэтому свежий
    случайный пароль в старую базу не попадёт, и панель ляжет в крэш-луте с
    Prisma P1000 (authentication failed). Если том остался — берём пароль из
    прежнего .env, а если его не восстановить, предлагаем снести базу.
    """
    out, _ = run("docker volume ls -q --filter name=remnawave-db-data")
    if not out.strip():
        return rand(24)
    old = ""
    try:
        with open("/opt/remnawave/.env") as f:
            for line in f:
                if line.startswith("POSTGRES_PASSWORD="):
                    old = line.split("=", 1)[1].strip()
                    break
    except OSError:
        pass
    if old:
        say("  Найден том базы от прошлой установки — использую её пароль")
        return old
    warn("Том базы remnawave-db-data остался от прошлой установки, "
         "а пароль от него утерян")
    say("  С новым паролем панель не войдёт в базу (Prisma P1000)")
    if sys.stdin.isatty() and ask("Удалить старую базу и поставить начисто? (y/N)",
                                  "n").lower() in ("y", "yes", "д", "да"):
        run("cd /opt/remnawave && docker compose down -v 2>/dev/null")
        run("docker volume rm -f remnawave-db-data "
            "remnawave_remnawave-db-data 2>/dev/null")
        return rand(24)
    err("Без совпадающего пароля установка не поднимется")
    say("  Удали том вручную: cd /opt/remnawave && docker compose down -v")
    sys.exit(1)


def remnawave_bringup(cfg):
    """Docker + compose + .env + запуск контейнеров + регистрация админа + API-токен.

    Общая часть панели Remnawave для режима 1 (панель+нода) и режима 4 (только
    панель). Возвращает API-токен (или '' при неудаче)."""
    domain   = cfg["domain"]
    admin_pw = cfg["admin_pass"]

    step("Установка панели Remnawave 3.x")
    check_disk(5)
    if not install_docker() or not ensure_compose():
        err("Docker не установился! Попробуй вручную: curl -fsSL https://get.docker.com | sh")
        sys.exit(1)

    os.makedirs("/opt/remnawave", exist_ok=True)
    pg_pass = resolve_pg_pass()
    # POSTGRES_PASSWORD подставляется прямо в compose — файл только для root
    write_file("/opt/remnawave/docker-compose.yml",
               REMNAWAVE_COMPOSE.replace("{pg_pass}", pg_pass), mode=0o600)
    # .env по схеме Remnawave 3.x: APP_SECRET вместо JWT_*, redis через unix-сокет,
    # WEBHOOK_SECRET_HEADER ровно 64 символа [a-zA-Z0-9], отдельный порт метрик.
    env = (
        "APP_PORT=3000\n"
        "METRICS_PORT=3001\n"
        "API_INSTANCES=1\n"
        "APP_SECRET=%s\n"
        "METRICS_USER=metrics\n"
        "METRICS_PASS=%s\n"
        "WEBHOOK_ENABLED=false\n"
        "WEBHOOK_SECRET_HEADER=%s\n"
        "POSTGRES_USER=postgres\n"
        "POSTGRES_PASSWORD=%s\n"
        "POSTGRES_DB=postgres\n"
        'DATABASE_URL="postgresql://postgres:%s@remnawave-db:5432/postgres"\n'
        "REDIS_SOCKET=/var/run/valkey/valkey.sock\n"
        "FRONT_END_DOMAIN=%s\n"
        "PANEL_DOMAIN=%s\n"
        "SUB_PUBLIC_DOMAIN=%s/api/sub\n"
        % (rand(64), rand(16), rand(64), pg_pass, pg_pass,
           domain, domain, domain)
    )
    write_file("/opt/remnawave/.env", env, mode=0o600)          # пароль БД, JWT

    say("  Запуск контейнеров Remnawave...")
    run("cd /opt/remnawave && docker compose down 2>/dev/null")
    out, rc = run("cd /opt/remnawave && docker compose pull 2>&1", timeout=900)
    if rc != 0:
        err("docker compose pull не прошёл — образы не скачались:")
        say("  " + "\n  ".join(out.strip().splitlines()[-8:]))
        if "no space left" in out.lower():
            say(run("df -h /")[0])
            say("  Освободи место (docker system prune -af) или возьми диск побольше")
        sys.exit(1)
    out, rc = run("cd /opt/remnawave && docker compose up -d 2>&1", timeout=600)
    if rc != 0:
        err("docker compose up ошибка:\n" + out)
        sys.exit(1)

    say("  Ожидание запуска контейнеров (до 5 минут)...")
    up = False
    dying = 0
    for i in range(60):
        # /health на порту метрик — тот же эндпоинт, что в healthcheck контейнера.
        # По auth/register проверять нельзя: маршрут только POST, и GET на нём
        # всегда отдаёт 404, сколько бы панель ни работала.
        # Готовность — это ответ САМОГО API на 3000, а не /health на 3001.
        # Метрики поднимаются раньше REST-инстанса (в логах панели cron-0
        # стартует на секунду-полторы раньше rest-0), а порт 3000 к тому
        # моменту уже опубликован docker-proxy: он принимает соединение и рвёт
        # его, раз внутри контейнера ещё никто не слушает. Регистрация в эту
        # щель ловила ECONNRESET сразу после бодрого «панель запущена».
        #
        # Заголовки обязательны: proxyCheckMiddleware рвёт сокет, если нет
        # x-forwarded-proto: https И непустого x-forwarded-for. Без них ответа
        # не будет никогда и проба ничего не измеряет.
        code, _ = run("RDOM=$(grep PANEL_DOMAIN /opt/remnawave/.env | head -1 | cut -d= -f2); "
                      "curl -s -X POST -H \"Host: ${RDOM:-localhost}\" "
                      "-H 'Content-Type: application/json' -d '{}' "
                      "http://127.0.0.1:3000/api/auth/register "
                      "-H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1' "
                      "-o /dev/null -w '%{http_code}'")
        if code.strip() in ("200", "201", "400", "409", "422"):
            up = True; break
        if i and i % 6 == 0:      # каждые 30 с — признак жизни, а не молчание на 5 минут
            ps, _ = run("cd /opt/remnawave && docker compose ps -a "
                        "--format '{{.Service}}={{.State}}' 2>/dev/null")
            states = ps.split()
            say("  %3d с · %s" % (i * 5, " ".join(states) or "контейнеров нет"))
            if states and not any("running" in s.lower() for s in states):
                err("Ни один контейнер не поднялся — ждать дальше бессмысленно")
                break
            # remnawave=restarting значит, что панель уже упала и её поднял
            # restart:always. Второй такой замер подряд — это не «долгий старт»,
            # а цикл падений: ждать оставшиеся минуты незачем.
            panel_state = next((s for s in states if s.startswith("remnawave=")), "")
            if any(w in panel_state for w in ("restarting", "exited", "dead")):
                dying += 1
                if dying >= 2:
                    err("Контейнер remnawave падает и перезапускается по кругу")
                    break
            else:
                dying = 0
        nap(5)
    if not up:
        err("Панель Remnawave не поднялась — логи контейнеров:")
        logs = run("docker compose -f /opt/remnawave/docker-compose.yml "
                   "logs --tail=50 2>&1")[0]
        say(logs)
        if "P1000" in logs:
            say("  Пароль не подошёл к существующей базе. Снести её и начать "
                "начисто: cd /opt/remnawave && docker compose down -v")
        sys.exit(1)
    ok("Панель Remnawave запущена")

    # nginx для панели (proxy 127.0.0.1:3000) + LE или self-signed
    say("  Регистрация админа...")
    login_jwt = remnawave_register("admin", admin_pw)
    token = remnawave_api_token(login_jwt)
    if not token:
        err("Без токена панели профиль, ноду и юзера создать нельзя")
        say("  Сама панель работает: https://%s/ — но настроить её через API "
            "не выйдет, продолжать бессмысленно" % domain)
        sys.exit(1)
    write_file("/opt/remnawave/.panel_token", token, mode=0o600)
    return token


def install_remnawave(cfg):
    """Install Remnawave 3.x panel + node + profile + host + user (mode 1, local)."""
    domain   = cfg["domain"]
    origin   = cfg.get("origin_domain", domain)
    cdn_dom  = cfg.get("cdn_domain", "")
    path     = cfg["path"]
    xport    = cfg["xport"]

    token = remnawave_bringup(cfg)

    # ── профиль + инбаунды (CDN xhttp + опц. hy2/grpc + опц. BRIDGE_IN) ──
    step("Создание профиля, ноды, хоста и юзера через API")
    user_uuid = str(_uuid.uuid4())
    inbounds = [build_xhttp_inbound(xport, path, "%s-CDN" % (cfg["cdn"]),
                                    user_uuid, origin)]
    reality = None
    if not cfg.get("no_hy2"):
        inbounds.append(build_hy2_inbound(8443, user_uuid))
        ok("Добавлен Hysteria2 inbound (UDP 8443)")
    if not cfg.get("no_grpc"):
        priv, pub = gen_x25519()
        if priv:
            sid = rand(8, "0123456789abcdef")
            inbounds.append(build_grpc_inbound(2053, user_uuid, priv, pub, sid,
                                               _slug("grpc")))
            reality = {"pbk": pub, "sid": sid}
            ok("Добавлен gRPC Reality inbound (TCP 2053)")
    if cfg.get("cascade"):
        inbounds.append(build_xhttp_inbound(8888, path, "BRIDGE_IN", user_uuid, origin))
        ok("Добавлен BRIDGE_IN inbound (TCP 8888) для каскада")

    prof_tag = _slug("cdn")
    profile = {"name": prof_tag, "inbounds": inbounds}
    resp, code = None, 0
    for attempt in range(3):
        resp, code = rw_api_local(token, "POST", "config-profiles", profile)
        if code in (200, 201):
            break
        say("  API retry профиля (%d/3), жду 10 сек..." % (attempt + 1))
        nap(10)
    prof_uuid = (resp.get("response", {}) or {}).get("uuid") if resp else None
    if not prof_uuid:
        warn("Ответ создания профиля: %s" % json.dumps(resp)[:200])
    else:
        say("  Profile UUID: %s" % prof_uuid)

    # ── нода (remnanode на 127.0.0.1:2222 внутри docker gateway) ──
    step("Настройка ноды Remnawave")
    gw, _ = run("docker network inspect remnawave-network "
                "-f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'")
    gw = gw.strip() or "172.18.0.1"
    say("  Docker gateway: %s" % gw)
    node = {"name": "node-local", "address": gw, "port": 2222,
            "configProfile": {"activeConfigProfileUuid": prof_uuid,
                              "activeInbounds": [i["tag"] for i in inbounds]}}
    resp, code = rw_api_local(token, "POST", "nodes", node)
    node_uuid = (resp.get("response", {}) or {}).get("uuid") if resp else None
    secret = (resp.get("response", {}) or {}).get("secretKey") if resp else None
    if node_uuid:
        say("  Node UUID: %s" % node_uuid)

    os.makedirs("/opt/remnanode", exist_ok=True)
    download_xray_binary("/opt/remnanode/xray-custom")
    write_file("/opt/remnanode/docker-compose.yml", REMNANODE_COMPOSE)
    write_file("/opt/remnanode/.env", "NODE_PORT=2222\nSECRET_KEY=%s\n" % (secret or ""),
               mode=0o600)
    setup_xray_ru_geo()
    say("  Запуск контейнера remnanode...")
    run("cd /opt/remnanode && docker compose pull", timeout=600)
    run("cd /opt/remnanode && docker compose up -d")
    # Файрвол ставим до ограничения 2222: тогда правило ноды уходит в ufw и
    # переживает перезагрузку. Порты запасных каналов открываем явно, иначе
    # политика deny incoming их закроет.
    extra_tcp = ([8888] if cfg.get("cascade") else []) \
        + ([] if cfg.get("no_grpc") else [2053])
    extra_udp = [] if cfg.get("no_hy2") else [8443]
    firewall_setup(extra_tcp=extra_tcp, extra_udp=extra_udp)
    restrict_node_port_2222(gw)
    node_wait_ready()

    # ── хост CDN + опц. hy2/grpc, юзер, сквад ──
    create_remnawave_host(token, prof_uuid, inbounds[0]["tag"], cdn_dom or origin,
                          origin, path, reality)
    add_inbounds_to_squad(token, [i["tag"] for i in inbounds])
    sub_url = create_remnawave_user(token, "user1", user_uuid, domain)

    return {"token": token, "user_uuid": user_uuid, "sub_url": sub_url,
            "reality": reality, "prof_uuid": prof_uuid}


def download_xray_binary(dest):
    """Download xray XRAY_MIN_VERSION binary for volume-mount into remnanode."""
    _, rc = run("test -x %s && %s version 2>/dev/null | head -1" % (dest, dest))
    if rc == 0:
        ok("Xray %s уже скачан" % XRAY_MIN_VERSION); return
    say("  Скачивание xray %s..." % XRAY_MIN_VERSION)
    arch, _ = run("uname -m")
    zipname = ("Xray-linux-arm64-v8a.zip" if "aarch64" in arch or "arm64" in arch
               else "Xray-linux-64.zip")
    url = ("https://github.com/XTLS/Xray-core/releases/download/v%s/%s"
           % (XRAY_MIN_VERSION, zipname))
    out, rc = run("cd /tmp && curl -sL -o xray_dl.zip '%s' && "
                  "python3 -c \"import zipfile;z=zipfile.ZipFile('xray_dl.zip');"
                  "z.extract('xray','xray_dl');z.close()\" && mv xray_dl/xray '%s' && "
                  "chmod +x '%s' && rm -rf xray_dl.zip xray_dl" % (url, dest, dest),
                  timeout=300)
    if rc == 0:
        ok("Xray %s готов" % XRAY_MIN_VERSION)
    else:
        warn("Не удалось скачать xray: %s" % out[:120])


def detect_ssh_port(runner):
    """Порт sshd из sshd_config (иначе 22) — чтобы не отрезать себе доступ."""
    out, _ = runner("awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' "
                    "/etc/ssh/sshd_config 2>/dev/null")
    p = out.strip()
    return p if p.isdigit() and 0 < int(p) < 65536 else "22"


def ufw_active(runner):
    out, _ = runner("ufw status 2>/dev/null")
    return "Status: active" in out or "активен" in out


def persist_iptables(runner):
    """Сохранить правила iptables, иначе они исчезнут после перезагрузки."""
    runner("echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' "
           "| debconf-set-selections; "
           "echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' "
           "| debconf-set-selections; "
           "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent "
           ">/dev/null 2>&1")
    out, rc = runner("netfilter-persistent save >/dev/null 2>&1")
    if rc != 0:
        # без пакета — сохраняем дамп руками, восстановление на старте сети
        out, rc = runner("mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4")
    if rc == 0:
        ok("Правила iptables сохранены (переживут перезагрузку)")
    else:
        warn("Не удалось сохранить правила iptables — после ребута их не будет.\n"
             "     Проверь вручную: netfilter-persistent save")
    return rc == 0


def firewall_setup(cred=None, extra_tcp=(), extra_udp=()):
    """ufw с политикой deny incoming: SSH, 80/443 и явно перечисленные порты.

    Порт sshd открывается ПЕРВЫМ и только потом включается политика, иначе
    установка обрывает сама себя вместе с SSH-сессией.
    """
    runner = (lambda c: run_remote(cred, c)) if cred else run
    if runner("which ufw")[1] != 0:
        pkg_install("ufw", cred)
    if runner("which ufw")[1] != 0:
        warn("ufw не установился — базовый файрвол не настроен")
        return False
    sshp = detect_ssh_port(runner)
    runner("ufw allow %s/tcp >/dev/null 2>&1" % sshp)
    for p in (80, 443) + tuple(extra_tcp):
        runner("ufw allow %s/tcp >/dev/null 2>&1" % p)
    for p in tuple(extra_udp):
        runner("ufw allow %s/udp >/dev/null 2>&1" % p)
    runner("ufw default deny incoming >/dev/null 2>&1")
    runner("ufw default allow outgoing >/dev/null 2>&1")
    runner("ufw --force enable >/dev/null 2>&1")
    if ufw_active(runner):
        ok("Файрвол: deny incoming, открыты SSH %s, 80, 443%s"
           % (sshp, (", " + ", ".join(str(p) for p in
                                      tuple(extra_tcp) + tuple(extra_udp)))
              if (extra_tcp or extra_udp) else ""))
        return True
    warn("ufw не включился — правила не применены")
    return False


def restrict_node_port_2222(panel_ip, cred=None):
    """Порт ноды 2222 доступен только панели.

    При активном ufw правила уходят в него (переживают перезагрузку сами),
    иначе — сырой iptables с последующим сохранением.
    """
    runner = (lambda c: run_remote(cred, c)) if cred else run
    ip = panel_ip
    if not re.match(r"^\d+\.\d+\.\d+\.\d+", ip or ""):
        out, _ = runner("getent hosts %s | head -1 | tr -s ' ' | cut -d' ' -f1" % ip)
        ip = out.strip()
    if not re.match(r"^\d+\.\d+\.\d+\.\d+", ip or ""):
        warn("Не удалось определить IP панели из '%s' — порт 2222 оставлен открытым" % panel_ip)
        return
    if ufw_active(runner):
        runner("ufw allow from %s to any port 2222 proto tcp >/dev/null 2>&1" % ip)
        runner("ufw allow from 172.16.0.0/12 to any port 2222 proto tcp >/dev/null 2>&1")
        runner("ufw deny 2222/tcp >/dev/null 2>&1")
        ok("Порт 2222 ограничен через ufw: панель %s" % ip)
        return
    # Идемпотентно: -C проверяет наличие правила, добавляем только если нет,
    # иначе повторные запуски скрипта плодят дубликаты в INPUT.
    def _rule(spec, where="-I"):
        runner("iptables -C INPUT %s 2>/dev/null || iptables %s INPUT %s"
               % (spec, where, spec))
    _rule("-p tcp --dport 2222 -s %s -j ACCEPT" % ip)
    _rule("-p tcp --dport 2222 -s 127.0.0.1 -j ACCEPT")
    _rule("-p tcp --dport 2222 -s 172.16.0.0/12 -j ACCEPT")
    _rule("-p tcp --dport 2222 -j DROP", where="-A")
    ok("Порт 2222 ограничен: панель %s" % ip)
    persist_iptables(runner)


def node_wait_ready(cred=None):
    """Дождаться 'XRay Core' в логах remnanode (нода запустилась)."""
    runner = (lambda c: run_remote(cred, c)) if cred else run
    say("  Ожидание запуска ноды...")
    for _ in range(24):
        out, _ = runner("docker logs remnanode --tail=15 2>&1")
        if "XRay Core" in out or "is up and running" in out:
            ok("Нода запущена!"); return True
        nap(5)
    warn("Нода не отрапортовала о запуске — проверь: docker logs remnanode")
    return False


def create_remnawave_host(token, prof_uuid, inbound_tag, cdn_domain, origin,
                          path, reality):
    """Создать CDN-хост и привязать к профилю/инбаунду.

    Имя поля xhttp-extra зависит от версии панели: 2.7.x -> xHttpExtraParams,
    2.8+ -> xhttpExtraParams. Ставим ОБА — панель молча игнорит лишнее.
    """
    if not prof_uuid:
        warn("нет profile_uuid — хост CDN не создан"); return None
    host = {
        "profileUuid": prof_uuid,
        "inboundTag": inbound_tag,
        "remark": "CDN %s" % cdn_domain,
        "address": cdn_domain,
        "port": 443,
        "sni": origin,
        "host": origin,
        "path": path,
        "xhttpExtraParams": {"mode": "packet-up"},
        "xHttpExtraParams": {"mode": "packet-up"},
        "securityLayer": "TLS",
    }
    resp, code = rw_api_local(token, "POST", "hosts", host)
    huuid = (resp.get("response", {}) or {}).get("uuid") if resp else None
    if huuid:
        ok("Host UUID: %s — привязан к ноде" % huuid)
    else:
        warn("Ответ создания хоста: %s" % json.dumps(resp)[:160])
    return huuid


def find_default_squad(token):
    """UUID сквада Default-Squad, иначе первый попавшийся."""
    resp, _ = rw_api_local(token, "GET", "internal-squads")
    squads = (resp.get("response", {}) or {}).get("internalSquads", []) if resp else []
    if not squads:
        return None
    for s in squads:
        if s.get("name") == "Default-Squad":
            return s.get("uuid")
    return squads[0].get("uuid")


def add_inbounds_to_squad(token, tags):
    """Добавить инбаунды в Default-Squad (иначе нода получает пустой список клиентов)."""
    squad = find_default_squad(token)
    if not squad:
        warn("Default-Squad не найден"); return
    resp, code = rw_api_local(token, "PATCH", "internal-squads/%s" % squad,
                              {"inbounds": tags})
    if code in (200, 201):
        ok("%d инбаунд(ов) добавлено в Default-Squad" % len(tags))
    else:
        warn("Не удалось добавить инбаунды в сквад: %s" % json.dumps(resp)[:160])


def create_remnawave_user(token, username, vless_uuid, domain):
    """Создать юзера user1 и вернуть URL подписки."""
    squad = find_default_squad(token)
    body = {
        "username": username,
        "vlessUuid": vless_uuid,
        "trafficLimitBytes": 0,
        "expireAt": "2099-12-31T23:59:59.000Z",
        "activeInternalSquads": [squad] if squad else [],
    }
    resp, code = rw_api_local(token, "POST", "users", body)
    r = resp.get("response", {}) if resp else {}
    short = r.get("shortUuid", "")
    if r.get("uuid"):
        ok("User UUID: %s  Short: %s" % (r.get("uuid"), short))
    else:
        warn("Ответ создания юзера: %s" % json.dumps(resp)[:160])
    return "https://%s/api/sub/%s" % (domain, short) if short else ""


# ─────────────────────────────────────────────────────────────────────────────
#  Let's Encrypt (certbot webroot / acme.sh)
# ─────────────────────────────────────────────────────────────────────────────

def issue_le_cert(domain, crt=CDN_CRT, key=CDN_KEY, cred=None):
    """Выпустить LE через certbot webroot, скопировать в cdn.crt/cdn.key.

    Requires nginx с location /.well-known/acme-challenge/ -> /var/www/certbot.
    Возвращает True при успехе.
    """
    runner = (lambda c, **k: run_remote(cred, c, **k)) if cred else run
    pkg_install("certbot", cred)
    runner("mkdir -p /var/www/certbot")
    # дождаться, пока DNS домена укажет на этот сервер
    myip = get_ip(cred)
    for _ in range(12):
        out, _ = runner("getent hosts %s | head -1 | tr -s ' ' | cut -d' ' -f1" % domain)
        if out.strip() == myip:
            break
        say("  жду DNS %s -> %s ..." % (domain, myip))
        nap(10)
    for attempt in range(3):
        out, rc = runner("certbot certonly --webroot -w /var/www/certbot -d %s "
                         "--non-interactive --agree-tos "
                         "--register-unsafely-without-email" % domain, timeout=180)
        live = "/etc/letsencrypt/live/%s" % domain
        _, ok_rc = runner("test -f %s/fullchain.pem" % live)
        if ok_rc == 0:
            runner("cp %s/fullchain.pem %s && cp %s/privkey.pem %s && "
                   "nginx -s reload 2>/dev/null; docker restart remnanode 2>/dev/null || true"
                   % (live, crt, live, key))
            # deploy-hook на автопродление
            hook = ("#!/bin/bash\ncp %s/fullchain.pem %s\ncp %s/privkey.pem %s\n"
                    "nginx -s reload\ndocker restart remnanode 2>/dev/null || true\n"
                    % (live, crt, live, key))
            runner("mkdir -p /etc/letsencrypt/renewal-hooks/deploy && "
                   "printf '%%b' '%s' > /etc/letsencrypt/renewal-hooks/deploy/cert.sh && "
                   "chmod +x /etc/letsencrypt/renewal-hooks/deploy/cert.sh"
                   % hook.replace("'", "'\\''"))
            ok("Сертификат LE получен для %s" % domain)
            return True
        say("  certbot не прошёл (попытка %d/3), повтор через 20с..." % (attempt + 1))
        nap(20)
    warn("сертификат для %s не выпущен — self-signed" % domain)
    return False


def upgrade_origin_cert(origin_domain, cred=None, skip=False):
    """Заменить self-signed на Let's Encrypt для origin, если получится.

    Self-signed CDN не может проверить — у провайдера приходится включать
    «игнорировать сертификат origin», то есть канал шифруется, но origin не
    аутентифицируется. С настоящим LE этого костыля не нужно. Вызывать ПОСЛЕ
    старта nginx: certbot ходит через /.well-known/acme-challenge/.
    При неудаче остаётся self-signed — установка не прерывается.
    """
    if skip:
        return False
    runner = (lambda c: run_remote(cred, c)) if cred else run
    say("  Пробую выпустить Let's Encrypt для origin %s..." % origin_domain)
    if issue_le_cert(origin_domain, cred=cred):
        runner("chmod 600 %s" % shq(CDN_KEY))
        return True
    say("  Остаётся self-signed — у CDN-провайдера включи "
        "«игнорировать сертификат origin»")
    return False


def nginx_panel_proxy(domain, upstream_port, crt=CDN_CRT, key=CDN_KEY,
                      extra_locations=""):
    """nginx-конфиг для проксирования панели (80->443 redirect + proxy)."""
    return """server {
    listen 80;
    server_name %s;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
%s}
""" % (domain, domain, crt, key, upstream_port, extra_locations)


# ─────────────────────────────────────────────────────────────────────────────
#  3x-ui (панель со встроенным xray)
# ─────────────────────────────────────────────────────────────────────────────

def install_3xui_panel(admin_pw, port, base_path):
    """Скачать и поставить 3x-ui неинтерактивно, задать admin/port/path."""
    _, rc = run("test -f /usr/local/x-ui/x-ui && test -f /etc/x-ui/x-ui.db && echo ok")
    if rc == 0:
        ok("3x-ui уже установлен и работает — пропускаю переустановку")
    else:
        say("  Скачивание установщика 3x-ui...")
        run("curl -fsSL --max-time 60 "
            "https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh "
            "-o /tmp/3xui_install.sh || curl -fsSL --max-time 60 "
            "https://gh-proxy.com/https://raw.githubusercontent.com/mhsanaei/3x-ui/"
            "master/install.sh -o /tmp/3xui_install.sh", timeout=120)
        _, rc = run("test -s /tmp/3xui_install.sh")
        if rc != 0:
            err("Не удалось скачать установщик 3x-ui! Проверь интернет.")
            sys.exit(1)
        say("  Запуск установщика 3x-ui (может занять несколько минут)...")
        run("XUI_NONINTERACTIVE=1 XUI_DB_TYPE=sqlite XUI_USERNAME=admin "
            "XUI_PASSWORD=%s XUI_PORT=%d XUI_WEB_BASE_PATH=%s bash /tmp/3xui_install.sh %s"
            % (admin_pw, port, base_path, XUI_VERSION), timeout=900)
    _, rc = run("test -f /etc/x-ui/x-ui.db && echo OK")
    if rc != 0:
        err("3x-ui не установился корректно — нет /etc/x-ui/x-ui.db")
        say("  Обычно это таймаут скачивания. Просто ЗАПУСТИ СКРИПТ СНОВА.")
        sys.exit(1)
    run("/usr/local/x-ui/x-ui setting -username admin -password %s -port %d "
        "-webBasePath %s" % (admin_pw, port, base_path))
    run("systemctl restart x-ui")
    ok("3x-ui установлен: порт=%d, путь=/%s" % (port, base_path.strip("/")))


def xui_sql(sql):
    """Выполнить SQL в /etc/x-ui/x-ui.db через sqlite3."""
    pkg_install("sqlite3") if run("which sqlite3")[1] != 0 else None
    write_file("/tmp/_xui.sql", sql, mode=0o600)   # в SQL едут uuid и пароли
    out, rc = run("sqlite3 /etc/x-ui/x-ui.db < /tmp/_xui.sql 2>&1")
    run("rm -f /tmp/_xui.sql")
    if rc != 0:
        warn("SQL ошибка: %s" % out[:160])
    return rc == 0


def xui_cdn_inbound(tag, port, path, origin, uuid, sub_id):
    """Создать CDN xhttp inbound в 3x-ui напрямую в SQLite."""
    stream = build_xhttp_inbound(port, path, tag, uuid, origin)["streamSettings"]
    settings = {"clients": [{"id": uuid, "email": "user1", "flow": "",
                             "subId": sub_id}], "decryption": "none", "fallbacks": []}
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"]}
    ts = int(time.time() * 1000)
    sql = (
        "DELETE FROM client_inbounds WHERE client_id IN "
        "(SELECT id FROM clients WHERE email='user1');\n"
        "DELETE FROM client_traffics WHERE email='user1';\n"
        "DELETE FROM clients WHERE email='user1';\n"
        "DELETE FROM inbounds WHERE tag='%s';\n"
        "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, "
        "listen, port, protocol, settings, stream_settings, tag, sniffing) "
        "VALUES (1,0,0,0,'%s-CDN',1,0,'127.0.0.1',%d,'vless','%s','%s','%s','%s');\n"
        "INSERT INTO clients (email, sub_id, uuid, flow, limit_ip, total_gb, "
        "expiry_time, enable, created_at) VALUES ('user1','%s','%s','',0,0,0,1,%d);\n"
        "INSERT INTO client_traffics (inbound_id, enable, email, up, down, "
        "expiry_time, total, reset) VALUES ((SELECT id FROM inbounds WHERE tag='%s'),"
        "1,'user1',0,0,0,0,0);\n"
        % (tag, tag, port,
           json.dumps(settings).replace("'", "''"),
           json.dumps(stream).replace("'", "''"),
           tag, json.dumps(sniff).replace("'", "''"),
           sub_id, uuid, ts, tag)
    )
    if xui_sql(sql):
        run("systemctl restart x-ui")
        ok("Inbound создан через SQLite: %s-CDN" % tag)
        return True
    return False


def install_3xui(cfg):
    """Install 3x-ui + CDN inbound (mode 1, panel=2). Single server."""
    step("Установка 3x-ui")
    domain = cfg["domain"]; origin = cfg.get("origin_domain", domain)
    path = cfg["path"]; admin_pw = cfg["admin_pass"]
    panel_port = random.randint(20000, 40000)
    panel_path = rand(10, "abcdefghijklmnopqrstuvwxyz0123456789")

    ensure_nginx_base()
    install_3xui_panel(admin_pw, panel_port, panel_path)
    setup_xray_ru_geo()

    # LE или self-signed для панели
    nginx_write_conf("panel.conf", nginx_panel_proxy(domain, panel_port))
    if not issue_le_cert(domain):
        self_signed_cert(domain)
    nginx_write_conf("panel.conf", nginx_panel_proxy(domain, panel_port))

    # CDN xhttp inbound
    step("Создание %s CDN inbound" % cfg["cdn"])
    uuid = str(_uuid.uuid4()); sub_id = rand(16)
    xport = random.randint(10000, 20000)
    xui_cdn_inbound(cfg["cdn"], xport, path, origin, uuid, sub_id)

    reality = None
    if not cfg.get("no_grpc"):
        reality = xui_grpc_inbound(uuid)

    firewall_setup(extra_tcp=([] if cfg.get("no_grpc") else [2053]),
                   extra_udp=([] if cfg.get("no_hy2") else [8443]))

    return {"user_uuid": uuid, "sub_id": sub_id, "xport": xport,
            "panel_port": panel_port, "panel_path": panel_path,
            "reality": reality, "domain": domain}


def xui_grpc_inbound(uuid):
    """VLESS Reality gRPC inbound в 3x-ui (SQLite). Возвращает {pbk,sid,service} или None."""
    priv, pub = gen_x25519()
    if not priv:
        say("  ПРОПУСК: не удалось сгенерировать x25519 ключи")
        return None
    step("Установка VLESS Reality gRPC")
    port = random.randint(30000, 40000)
    sid = rand(8, "0123456789abcdef"); service = _slug("grpc")
    stream = build_grpc_inbound(port, uuid, priv, pub, sid, service)["streamSettings"]
    settings = {"clients": [{"id": uuid, "email": "user1", "flow": ""}],
                "decryption": "none"}
    sniff = {"enabled": True, "destOverride": ["http", "tls"]}
    sql = (
        "DELETE FROM inbounds WHERE tag='grpc-reality';\n"
        "INSERT INTO inbounds (user_id, up, down, total, remark, enable, expiry_time, "
        "listen, port, protocol, settings, stream_settings, tag, sniffing) "
        "VALUES (1,0,0,0,'gRPC Reality',1,0,'',%d,'vless','%s','%s','grpc-reality','%s');\n"
        "INSERT INTO client_traffics (inbound_id, enable, email, up, down, expiry_time, "
        "total, reset) VALUES ((SELECT id FROM inbounds WHERE tag='grpc-reality'),"
        "1,'user1',0,0,0,0,0);\n"
        % (port, json.dumps(settings).replace("'", "''"),
           json.dumps(stream).replace("'", "''"),
           json.dumps(sniff).replace("'", "''"))
    )
    if xui_sql(sql):
        run("systemctl restart x-ui")
        ok("gRPC Reality inbound создан на TCP порту %d" % port)
        return {"pbk": pub, "sid": sid, "service": service, "port": port}
    return None


# ─────────────────────────────────────────────────────────────────────────────
#  Инструкции по настройке CDN (ручной шаг у провайдера)
# ─────────────────────────────────────────────────────────────────────────────

def print_cdn_instructions(provider, origin, my_ip):
    """Печать инструкции по созданию CDN-ресурса. provider: vk|yandex|beeline|timeweb."""
    print("", flush=True)
    print("  " + _c("1;" + C_TITLE, "Настройка CDN у провайдера")
          + _c(C_DIM, " · %s" % provider), flush=True)
    hr()
    if provider == "vk":
        say("""
  DNS в Cloudflare:
    A     %s        ->  %s   (DNS only, серое облако)
    CNAME %s (cdn) ->  [VK CDN CNAME после создания] (DNS only)

  VK Cloud CDN:
    - Протокол к источнику: HTTP (порт 80)
    - Источник: %s
    - Заголовок Host: Пересылать
    - SSL: Let's Encrypt
    - Кеширование: ВЫКЛ (все 4 переключателя)
    - HTTP методы: GET, HEAD, OPTIONS
    - Gzip: ВЫКЛ
""" % (origin, my_ip, origin, origin))
    elif provider == "yandex":
        say("""
  Yandex Certificate Manager -> создать сертификат (тип проверки DNS),
  создать CNAME _acme-challenge.%s, дождаться статуса "Issued".

  Yandex Cloud CDN -> создать ресурс:
    - Источник: %s (HTTPS, SNI вручную = %s, Host = своё значение = %s)
    - Кеширование: ВЫКЛ, Сжатие: ВЫКЛ
    - Query string: НЕ игнорировать (sessionID и seq идут в query!)
    - Проверка сертификата источника: ВЫКЛ
""" % (origin, origin, origin, origin))
    elif provider == "beeline":
        say("""
  CDNvideo (panel.cdnvideo.ru):
    - Адрес (Origin): %s:443
    - HTTPS к источнику: ВКЛ, SNI-хост: %s, Host: передавать исходный
    - Кеширование 2xx/3xx/4xx/5xx/browser: НЕ кешировать
    - Кешировать с учётом query string: ВКЛ + "Учитывать все параметры"
      !!! sessionID и seq идут в query — иначе туннель не поднимется
    - Rewrite (экспертные): /static/getFile/video/segment.ts/ -> без слеша
    - HTTP2 ВКЛ, HTTP3 ВЫКЛ, Brotli/Gzip ВЫКЛ
  CDN-домен (xxx.a.trbcdn.net) выдаст сам CDNvideo.
""" % (origin, origin))
    elif provider == "timeweb":
        say("""
  Timeweb (timeweb.cloud) -> CDN -> Создать ресурс:
    - Источник: вкладка "IP-адрес", IP: %s, HTTPS: НЕ включать
    - Кеширование CDN/браузер: ВЫКЛ, Всегда онлайн: ВЫКЛ
    - Игнорировать параметры запроса: ВЫКЛ (sessionID/seq в query!)
    - HTTP/3: ВЫКЛ, Gzip: ВЫКЛ
  Технический домен xxx.cdn.twcstorage.ru создаётся автоматически.
""" % my_ip)


def dns_wait(lines, skip=False):
    """Показать нужные DNS-записи и подождать ENTER (если не skip)."""
    callout("DNS-записи в Cloudflare", lines)
    if not skip:
        try:
            input("\n  " + _c(C_ACC, "❯") + " Enter когда записи созданы"
                  + _c(C_DIM, "  "))
        except (EOFError, KeyboardInterrupt):
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  Режим 2: панель здесь + нода на удалённом сервере (по SSH)
# ─────────────────────────────────────────────────────────────────────────────

def setup_remote_node(cred, secret, panel_ip, origin, cdn, path, xport,
                      no_origin_le=False):
    """Install Docker + nginx CDN origin + remnanode на удалённом сервере via SSH."""
    say("  [удалённая] Подключение к %s..." % cred["ip"])
    if not cred.get("key") and not ensure_sshpass():
        return False
    out, rc = run_remote(cred, "echo OK")
    if "OK" not in out:
        err("Не могу подключиться по SSH к %s" % cred["ip"])
        if out.strip():
            say("  " + out.strip().splitlines()[-1][:200])
        return False
    say("  [удалённая] SSH OK, установка пакетов...")
    pkg_install("nginx openssl curl ca-certificates gnupg", cred)
    firewall_setup(cred, extra_tcp=[2053], extra_udp=[8443])
    say("  [удалённая] Установка Docker...")
    if not install_docker(cred) or not ensure_compose(cred):
        err("[удалённая] Docker не установился на %s" % cred["ip"]); return False
    tune_os(cred)
    ensure_nginx_base(cred)
    self_signed_cert("cdn-origin", cred)
    write_decoy(origin, cred)
    # nginx CDN origin
    conf = nginx_cdn_origin_config(xport, path, "prefix")
    write_remote(cred, "/etc/nginx/sites-available/default", conf)
    run_remote(cred, "rm -f /etc/nginx/sites-enabled/default && "
               "ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && "
               "nginx -t && systemctl restart nginx")
    upgrade_origin_cert(origin, cred, skip=no_origin_le)
    # remnanode
    say("  [удалённая] Настройка remnanode...")
    run_remote(cred, "mkdir -p /opt/remnanode")
    write_remote(cred, "/opt/remnanode/docker-compose.yml", REMNANODE_COMPOSE)
    write_remote(cred, "/opt/remnanode/.env",
                 "NODE_PORT=2222\nSECRET_KEY=%s\n" % (secret or ""), mode=0o600)
    setup_xray_ru_geo(cred=cred)
    run_remote(cred, "cd /opt/remnanode && docker compose pull", timeout=600)
    run_remote(cred, "cd /opt/remnanode && docker compose up -d")
    restrict_node_port_2222(panel_ip, cred)
    node_wait_ready(cred)
    ok("[удалённая] Нода запущена на %s" % cred["ip"])
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  Режим 3: только нода/CDN к существующей панели (Remnawave, по SSH API)
# ─────────────────────────────────────────────────────────────────────────────

def install_node_only(cfg):
    """Install node + CDN origin on THIS server, connect to existing panel via SSH."""
    step("Проверка подключения к панели")
    panel = {"ip": cfg["panel_url"], "user": cfg.get("panel_ssh_user", "root"),
             "pass": cfg.get("panel_ssh_pass", ""), "key": cfg.get("panel_key")}
    # sshpass нужен ДО первого run_remote — на чистой ноде его ещё нет
    if not panel["key"] and not ensure_sshpass():
        sys.exit(1)
    out, rc = run_remote(panel, "echo ok")
    if "ok" not in out:
        err("SSH к панели %s не удался" % panel["ip"])
        if out.strip():
            say("  " + out.strip().splitlines()[-1][:200])
        sys.exit(1)
    ok("SSH к панели: OK")
    # проверить, что Remnawave API отвечает локально на панели
    out, _ = run_remote(panel, "curl -s http://127.0.0.1:3001/health || "
                        "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api")
    token = resolve_panel_token(panel, cfg)
    if not token:
        sys.exit(1)
    api = lambda m, p, d=None: rw_api_ssh(panel, token, m, p, d)

    step("Подготовка системы")
    check_ubuntu()
    pkg_install("nginx openssl curl sqlite3 ca-certificates gnupg sshpass certbot")
    tune_os()
    ensure_nginx_base()
    self_signed_cert(cfg.get("origin_domain", cfg["domain"]))
    write_decoy(cfg.get("origin_domain", cfg["domain"]))
    install_docker(); ensure_compose()

    # создать профиль/инбаунд/ноду через API панели, поднять remnanode здесь
    step("Создание профиля через API панели")
    user_uuid = str(_uuid.uuid4())
    origin = cfg.get("origin_domain", cfg["domain"]); path = cfg["path"]
    xport = random.randint(10000, 20000)
    inbounds = [build_xhttp_inbound(xport, path, "%s-CDN" % cfg["cdn"], user_uuid, origin)]
    prof, code = api("POST", "config-profiles",
                     {"name": _slug("cdn"), "inbounds": inbounds})
    prof_uuid = (prof.get("response", {}) or {}).get("uuid") if prof else None

    my_ip = get_ip()
    node, code = api("POST", "nodes",
                     {"name": "cdn-%s" % my_ip, "address": my_ip, "port": 2222,
                      "configProfile": {"activeConfigProfileUuid": prof_uuid,
                                        "activeInbounds": [i["tag"] for i in inbounds]}})
    secret = (node.get("response", {}) or {}).get("secretKey") if node else None
    os.makedirs("/opt/remnanode", exist_ok=True)
    download_xray_binary("/opt/remnanode/xray-custom")
    write_file("/opt/remnanode/docker-compose.yml", REMNANODE_COMPOSE)
    write_file("/opt/remnanode/.env", "NODE_PORT=2222\nSECRET_KEY=%s\n" % (secret or ""),
               mode=0o600)
    setup_xray_ru_geo()
    if cfg.get("skip_cdn"):
        say("  Пропуск nginx CDN-origin (режим «только нода»)")
    else:
        conf = nginx_cdn_origin_config(xport, path, "prefix")
        write_file("/etc/nginx/sites-available/default", conf)
        run("rm -f /etc/nginx/sites-enabled/default && "
            "ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && "
            "nginx -t && systemctl restart nginx")
        upgrade_origin_cert(origin, skip=cfg.get("no_origin_le"))
    firewall_setup(extra_tcp=[2053], extra_udp=[8443])
    run("cd /opt/remnanode && docker compose pull", timeout=600)
    run("cd /opt/remnanode && docker compose up -d")
    node_wait_ready()
    ok("Нода подключена к панели %s" % panel["ip"])
    return {"user_uuid": user_uuid, "prof_uuid": prof_uuid, "my_ip": my_ip}


# ─────────────────────────────────────────────────────────────────────────────
#  Каскад (relay в РФ -> exit за рубежом). Самый сложный сценарий.
#  Схема: BRIDGE_IN :8888, exit 3x-ui с Reality :443; API-оркестрация — как выше.
# ─────────────────────────────────────────────────────────────────────────────

def cascade_direction_ok(exit_ip):
    """Warn if cascade wrong: этот сервер должен быть РФ, exit — зарубежный."""
    say("  Проверяю направление каскада...")
    here = get_country()
    there = get_country(exit_ip)
    if here and there and here == there:
        warn("Оба сервера в одной стране (%s). Каскад бессмысленен." % here)
        return False
    if here and here != "RU" and there == "RU":
        err("КАСКАД НАСТРОЕН НАОБОРОТ! Трафик выйдет с РФ IP.")
        say("  ПРАВИЛЬНО: запусти скрипт на РОССИЙСКОМ сервере, %s укажи как exit."
            % exit_ip)
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
#  Отдельные компоненты: только панель / только нода / только CDN
# ─────────────────────────────────────────────────────────────────────────────

def install_panel_only(cfg):
    """Режим 4: только панель — без локальной ноды и без CDN-origin.

    Remnawave: docker-панель + регистрация админа + API-токен.
    3x-ui:     панель + nginx-прокси + LE/self-signed.
    Ноды подключаются потом отдельным запуском (режим «только нода»)."""
    domain = cfg["domain"]
    admin_pw = cfg["admin_pass"]
    if cfg.get("panel") == "2":
        step("Установка панели 3x-ui (без CDN inbound)")
        panel_port = random.randint(20000, 40000)
        panel_path = rand(10, "abcdefghijklmnopqrstuvwxyz0123456789")
        ensure_nginx_base()
        install_3xui_panel(admin_pw, panel_port, panel_path)
        setup_xray_ru_geo()
        nginx_write_conf("panel.conf", nginx_panel_proxy(domain, panel_port))
        if not issue_le_cert(domain):
            self_signed_cert(domain)
        nginx_write_conf("panel.conf", nginx_panel_proxy(domain, panel_port))
        firewall_setup()
        ok("Панель 3x-ui готова — подключай ноды в веб-интерфейсе")
        return {"panel_only": True, "panel_port": panel_port,
                "panel_path": panel_path}
    # Remnawave
    token = remnawave_bringup(cfg)
    firewall_setup()
    ok("Панель Remnawave готова — подключай ноды (режим «только нода»)")
    return {"panel_only": True, "token": token}


def install_cdn_only(cfg):
    """Режим 6: только nginx CDN-origin перед уже работающей нодой на ЭТОМ сервере.

    Не трогает панель и docker-ноду — ставит только nginx-фронт (self-signed серт
    + decoy) на upstream 127.0.0.1:<xport> с путём <path> и печатает инструкцию
    провайдеру."""
    origin = cfg.get("origin_domain", cfg["domain"])
    xport = cfg["xport"]
    path = cfg["path"]
    my_ip = get_ip() or "<SERVER_IP>"
    step("Установка nginx CDN-origin (только CDN)")
    say("  Upstream: 127.0.0.1:%d   path: %s" % (xport, path))
    ensure_nginx_base()
    self_signed_cert(origin)
    write_decoy(origin)
    conf = nginx_cdn_origin_config(xport, path, "prefix")
    write_file("/etc/nginx/sites-available/default", conf)
    run("rm -f /etc/nginx/sites-enabled/default && "
        "ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default && "
        "nginx -t && systemctl restart nginx")
    upgrade_origin_cert(origin, skip=cfg.get("no_origin_le"))
    firewall_setup()
    ok("nginx CDN-origin поднят на :443 -> 127.0.0.1:%d" % xport)
    return {"cdn_only": True, "my_ip": my_ip}


# ─────────────────────────────────────────────────────────────────────────────
#  Аргументы и главный сценарий
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse CLI args for non-interactive mode."""
    p = argparse.ArgumentParser(description="VPN CDN Installer v%s" % INSTALLER_VERSION)
    p.add_argument("--mode", help="1=Panel+node here, 2=Panel here+node remote, "
                   "3=Node+CDN to existing panel, 4=Panel only, 5=Node only, 6=CDN only")
    p.add_argument("--panel", help="1=Remnawave, 2=3x-ui (modes 1,2,4)")
    p.add_argument("--cdn", help="CDN provider: 1=VK 2=Yandex 3=Beeline 4=Timeweb")
    p.add_argument("--domain", help="Domain name")
    p.add_argument("--path", help="Existing xhttp path (mode 6 CDN-only), e.g. /abc123")
    p.add_argument("--xport", type=int,
                   help="Existing local xray upstream port on 127.0.0.1 (mode 6 CDN-only)")
    p.add_argument("--node-ip", help="Remote node IP (mode 2)")
    p.add_argument("--node-user", default="root", help="SSH user for remote node")
    p.add_argument("--node-pass", help="Remote node password (mode 2)")
    p.add_argument("--node-key", help="Path to SSH private key for remote node")
    p.add_argument("--panel-url", help="Panel IP (mode 3)")
    p.add_argument("--panel-token", help="Remnawave API token (modes 3,5). "
                   "Если не задан — берётся /opt/remnawave/.panel_token с панели, "
                   "иначе логин по --panel-user/--panel-pass")
    p.add_argument("--panel-user", help="Panel Remnawave username (mode 3)")
    p.add_argument("--panel-pass", help="Panel Remnawave password (mode 3)")
    p.add_argument("--panel-ssh-user", default="root", help="Panel SSH user (mode 3)")
    p.add_argument("--panel-ssh-pass", help="Panel SSH password (mode 3)")
    p.add_argument("--no-hy2", action="store_true", help="Skip Hysteria2")
    p.add_argument("--no-grpc", action="store_true", help="Skip gRPC")
    p.add_argument("--no-origin-le", action="store_true",
                   help="Do not try Let's Encrypt for the CDN origin (keep self-signed)")
    p.add_argument("--squad", help="Squad number or name (mode 3 Remnawave)")
    p.add_argument("--wipe", action="store_true",
                   help="Снести прошлую установку без вопросов (для автозапуска)")
    p.add_argument("--no-wipe", action="store_true",
                   help="Не трогать прошлую установку (ставить поверх)")
    p.add_argument("--skip-dns-wait", action="store_true")
    p.add_argument("--skip-cdn-wait", action="store_true")
    p.add_argument("--cascade", action="store_true", help="Enable cascade relay")
    p.add_argument("--cascade-ip", help="Cascade relay server IP")
    p.add_argument("--cascade-user", default="root", help="Cascade relay SSH user")
    p.add_argument("--cascade-pass", help="Cascade relay SSH password")
    p.add_argument("--key", help="License key (опционально)")
    return p.parse_args()


def flush_stdin():
    """Выбросить всё, что настучалось в терминал, пока шёл долгий шаг.

    Иначе нажатия во время docker pull попадают в следующий вопрос: домен
    приезжает с мусором в начале, а битый байт роняет input() с
    UnicodeDecodeError.
    """
    if not sys.stdin.isatty():
        return
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def ask(prompt, default=None):
    tail = _c(C_DIM, " [%s]" % default) if default else ""
    line = "  " + _c(C_ACC, "❯") + " " + prompt + tail + _c(C_DIM, "  ")
    while True:
        flush_stdin()
        try:
            v = input(line).strip()
        except (EOFError, KeyboardInterrupt):
            v = ""
        except UnicodeDecodeError:
            warn("Ввод не похож на UTF-8 (обрывок прошлого нажатия) — повтори")
            continue
        return v or (default or "")


def ask_required(prompt, why):
    """Спросить и не пускать дальше с пустым значением."""
    while True:
        v = ask(prompt)
        if v:
            return v
        warn("Пустое значение — %s" % why)


def ask_secret(prompt):
    """Пароль без эха в терминале."""
    line = "  " + _c(C_ACC, "❯") + " " + prompt + _c(C_DIM, "  ")
    try:
        return getpass.getpass(line).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def ssh_host(value):
    """https://panel.example.com/xyz -> panel.example.com (SSH нужен хост, не URL)."""
    v = (value or "").strip()
    v = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", v)
    v = v.split("/")[0].split("?")[0]
    if "@" in v:
        v = v.rsplit("@", 1)[1]
    return v.split(":")[0] if v.count(":") == 1 else v


def choose(prompt, options):
    print("", flush=True)
    print("  " + _c("1;" + C_TITLE, prompt), flush=True)
    hr()
    for i, o in enumerate(options, 1):
        print("   " + _c(C_ACC, "%2d" % i) + _c(C_DIM, " │ ") + o, flush=True)
    hr()
    while True:
        v = ask("Выбор")
        if v.isdigit() and 1 <= int(v) <= len(options):
            return int(v)


CDN_NAMES = {1: "vk", 2: "yandex", 3: "beeline", 4: "timeweb"}
CDN_LABELS = {1: "VK Cloud", 2: "Yandex Cloud", 3: "Beeline (CDNvideo)",
              4: "Timeweb"}


def main():
    args = parse_args()
    banner()

    if os.geteuid() != 0:
        err("Нужны права root — запусти через sudo")
        sys.exit(1)
    check_ubuntu()

    my_ip = get_ip() or "<SERVER_IP>"
    say("   " + _c(C_DIM, "◦ Server IP: ") + _c(C_VAL, my_ip))

    # ── режим ──
    mode = args.mode or str(choose("Режим установки?", [
        "Панель + нода (всё на этом сервере)",
        "Панель здесь + нода на другом сервере",
        "Нода + CDN к существующей панели",
        "Только панель (ноды подключишь потом)",
        "Только нода (к существующей панели, без CDN)",
        "Только CDN-origin (перед уже работающей нодой)"]))

    # какие шаги нужны этому режиму
    need_panel = mode in ("1", "2", "4")           # спросить тип панели
    need_cdn   = mode in ("1", "2", "3", "5", "6") # нужен CDN-провайдер (тег/инструкция)
    cdn_origin = mode in ("1", "2", "3", "6")      # ставит nginx CDN-origin + инструкция

    # ── панель ──
    if need_panel:
        panel = args.panel or str(choose("Панель (Panel)?", ["Remnawave 3.x",
                                  "3x-ui"]))
    else:
        panel = "1"

    # ── CDN ──
    if need_cdn:
        cdn_n = int(args.cdn) if args.cdn else choose("CDN провайдер?", [
            "VK Cloud", "Yandex Cloud", "Beeline (CDNvideo)", "Timeweb"])
        cdn_name = CDN_NAMES[cdn_n]
    else:
        cdn_name = ""

    domain = (args.domain or ask("Домен без http:// (Domain)") or "").strip()
    if not domain:
        err("Домен обязателен"); sys.exit(1)
    if not RE_DOMAIN.match(domain):
        err("Домен '%s' не похож на домен (ожидается вид example.com)" % domain)
        hint = homoglyph_hint(domain)
        if hint:
            say("  " + hint)
        sys.exit(1)
    origin = "origin." + domain

    # путь/upstream-порт: режим 6 (только CDN) берёт СУЩЕСТВУЮЩИЕ, остальные — новые
    if mode == "6":
        path = (args.path or ask("Существующий xhttp путь (например /abc123)") or "").strip()
        if not RE_XPATH.match(path):
            err("Путь '%s' невалиден: ожидается вид /abc123 "
                "(латиница, цифры, - _ . ~ /)" % path)
            hint = homoglyph_hint(path)
            if hint:
                say("  " + hint)
            sys.exit(1)
        if args.xport:
            xport = args.xport
        else:
            xp = ask("Локальный upstream-порт xray на 127.0.0.1", default="8080")
            xport = int(xp) if str(xp).isdigit() else random.randint(10000, 20000)
        if not 0 < xport < 65536:
            err("Порт %s вне диапазона 1..65535" % xport); sys.exit(1)
    else:
        path = rand_path()
        xport = random.randint(10000, 20000)
    admin_pw = rand_password()

    cfg = {"mode": mode, "panel": panel, "cdn": cdn_name, "domain": domain,
           "origin_domain": origin, "path": path, "admin_pass": admin_pw,
           "no_hy2": args.no_hy2, "no_grpc": args.no_grpc,
           "cascade": args.cascade, "xport": xport,
           "no_origin_le": args.no_origin_le}

    # ── DNS ──
    if mode == "4":
        dns_wait(["A %s -> %s   (панель, DNS only)" % (domain, my_ip)],
                 skip=args.skip_dns_wait)
    elif cdn_origin:
        dns_wait(["A     %s        ->  %s   (DNS only)" % (origin, my_ip),
                  "CNAME %s -> [CDN CNAME после создания] (DNS only)" % domain],
                 skip=args.skip_dns_wait)
    # mode 5 (только нода) — DNS не требуется

    # ── снести прошлую установку тех компонентов, которые ставим сейчас ──
    if not args.no_wipe:
        wipe_previous(panel=(mode in ("1", "2", "4")),
                      node=(mode in ("1", "2", "3", "5")),
                      assume_yes=args.wipe)

    # ── установка ──
    result = {}
    if mode == "1" and panel == "1":
        result = install_remnawave(cfg)
    elif mode == "1" and panel == "2":
        result = install_3xui(cfg)
    elif mode == "2":
        # панель Remnawave здесь + нода на args.node-ip
        cfg2 = dict(cfg)
        result = install_remnawave(cfg2)   # панель + локальная нода как основа
        if args.node_ip:
            cred = {"ip": args.node_ip, "user": args.node_user,
                    "pass": args.node_pass, "key": args.node_key}
            setup_remote_node(cred, None, my_ip, origin, cdn_name, path, cfg["xport"],
                              no_origin_le=cfg.get("no_origin_le"))
    elif mode in ("3", "5"):
        cfg["panel_url"] = ssh_host(args.panel_url or ask_required(
            "IP/URL панели Remnawave", "без адреса панели подключиться некуда"))
        cfg["panel_ssh_user"] = args.panel_ssh_user
        cfg["panel_key"] = args.node_key
        cfg["panel_token"] = args.panel_token
        cfg["panel_user"] = args.panel_user
        cfg["panel_pass"] = args.panel_pass
        if cfg["panel_key"]:
            cfg["panel_ssh_pass"] = args.panel_ssh_pass or ""
        else:
            cfg["panel_ssh_pass"] = args.panel_ssh_pass
            while not cfg["panel_ssh_pass"]:
                cfg["panel_ssh_pass"] = ask_secret("SSH пароль панели")
                if not cfg["panel_ssh_pass"]:
                    warn("Пустой пароль — SSH к панели не пройдёт "
                         "(или запусти с --node-key /путь/к/ключу)")
        cfg["skip_cdn"] = (mode == "5")   # «только нода» — без nginx CDN-origin
        result = install_node_only(cfg)
    elif mode == "4":
        result = install_panel_only(cfg)
    elif mode == "6":
        result = install_cdn_only(cfg)

    # ── CDN-инструкция + ожидание ──
    cdn_domain = ""
    if cdn_origin:
        print_cdn_instructions(cdn_name, origin, my_ip)
        if not args.skip_cdn_wait:
            try:
                input("\n  " + _c(C_ACC, "❯") + " Enter когда CDN настроен и серт"
                      " выпущен" + _c(C_DIM, "  "))
            except (EOFError, KeyboardInterrupt):
                pass
        cdn_domain = ask("CDN домен (например xxx.cdn.twcstorage.ru)")

    # ── финальный отчёт ──
    cdn_val = cdn_domain or "— укажи после настройки провайдера"
    if mode == "5":
        rows = [("Режим", "только нода → панель %s" % cfg.get("panel_url", "")),
                ("Origin", "%s  (A → %s)" % (origin, my_ip)),
                ("Нода", "xhttp 127.0.0.1:%d  путь %s" % (xport, path)),
                "",
                ("Дальше", "режим 6 (только CDN) перед этой нодой:"),
                ("", "--xport %d --path %s" % (xport, path))]
    elif mode == "6":
        rows = [("Режим", "только CDN-origin"),
                ("Origin", "%s  (A → %s)" % (origin, my_ip)),
                ("nginx", ":443 → 127.0.0.1:%d  путь %s" % (xport, path)),
                ("CDN", cdn_val)]
    else:
        rows = []
        if mode == "4":
            rows.append(("Режим", "только панель — ноды подключишь позже"))
        rows += [("Панель", "https://%s/" % domain),
                 ("Логин", "admin"),
                 ("Пароль", admin_pw),
                 ("Origin", "%s  (A → %s)" % (origin, my_ip))]
        if cdn_origin:
            rows.append(("CDN", cdn_val))
    if result.get("sub_url"):
        rows.append(("Подписка", result["sub_url"]))
    card("ГОТОВО · УСТАНОВКА ЗАВЕРШЕНА", rows, color=C_OK)

    if cdn_domain and result.get("user_uuid"):
        link = ("vless://%s@%s:443?type=xhttp&security=tls&sni=%s&fp=random"
                "&path=%s&host=%s&mode=packet-up&encryption=none#user1-%s"
                % (result["user_uuid"], cdn_domain, origin, path, origin, cdn_name))
        callout("VLESS CDN ссылка", [link], color=C_TITLE)
    if result.get("reality"):
        r = result["reality"]
        callout("Reality", ["PBK: %s" % r.get("pbk"),
                            "SID: %s" % r.get("sid")], color=C_TITLE)
    print("", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("", flush=True)
        warn("Установка отменена")
        sys.exit(130)
