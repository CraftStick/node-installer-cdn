#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
node-installer-cdn.py — установщик прокси-инфраструктуры за российским CDN

ЧТО ЭТО
-------
Самодостаточный установщик: разворачивает панель + ноду + CDN-обвязку и
связывает их между собой. Никуда не «звонит», кроме официальных репозиториев
(docker, xray, remnawave, letsencrypt) и ваших серверов по SSH.
Конфиги (nginx, docker-compose, systemd, sysctl, SQL) вшиты как есть.

ЧТО ДЕЛАЕТ
----------
Разворачивает XHTTP(packet-up)-прокси за российским CDN. Режимы:
  1  Панель + нода на этом сервере
  2  Нода + CDN к уже существующей панели (панель — по SSH)
  3  Только CDN перед уже работающей нодой
Панель: Remnawave 3.x. CDN: Yandex Cloud.

ЗАПУСК
------
    sudo python3 node-installer-cdn.py                 # интерактивно
    sudo python3 node-installer-cdn.py --mode 1 --cdn 1 --domain example.com

ТРЕБОВАНИЯ: Ubuntu/Debian, root. Для режима 2 — sshpass (ставится сам).

ВНИМАНИЕ: работает под root и меняет сеть/сервисы. Обкатывайте на одноразовом VPS
со снапшотом. Ответственность за использование — на запускающем.
"""

import os
import sys
import re
import hmac
import json
import time
import uuid as _uuid
import base64
import random
import string
import shlex
import getpass
import hashlib
import functools
import argparse
import subprocess
import urllib.error
import urllib.parse
import urllib.request

# Все случайные значения здесь — секреты (APP_SECRET, пароли, путь туннеля),
# поэтому источник — CSPRNG ОС, а не предсказуемый по выходу Mersenne Twister.
_rng = random.SystemRandom()

# ─────────────────────────────────────────────────────────────────────────────
#  Константы
# ─────────────────────────────────────────────────────────────────────────────

INSTALLER_VERSION = "2.0"             # версия установщика, печатается в баннере

XRAY_MIN_VERSION = "26.7.28"          # точная (не минимальная) версия xray-core для ноды
REMNAWAVE_IMAGE  = "remnawave/backend:3"       # мажорный тег 3.x (офиц. compose)
REMNANODE_IMAGE  = "ghcr.io/remnawave/node:latest"
POSTGRES_IMAGE   = "postgres:18.4"             # как в офиц. compose Remnawave 3.x
VALKEY_IMAGE     = "valkey/valkey:9-alpine"    # 3.x: redis через unix-сокет

# Валидация пользовательского ввода: значения попадают в шелл-строки и конфиги
# apt ждёт чужую блокировку dpkg (автообновление, cloud-init) до 5 минут,
# вместо того чтобы сразу упасть с «Could not get lock»
APT_GET = "DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300"

RE_DOMAIN = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")
RE_XPATH  = re.compile(r"^/[A-Za-z0-9._~/-]{1,120}$")
# [0-9], а не \d: \d в Python-регекспах ловит и юникодные цифры
RE_IPV4   = re.compile(r"^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$")

# Локальный порт xhttp-инбаунда. Фиксированный, как в оригинальном
# установщике: наружу он не смотрит (TLS снимает nginx), поэтому случайность
# ничего не даёт, а предсказуемый порт нужен режиму 3 и ручной диагностике.
XHTTP_PORT = 4443

PANEL_PORT = 3000                     # Remnawave слушает только 127.0.0.1:3000

PANEL_ENV = "/opt/remnawave/.env"

CDN_CRT = "/etc/nginx/ssl/cdn.crt"
CDN_KEY = "/etc/nginx/ssl/cdn.key"
# Метка в начале каждого конфига, который пишет установщик: по ней снос
# отличает свои файлы от дистрибутивных и чужих (см. wipe_previous).
CONF_MARK = "# node-installer-cdn"

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
def remnanode_compose(custom_xray=True):
    """Compose ноды. custom_xray — монтировать ли свой бинарник xray поверх штатного.

    Монтируется ТОЛЬКО когда файл реально скачан. Docker создаёт отсутствующий
    host path каталогом, и такой каталог, наложенный на /usr/local/bin/xray,
    закрывает собой рабочий бинарник из образа — нода перестаёт стартовать
    вовсе. Лучше поехать на xray из образа, чем на пустом каталоге.
    """
    xray_mount = ("      - /opt/remnanode/xray-custom:/usr/local/bin/xray\n"
                  if custom_xray else "")
    return """services:
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
%s    env_file:
      - .env
""" % (REMNANODE_IMAGE, xray_mount)


# ─────────────────────────────────────────────────────────────────────────────
#  Мелкие утилиты вывода
# ─────────────────────────────────────────────────────────────────────────────

LOWER_ALNUM = string.ascii_lowercase + string.digits


def rand(n=16, alphabet=string.ascii_letters + string.digits):
    return "".join(_rng.choice(alphabet) for _ in range(n))

def rand_password(n=28):
    """Пароль под требования Remnawave: >=24 символов, есть A-Z, a-z и 0-9.

    Панель проверяет ^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{24,}$ — случайной
    строки мало, нужно гарантировать каждый класс символов.
    """
    n = max(n, 24)
    chars = [_rng.choice(string.ascii_uppercase),
             _rng.choice(string.ascii_lowercase),
             _rng.choice(string.digits)]
    pool = string.ascii_letters + string.digits
    chars += [_rng.choice(pool) for _ in range(n - 3)]
    _rng.shuffle(chars)
    return "".join(chars)


# Каталоги, за которые путь сойдёт при взгляде в логи CDN: /uploadfiles/... —
# то, что использовал оригинальный установщик.
PATH_PREFIXES = ["uploadfiles", "content/media", "static/files", "upload/data",
                 "assets/video", "files/storage"]

def rand_label():
    """Случайная метка поддомена для origin: 'a7f3k2'.

    Прежний фиксированный 'origin.<домен>' стоит первым в любом словаре для
    поиска настоящего IP за CDN — подбирается за секунды. Первый символ буква:
    цифру в начале метки принимают не все панели DNS.

    Случайность прячет origin только от перебора. Если на него выпустить
    Let's Encrypt, имя всё равно попадёт в публичные CT-логи — тогда прятать
    его смысла нет (см. upgrade_origin_cert).
    """
    return _rng.choice(string.ascii_lowercase) + rand(_rng.randint(5, 7), LOWER_ALNUM)


def panel_host(cfg):
    """Домен панели: свой поддомен, а не корень домена.

    На корне панель стояла бы по угадываемому адресу, а её сертификат
    выпускался бы на один и тот же набор имён при каждой переустановке — а
    там недельный лимит Let's Encrypt в 5 штук, в который упираешься после
    нескольких прогонов подряд. Случайный поддомен снимает оба вопроса.
    """
    return cfg.get("panel_domain") or cfg["domain"]


def rand_path():
    """Путь xhttp: правдоподобный каталог + случайный хвост.

    Одного каталога мало — их всего несколько, и путь стал бы угадываемым;
    случайный хвост оставляет endpoint скрытым, а вид пути — обычным.
    """
    return "/%s/%s" % (_rng.choice(PATH_PREFIXES), rand(_rng.randint(6, 10), LOWER_ALNUM))


def tunnel_dir(path):
    """Путь туннеля в виде каталога: '/a/b' и 'a/b/' -> '/a/b/'."""
    return "/" + path.strip("/") + "/"

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
    """Обрезать/дополнить строку до ширины w по len().

    Символы считаются как есть, ANSI не распознаётся: цветную строку обрезка
    порвёт посреди escape-последовательности. Красить надо снаружи — то, что
    уже дополнено до ширины.
    """
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
    hr()

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
    """Стартовый баннер: логотип CDN (шрифт ANSI Shadow) + версия.

    3D даёт сам шрифт (тень «зашита» в глифы ╗╝═║╚), цвет — truecolor-градиент
    по строкам cyan→фиолетовый. Вне TTY _c печатает строки без ANSI.
    """
    rows = [
        " ██████╗██████╗ ███╗   ██╗",
        "██╔════╝██╔══██╗████╗  ██║",
        "██║     ██║  ██║██╔██╗ ██║",
        "██║     ██║  ██║██║╚██╗██║",
        "╚██████╗██████╔╝██║ ╚████║",
        " ╚═════╝╚═════╝ ╚═╝  ╚═══╝",
    ]
    grad = ["38;2;0;162;255", "38;2;0;212;255", "38;2;0;255;255",
            "38;2;124;252;255", "38;2;204;153;255", "38;2;224;102;255"]

    print("", flush=True)
    print(_c(C_ACC, "  " + "━" * (UI_W - 3)), flush=True)   # верхняя линия
    print("", flush=True)
    for col, row in zip(grad, rows):
        print("  " + _c(col, row), flush=True)

    print("", flush=True)
    print("  " + _c("1;" + C_TITLE, "CDN Installer")
          + _c(C_ACC, "  v" + INSTALLER_VERSION), flush=True)
    print("  " + _c(C_DIM, "XHTTP packet-up через российский CDN"), flush=True)
    print(_c(C_ACC, "  " + "━" * (UI_W - 3)), flush=True)

def callout(title, lines, color=C_ACC):
    """Врезка с левым рельсом (для DNS-записей, подсказок)."""
    print("", flush=True)
    print(_c(color, "  ┃ ") + _c("1;" + color, title), flush=True)
    for ln in lines:
        print(_c(color, "  ┃ ") + _c(C_VAL, ln), flush=True)


# ─────────────────────────────────────────────────────────────────────────────
#  Выполнение команд: локально и по SSH
# ─────────────────────────────────────────────────────────────────────────────

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

def is_ipv4(value):
    """Строгая проверка IPv4: ровно четыре октета 0..255 и ничего сверх того.

    Именно строгая, с якорем на конце: по прежнему `^\\d+\\.\\d+\\.\\d+\\.\\d+`
    строка вида '1.2.3.4; что-нибудь' считалась адресом и уезжала дальше в
    команду файрвола как есть.
    """
    m = RE_IPV4.match(value or "")
    return bool(m) and all(int(g) <= 255 for g in m.groups())


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


def say_homoglyph_hint(value):
    """Напечатать homoglyph_hint, если есть что сказать."""
    hint = homoglyph_hint(value)
    if hint:
        say("  " + hint)


def run(cmd, timeout=600, env_extra=None, input=None):
    """Run a shell command with clean env (no bundled LD_LIBRARY_PATH).

    env_extra — переменные окружения для дочернего процесса (пароль для
    sshpass передаётся так, чтобы не светиться в ps).
    input — строка на stdin команды: так секреты не попадают в argv.
    Возвращает (stdout, rc). stderr сливается в stdout.
    """
    env = dict(os.environ)
    env.pop("LD_LIBRARY_PATH", None)
    if env_extra:
        env.update(env_extra)
    try:
        p = subprocess.run(cmd, shell=True, env=env, timeout=timeout,
                           input=None if input is None else input.encode(),
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
    host = shq("%s@%s" % (user, cred["ip"]))
    if cred.get("key"):
        return "ssh -i %s %s %s " % (shq(cred["key"]), opts, host)
    # пароль уходит в окружение (SSHPASS), а не в argv — ps его не покажет
    return "sshpass -e ssh %s %s " % (opts, host)


def run_remote(cred, cmd, timeout=600, input=None):
    """Run command on remote server via SSH (password or key).

    Сама команда видна в ps на обеих машинах (argv ssh здесь, sh -c там),
    поэтому секреты передавайте через input — ssh отдаёт его в stdin команды.
    """
    safe = cmd.replace("'", "'\\''")
    env_extra = None if cred.get("key") else {"SSHPASS": cred.get("pass", "") or ""}
    return run(_ssh_prefix(cred) + "'" + safe + "'", timeout=timeout,
               env_extra=env_extra, input=input)


def _runner(cred):
    """runner(cmd, **kw) -> (out, rc) на сервере панели (тот же вид, что у run)."""
    return lambda cmd, **kw: run_remote(cred, cmd, **kw)


def write_file(path, content, mode=None):
    """Записать файл; mode=0o600 для всего, что содержит секреты.

    Файл создаётся сразу с нужными правами (os.open), а не chmod'ится после
    записи: иначе между open и chmod пароль лежит в файле с правами по umask.
    """
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                 0o644 if mode is None else mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        if mode is not None:
            os.fchmod(fd, mode)      # файл мог существовать с другими правами
        f.write(content)


def env_grep_cmd(var):
    """Шелл-команда, печатающая значение var из .env панели (локально или по SSH)."""
    return 'grep -oP "%s=\\K.*" %s 2>/dev/null' % (var, PANEL_ENV)


def panel_env_value(var):
    """Значение var из локального .env панели; '' — нет файла или переменной."""
    try:
        with open(PANEL_ENV, encoding="utf-8") as f:
            for line in f:
                if line.startswith(var + "="):
                    return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


# ─────────────────────────────────────────────────────────────────────────────
#  Сеть / окружение
# ─────────────────────────────────────────────────────────────────────────────

IP_SERVICES = ["ifconfig.me", "icanhazip.com", "api.ipify.org",
               "ipinfo.io/ip", "checkip.amazonaws.com"]

def get_ip():
    """Get server's public IP."""
    for svc in IP_SERVICES:
        out, _ = run("curl -s4 --max-time 5 %s" % svc)
        # строгая проверка: страница ошибки или капча с цифрами внутри
        # не должна превратиться в «адрес» для файрвола и DNS-записей
        ip = out.strip()
        if is_ipv4(ip):
            return ip
    out, _ = run("hostname -I 2>/dev/null | awk '{print $1}'")
    return out.strip()


def check_ubuntu():
    """Exit if OS is not Ubuntu/Debian."""
    _, rc = run("which apt-get")
    if rc != 0:
        err("Поддерживается только Ubuntu/Debian!")
        say("  Переустанови сервер с Ubuntu 22.04/24.04")
        sys.exit(1)


def check_disk(need_gb):
    """Предупредить, если под docker-образы не хватает места на /.

    Панель тянет postgres + valkey + remnawave: на диске
    ~5 ГБ это упирается в «no space left on device» уже на docker compose pull,
    поэтому лучше сказать об этом до установки, а не через 5 минут ожидания.
    """
    out, _ = run("df -Pm / | awk 'NR==2 {print $4}'")
    try:
        free_gb = int(out.strip()) / 1024.0
    except ValueError:
        return
    if free_gb >= need_gb:
        return
    warn("Свободно всего %.1f ГБ на / — нужно ~%d ГБ под образы Docker"
         % (free_gb, need_gb))
    say("  Освободи место (docker system prune -af; apt-get clean) "
        "или возьми диск побольше")
    if sys.stdin.isatty() and not confirm("Всё равно продолжить? (y/N)", default=False):
        sys.exit(1)


def fix_dns():
    """Починить сломанный DNS (stub systemd-resolved), прописав прямые nameserver'ы.

    Проба — getent, а не nslookup: nslookup лежит в отдельном пакете
    (bind9-dnsutils), которого на минимальных образах Ubuntu/Debian нет. По его
    отсутствию функция раньше сносила исправный systemd-resolved, перезаписывала
    resolv.conf и потом рапортовала о нерабочем DNS. getent есть всегда — он из
    glibc и резолвит через NSS, то есть через тот же /etc/resolv.conf.
    """
    probe = "getent hosts google.com >/dev/null 2>&1"
    cmd = ("%s && exit 0; "
           "systemctl disable --now systemd-resolved 2>/dev/null; "
           "rm -f /etc/resolv.conf; "
           "printf 'nameserver 8.8.8.8\\nnameserver 1.1.1.1\\n' > /etc/resolv.conf; "
           "%s && echo DNS_FIXED || echo DNS_STILL_BROKEN" % (probe, probe))
    out, _ = run(cmd)
    if "DNS_FIXED" in out:
        ok("DNS исправлен (8.8.8.8 / 1.1.1.1)")
    elif "DNS_STILL_BROKEN" in out:
        warn("DNS всё ещё не работает")


_apt_mirror_fixed = False

def ensure_apt_mirror():
    """Если apt-зеркало недоступно — переключить на archive.ubuntu.com.

    Приватные образы VPS (Fornex, Beget) часто ставят своё зеркало, которое
    отваливается -> падает apt install и get.docker.com. Ubuntu-only, no-op на
    прочих ОС и при рабочем зеркале. За запуск делается один раз.
    """
    global _apt_mirror_fixed
    if _apt_mirror_fixed:
        return
    _apt_mirror_fixed = True
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
    run(script)


def pkg_install(packages):
    """Установить пакеты apt: чинит DNS, зеркало, ждёт блокировку, повторяет."""
    # За установку сюда приходят по нескольку раз (certbot — на каждый выпуск
    # сертификата), и каждый раз это apt-get update до трёх минут.
    # Проверка именно по Status, а не по `dpkg -s`: у снесённого, но не
    # вычищенного пакета остаётся статус «deinstall ok config-files», и
    # `dpkg -s` на нём выходит с нулём — установка молча пропускалась бы.
    if run("for p in %s; do dpkg-query -W -f='${Status}' \"$p\" 2>/dev/null "
           "| grep -q '^install ok installed$' || exit 1; done" % packages)[1] == 0:
        return True
    say("  Ставлю пакеты: %s" % packages)
    fix_dns()
    ensure_apt_mirror()
    # Автообновление держит блокировку dpkg. Раньше его убивали kill -9 и
    # стирали lock-файлы: посреди распаковки пакета это ломает базу dpkg, и
    # чинить её приходится руками. Теперь останавливаем штатно — по SIGTERM
    # unattended-upgrade доделывает текущий пакет и выходит, systemctl stop
    # этого дожидается. Таймеры не выключаются насовсем: после перезагрузки
    # они снова в строю.
    run("systemctl stop apt-daily.timer apt-daily-upgrade.timer "
           "apt-daily.service apt-daily-upgrade.service 2>/dev/null; "
           "dpkg --configure -a 2>/dev/null", timeout=900)
    run("%s update -qq" % APT_GET, timeout=180)
    install = "%s install -y %s" % (APT_GET, packages)
    _, rc = run(install, timeout=600)
    if rc != 0:
        say("  Повторная попытка установки...")
        run("%s --fix-broken install -y 2>/dev/null; "
               "%s update --fix-missing" % (APT_GET, APT_GET), timeout=300)
        _, rc = run(install, timeout=600)
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

DOCKER_DAEMON_JSON = "/etc/docker/daemon.json"
DOCKER_MIRRORS = ["https://huecker.io", "https://dockerhub.timeweb.cloud",
                  "https://mirror.gcr.io"]


def setup_docker_mirror():
    """Configure Docker Hub mirror if registry-1.docker.io is blocked."""
    code, _ = run("curl -s -o /dev/null -m 5 -w '%{http_code}' "
                     "https://registry-1.docker.io/v2/ 2>/dev/null")
    # Без авторизации реестр отвечает 401 — это и есть «доступен». Раньше
    # ждали 200, которого не бывает, и daemon.json перезаписывался всегда.
    if code.strip() in ("200", "401"):
        return
    say("  Настраиваю зеркало Docker Hub...")
    # daemon.json дописывается, а не перезаписывается: в нём бывают чужие
    # настройки (log-opts, data-root, insecure-registries), и затереть их —
    # значит незаметно поменять поведение docker на сервере.
    try:
        with open(DOCKER_DAEMON_JSON, encoding="utf-8") as f:
            old_text = f.read()
    except FileNotFoundError:
        old_text = ""
    except OSError as e:
        warn("Не прочитать %s (%s) — зеркало не настроено" % (DOCKER_DAEMON_JSON, e))
        return
    try:
        conf = json.loads(old_text) if old_text.strip() else {}
    except ValueError:
        conf = None
    if not isinstance(conf, dict):
        warn("%s не разобран как JSON-объект — не трогаю, зеркало не настроено"
             % DOCKER_DAEMON_JSON)
        return
    mirrors = conf.get("registry-mirrors")
    mirrors = list(mirrors) if isinstance(mirrors, list) else []
    new = [m for m in DOCKER_MIRRORS if m not in mirrors]
    if not new:
        ok("Зеркала Docker Hub уже прописаны")
        return
    if old_text:
        write_file("%s.bak.%d" % (DOCKER_DAEMON_JSON, int(time.time())), old_text)
    conf["registry-mirrors"] = mirrors + new
    write_file(DOCKER_DAEMON_JSON, json.dumps(conf, indent=2) + "\n")
    run("systemctl restart docker")
    ok("Зеркало Docker Hub настроено")


def install_docker():
    """Robustly install Docker: get.docker.com -> docker.io -> docker-ce -> static."""

    def has_docker():
        return run("docker --version")[1] == 0

    if has_docker():
        return True
    say("  Ставлю Docker (get.docker.com), это пара минут...")
    attempts = [
        (None, "curl -fsSL https://get.docker.com | sh 2>&1 | tail -5"),
        ("get.docker.com не сработал, чиню apt-зеркало и ставлю docker.io...",
         APT_GET + " install -y docker.io 2>&1 | tail -5"),
        ("пробую официальный репозиторий docker-ce...",
         'install -m 0755 -d /etc/apt/keyrings && '
           'curl -fsSL https://download.docker.com/linux/ubuntu/gpg '
           '-o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc && '
           'echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] '
           'https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) '
           'stable" > /etc/apt/sources.list.d/docker.list && ' + APT_GET + ' update -qq && '
         + APT_GET + ' install -y docker-ce docker-ce-cli '
           'containerd.io docker-compose-plugin 2>&1 | tail -5'),
        ("пробую статический бинарник docker...",
         'T=$(mktemp -d) && cd "$T" && A=$(uname -m) && curl -fsSL '
           'https://download.docker.com/linux/static/stable/$A/docker-27.3.1.tgz -o d.tgz && '
           'tar xzf d.tgz && cp docker/* /usr/bin/ && cd / && rm -rf "$T" && '
           'cat > /etc/systemd/system/docker.service <<EOF\n'
           '[Unit]\nDescription=Docker\nAfter=network.target\n'
           '[Service]\nExecStart=/usr/bin/dockerd\nRestart=always\nLimitNOFILE=1048576\n'
           '[Install]\nWantedBy=multi-user.target\nEOF\n'
           'systemctl daemon-reload && systemctl enable --now docker && sleep 6'),
    ]
    for i, (msg, cmd) in enumerate(attempts):
        if msg:
            say("  " + msg)
        if i == 1:
            ensure_apt_mirror()
        run(cmd, timeout=600)
        if has_docker():
            setup_docker_mirror()
            return True
    return False


def ensure_compose():
    """Гарантировать docker compose plugin."""
    _, rc = run("docker compose version 2>/dev/null")
    if rc == 0:
        return True
    say("  Ставлю docker compose plugin...")
    run(APT_GET + ' install -y -qq docker-compose-plugin 2>/dev/null || '
         + APT_GET + ' install -y -qq docker-compose-v2 2>/dev/null || '
           '(mkdir -p /usr/local/lib/docker/cli-plugins && '
           'curl -fsSL https://github.com/docker/compose/releases/latest/download/'
           'docker-compose-linux-$(uname -m) '
           '-o /usr/local/lib/docker/cli-plugins/docker-compose && '
           'chmod +x /usr/local/lib/docker/cli-plugins/docker-compose)', timeout=300)
    _, rc = run("docker compose version 2>/dev/null")
    return rc == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Тюнинг ОС, swap, nginx-база, SSL, заглушка
# ─────────────────────────────────────────────────────────────────────────────

def tune_os():
    """sysctl BBR + limits + swap 2G."""
    write_file("/etc/sysctl.d/99-vpn-tuning.conf", SYSCTL_TUNING)
    write_file("/etc/security/limits.d/99-nofile.conf", LIMITS_NOFILE)
    run("sysctl --system > /dev/null 2>&1")
    if run("swapon --show | grep -q /")[1] == 0:
        ok("Swap уже есть")
        return
    say("  Создание swap 2G...")
    # Скобки вокруг fstab обязательны: без них `a && b || echo` дописывал
    # swap в fstab и тогда, когда fallocate/mkswap упали (btrfs, нет места).
    run("fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && "
           "swapon /swapfile && "
           "{ grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab; }")


def ensure_nginx_base():
    """Гарантировать /etc/nginx/nginx.conf (битое зеркало / удалённый conffile)."""
    run("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled "
           "/etc/nginx/conf.d /etc/nginx/ssl /var/www/html")
    if run("test -s /etc/nginx/nginx.conf")[1] == 0:
        return
    ensure_apt_mirror()
    run(APT_GET + " install -y nginx-common nginx-core 2>&1 | tail -3", timeout=300)
    run(APT_GET + " install -y --reinstall "
           "-o Dpkg::Options::=--force-confmiss nginx-common 2>&1 | tail -3", timeout=300)
    if run("test -s /etc/nginx/nginx.conf")[1] == 0:
        return
    write_file("/etc/nginx/nginx.conf", NGINX_MINIMAL_CONF)
    if run("test -s /etc/nginx/mime.types")[1] != 0:
        write_file("/etc/nginx/mime.types", NGINX_MINIMAL_MIME)
    say("  nginx.conf восстановлен (минимальный конфиг)")


def self_signed_cert(cn="cdn-origin"):
    """Создать self-signed cdn.crt/cdn.key если их нет (ключ — только root)."""
    # Пара проверяется целиком: раньше смотрели только на .crt, и потерянный
    # ключ не перевыпускался — nginx после этого просто не поднимался. Скобки
    # вокруг test'ов обязательны, иначе `||` цепляется ещё и к mkdir/chmod.
    cmd = ("mkdir -p /etc/nginx/ssl && chmod 700 /etc/nginx/ssl; "
           "{ test -s %s && test -s %s; } || "
           "openssl req -x509 -nodes -days 3650 -newkey rsa:2048 "
           "-keyout %s -out %s -subj '/CN=%s' 2>/dev/null; chmod 600 %s 2>/dev/null"
           % (CDN_CRT, CDN_KEY, CDN_KEY, CDN_CRT, cn, CDN_KEY))
    run(cmd)


def write_decoy(domain):
    """Написать страницу-заглушку в /var/www/html/index.html."""
    write_file("/var/www/html/index.html", DECOY_HTML.format(domain=domain))


def nginx_write_conf(name, content):
    """Write nginx site config and enable symlink."""
    run("mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled")
    path = "/etc/nginx/sites-available/%s" % name
    write_file(path, content)
    run("rm -f /etc/nginx/sites-enabled/%s && ln -s %s /etc/nginx/sites-enabled/%s"
        % (name, path, name))
    # дистрибутивный nginx.conf приезжает с worker_connections 768 — поднимаем
    run("sed -i 's/worker_connections[[:space:]]*[0-9]*/worker_connections 16384/' "
        "/etc/nginx/nginx.conf")
    out, rc = run("nginx -t && systemctl restart nginx")
    if rc != 0:
        warn("проблема с nginx:\n" + out)
        say("  Попробуй: nginx -t и systemctl restart nginx")
    return rc == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Xray: инбаунды
# ─────────────────────────────────────────────────────────────────────────────

def xhttp_settings(path):
    """xhttpSettings туннеля — ОДИН набор и для инбаунда ноды, и для хоста.

    Клиент собирается панелью из хоста, и xray требует, чтобы обе стороны
    имели одинаковые значения. Пока установщик клал полный набор в инбаунд, а
    в хост — только {"mode": "packet-up"}, клиент слал аплинк POST'ами и
    обычный ?x_padding=: Yandex CDN отбивал POST кодом 405 (в списке
    разрешённых методов у него только GET, HEAD, OPTIONS), а xray отвечал 400
    на запросы с чужим паддингом. Поэтому набор один и берётся отсюда оба раза.

    uplinkHTTPMethod ровно "GET" заглавными — так в xray-core (POST/PUT/PATCH/
    GET) и так в рабочей конфигурации, с которой это снято. Аплинк GET'ами —
    единственный способ пройти CDN, который не пропускает POST.

    path у xray со слешем на конце: nginx проксирует всё, что под путём, а сам
    путь без слеша отдаёт 404.
    """
    return {
        "mode": "packet-up",
        "path": tunnel_dir(path),
        "xPaddingKey": "_dc",
        "xPaddingHeader": "X-Cache",
        "xPaddingMethod": "tokenish",
        "uplinkHTTPMethod": "GET",
        "xPaddingObfsMode": True,
        "xPaddingPlacement": "queryInHeader",
        "scMaxEachPostBytes": 524288,
        "scMaxConcurrentPosts": 1,
        "scMinPostsIntervalMs": 150,
    }


def build_xhttp_inbound(port, path, tag, uuid=None):
    """XHTTP packet-up inbound: слушает 127.0.0.1:port, TLS снимает nginx.

    clients пустой — пользователей в конфиг ноды подставляет панель.
    """
    return {
        "tag": tag,
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [{"id": uuid, "email": "user1"}] if uuid else [],
            "decryption": "none",
        },
        "sniffing": {"enabled": True, "routeOnly": False,
                     "destOverride": ["http", "tls", "quic"]},
        "streamSettings": {
            "network": "xhttp",
            "security": "none",
            "xhttpSettings": xhttp_settings(path),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
#  nginx CDN-origin конфиг (сердце XHTTP-фронтинга)
# ─────────────────────────────────────────────────────────────────────────────

def nginx_cdn_origin_config(port, path, crt=CDN_CRT, key=CDN_KEY):
    """Generate nginx CDN origin config.

    path — каталог. Голый путь отдаёт 404, проксируется только то, что под ним:
    активная проба ровно по <path> неотличима от обращения к несуществующей
    странице, а xhttp всегда ходит на <path>/<сессия>. (Снято с рабочей ноды
    на Yandex CDN.)
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
    # '/abc/' из --path дал бы 'location /abc// {' — туннель бы не работал
    bare = tunnel_dir(path).rstrip("/")
    loc = ("    location = %s {\n        return 404;\n    }\n\n"
           "    location %s/ {\n%s    }\n" % (bare, bare, proxy_block))

    return CONF_MARK + """
upstream xray_xhttp {
    server 127.0.0.1:%d;
    keepalive 128;
}

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
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
""" % (port, crt, key, loc)


# ─────────────────────────────────────────────────────────────────────────────
#  Caddy CDN-origin конфиг (альтернатива nginx: тот же XHTTP-фронтинг)
# ─────────────────────────────────────────────────────────────────────────────

def caddy_cdn_origin_config(port, path, crt=CDN_CRT, key=CDN_KEY,
                            panel_domain=None, panel_port=None):
    """Caddyfile-аналог nginx_cdn_origin_config.

    Origin-сайт — catch-all на :80/:443 с готовым сертификатом (self-signed /
    certbot), Caddy свой ACME для него не запускает. Поведение 1:1 с nginx:
    голый путь отдаёт 404, проксируется только <path>/*, кеш и буферизация
    выключены (flush_interval -1 — стриминг для packet-up).

    Если задан panel_domain — добавляется отдельный сайт панели на своём домене
    с авто-TLS (Let's Encrypt), тогда глобальный auto_https не выключаем.
    """
    p = path.strip("/")
    globals_block = "{\n    admin off\n}" if panel_domain else \
                    "{\n    admin off\n    auto_https off\n}"
    origin = """
:80, :443 {
    tls %s %s

    @acme path /.well-known/acme-challenge/*
    handle @acme {
        root * /var/www/certbot
        file_server
    }

    handle /health {
        header Content-Type application/json
        respond `{"status":"ok","service":"media-gateway","version":"4.2.1"}` 200
    }

    @tunnel_bare path /%s
    handle @tunnel_bare {
        respond 404
    }

    @tunnel path /%s/*
    handle @tunnel {
        reverse_proxy 127.0.0.1:%d {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            flush_interval -1
        }
        header Cache-Control "no-store, no-cache"
        header CDN-Cache-Control "no-store"
        header Pragma "no-cache"
        header X-Accel-Buffering "no"
    }

    handle {
        root * /var/www/html
        file_server
    }
}
""" % (crt, key, p, p, port)
    panel = ""
    if panel_domain:
        # Панель на своём домене: Caddy сам выпускает и продлевает LE-сертификат
        # (SNI разводит трафик — origin ловит всё, кроме этого домена).
        panel = """
%s {
    reverse_proxy 127.0.0.1:%d {
        header_up X-Forwarded-Proto https
    }
}
""" % (panel_domain, panel_port)
    return CONF_MARK + "\n" + globals_block + "\n" + origin + panel


def install_caddy():
    """Поставить caddy из официального репозитория Cloudsmith (Debian/Ubuntu)."""
    _, rc = run("command -v caddy")
    if rc == 0:
        return True
    run(APT_GET + " install -y debian-keyring debian-archive-keyring "
        "apt-transport-https curl gnupg")
    run("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' "
        "| gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg")
    run("curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' "
        "> /etc/apt/sources.list.d/caddy-stable.list")
    run(APT_GET + " update")
    _, rc = run(APT_GET + " install -y caddy")
    return rc == 0


def apply_caddy_front(port, path, crt=CDN_CRT, key=CDN_KEY,
                      panel_domain=None, panel_port=None):
    """Поднять caddy-фронт вместо nginx: освободить :80/:443, записать Caddyfile.

    Сертификат origin — self-signed (у всех CDN проверка сертификата источника
    выключена, валидный LE тут не обязателен). Если задан panel_domain — Caddy
    дополнительно обслуживает панель на своём домене с авто-TLS."""
    if not install_caddy():
        warn("caddy не установился — фронт остаётся на nginx")
        return False
    # nginx освобождает порты, иначе caddy не встанет на :443
    run("systemctl disable --now nginx 2>/dev/null")
    write_file("/etc/caddy/Caddyfile",
               caddy_cdn_origin_config(port, path, crt, key, panel_domain, panel_port))
    out, rc = run("caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile "
                  "2>&1 && systemctl enable --now caddy && systemctl restart caddy")
    if rc != 0:
        warn("проблема с caddy:\n" + out)
        say("  Проверь: caddy validate --config /etc/caddy/Caddyfile")
        return False
    return True


def apply_origin_front(cfg, xport, path, panel_domain=None, panel_port=None):
    """Единая точка подъёма origin-фронта: caddy при --front caddy, иначе nginx.

    Возвращает фактически поднятый фронт ("caddy"/"nginx"). При caddy панель (если
    задана) обслуживает сам caddy с авто-TLS, поэтому вызывающему не нужны ни
    nginx-panel.conf, ни certbot. При сбое caddy печатает warn и откатывается
    на nginx."""
    if cfg.get("front") == "caddy":
        if apply_caddy_front(xport, path, panel_domain=panel_domain,
                             panel_port=panel_port):
            ok("origin-фронт (caddy) на :443 -> 127.0.0.1:%d%s"
               % (xport, " + панель %s" % panel_domain if panel_domain else ""))
            return "caddy"
        cfg["front"] = "nginx"      # откат на надёжный дефолт
        # apply_caddy_front уже сделал nginx disable: без enable он поднимется
        # сейчас, но после перезагрузки :443 будет пуст. И caddy, если успел
        # стартовать, держит порты — nginx на них не встанет.
        run("systemctl disable --now caddy 2>/dev/null; systemctl enable nginx 2>/dev/null")
    ensure_nginx_base()             # на caddy-пути nginx не нужен вовсе
    nginx_write_conf("default", nginx_cdn_origin_config(xport, path))
    return "nginx"


# ─────────────────────────────────────────────────────────────────────────────
#  Remnawave API
# ─────────────────────────────────────────────────────────────────────────────

def api_response(resp):
    """Поле response из ответа панели; {} для ошибки, пустого или не-объекта."""
    r = resp.get("response") if isinstance(resp, dict) else None
    return r if isinstance(r, dict) else {}


def access_token(resp):
    """accessToken из ответа auth/login|register (в 3.x — внутри response)."""
    tok = api_response(resp).get("accessToken")
    if not tok and isinstance(resp, dict):
        tok = resp.get("accessToken")
    return tok or ""


def rw_api_local(token, method, path, data=None):
    """Make API call to local Remnawave panel (127.0.0.1:3000)."""
    url = "http://127.0.0.1:%d/api/%s" % (PANEL_PORT, path.lstrip("/"))
    # PANEL_DOMAIN как Host, чтобы пройти проверку origin панели
    rdom = panel_env_value("PANEL_DOMAIN") or "localhost"
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


def _curl_quote(value):
    """Строка в кавычках для конфига curl (-K): экранируются \\ и \", переводы строк
    отбрасываются — они всё равно разорвали бы строку конфига."""
    value = value.replace("\r", "").replace("\n", "")
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def rw_api_ssh(cred, token, method, path, data=None):
    """Make API call to Remnawave panel via SSH (curl to 127.0.0.1:3000).

    Возвращает (тело, HTTP-код) — как rw_api_local. Код приезжает отдельной
    последней строкой (-w), иначе отказ панели («A112», 401) выглядел бы для
    вызывающего успехом: JSON-то распарсился.
    """
    url = "http://127.0.0.1:%d/api/%s" % (PANEL_PORT, path.lstrip("/"))
    cmd = ('RDOM=$(%s); '
           'curl -s -K - -w "\\n%%{http_code}" -X %s -H "Content-Type: application/json" '
           '-H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" '
           '-H "X-Real-IP: 127.0.0.1" -H "X-Remnawave-Client-Type: browser" '
           '-H "Host: ${RDOM:-localhost}" %s'
           % (env_grep_cmd("PANEL_DOMAIN"), shq(method), shq(url)))
    # Пустой токен — это только auth/login: чужой Bearer из .panel_token ему не
    # нужен. Файл токена разбирает resolve_panel_token.
    tok = (token or "").strip()
    # Токен и тело (в нём бывает пароль админа для auth/login) идут конфигом
    # curl через stdin: в argv их увидел бы любой пользователь панели в ps.
    config = []
    if tok:
        config.append("header = %s" % _curl_quote("Authorization: Bearer " + tok))
    if data is not None:
        config.append("data = %s" % _curl_quote(json.dumps(data)))
    out, _ = run_remote(cred, cmd, input="\n".join(config) + "\n")
    body, _, tail = out.rpartition("\n")
    code = int(tail.strip()) if tail.strip().isdigit() else 0
    if not body.strip():
        return {"error": "empty response"}, code
    try:
        return json.loads(body), code
    except Exception:
        return {"error": "invalid JSON", "raw": body[:200]}, code


def rw_login_ssh(cred, username, password):
    """Логин в Remnawave через SSH-curl на панели. Возвращает accessToken или ''."""
    resp, _ = rw_api_ssh(cred, "", "POST", "auth/login",
                         {"username": username, "password": password})
    return access_token(resp)


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
        cand = mint_api_token(_runner(cred))
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
    creds = {"username": username, "password": password}
    resp, code = rw_api_local(None, "POST", "auth/register", creds)
    # code=0 — до HTTP не дошло: REST-инстанс панели ещё не слушает 3000 и
    # docker-proxy рвёт соединение. Ждать тут дешевле, чем падать.
    for attempt in range(6):
        if code != 0:
            break
        say("  Панель оборвала соединение, повтор через 5 с (%d/6)..." % (attempt + 1))
        time.sleep(5)
        resp, code = rw_api_local(None, "POST", "auth/register", creds)
    if code in (200, 201):
        ok("Админ зарегистрирован")
    elif code in (400, 409):
        # 400 — это не только «уже зарегистрирован», но и отказ валидации
        # (пароль короче 24 символов либо без цифры/заглавной). Считать его
        # успехом нельзя: раньше установка доезжала до конца с пустым токеном
        # и 401 на каждом вызове API.
        say("  Регистрация вернула %s: %s"
            % (code, str(resp.get("message") or resp)[:160]))
    tok = access_token(resp)
    if not tok:
        resp, code = rw_api_local(None, "POST", "auth/login", creds)
        tok = access_token(resp)
        if not tok:
            err("Ни регистрация, ни вход не дали токен: %s"
                % str(resp.get("message") or resp)[:160])
    return tok


def _sign_api_jwt(secret, uuid_str, days=365):
    """Подписать JWT роли API секретом панели (HS256).

    Панель проверяет ВСЕ токены секретом APP_SECRET (jwt.strategy.ts), а гвард
    для роли API не требует заголовка X-Remnawave-Client-Type — в отличие от
    ADMIN. Значит достаточно подписать {uuid, username, role:'API'} тем же
    секретом; проверено против эталона jwt.io побайтово.
    """
    def b(x):
        return base64.urlsafe_b64encode(x).rstrip(b"=")

    now = int(time.time())
    seg = (b(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
           + b"." + b(json.dumps({"uuid": uuid_str, "username": None, "role": "API",
                                  "iat": now, "exp": now + days * 86400},
                                 separators=(",", ":")).encode()))
    sig = b(hmac.new(secret.encode(), seg, hashlib.sha256).digest())
    return (seg + b"." + sig).decode()


def mint_api_token(runner):
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
        out, _ = runner(env_grep_cmd(var))
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
    out, rc = runner("echo %s | base64 -d | docker exec -i remnawave-db "
                     "psql -U postgres -v ON_ERROR_STOP=1" % b64)
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
        tok = api_response(resp).get("token")
        if isinstance(tok, dict):         # в части ревизий токен вложен ещё раз
            tok = tok.get("token")
        tok = tok.strip() if isinstance(tok, str) else ""
        if tok:
            ok("API-токен выпущен через /api/tokens")
            return tok
        err("Панель не выдала API-токен (%s): %s"
            % (code, str(resp.get("message") or resp)[:160]))
    return ""


NODE_NAME = "Server-CDN"          # как нода называется в панели
NODE_COUNTRY = "RU"               # флаг в панели: трафик клиента входит через РФ


def profile_name(cdn_name):
    """Имя профиля в панели: CDN-YANDEX."""
    return "CDN-%s" % cdn_name.upper()


def host_remark(cdn_name):
    """Подпись хоста в панели и в клиенте: «Yandex bypass»."""
    return "%s bypass" % cdn_name.capitalize()


def _leftovers(paths, containers, vol_filter=""):
    """Что осталось от прошлой установки: каталоги, контейнеры, тома."""
    found = [p for p in paths if os.path.exists(p)]
    names, _ = run("docker ps -a --format '{{.Names}}' 2>/dev/null")
    found += ["контейнер " + c for c in containers if c in names.split()]
    if vol_filter:
        vols, _ = run("docker volume ls -q --filter name=%s 2>/dev/null" % vol_filter)
        found += ["том " + v for v in vols.split()]
    return found


# Конфиги веб-фронта, которые пишет установщик: имя файла -> (что это, чей).
# Чей — какой компонент должен сноситься, чтобы трогать файл: конфиг панели в
# режиме 3 («только CDN» на сервере с панелью) удалять нельзя.
OUR_NGINX_SITES = {"default": ("конфиг nginx origin (туннель прошлой установки)", None),
                   "panel.conf": ("конфиг nginx панели", "panel")}
CADDYFILE = "/etc/caddy/Caddyfile"


def _is_ours(path):
    """True, если этот конфиг писал установщик (по метке CONF_MARK в начале).

    Дистрибутивный /etc/nginx/sites-available/default и чужие сайты на сервере
    метки не имеют — их снос не трогает.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return CONF_MARK in f.read(200)
    except OSError:
        return False


def _our_sites(panel):
    """Наши nginx-сайты, которые сносятся вместе с выбранными компонентами."""
    for name, (what, owner) in sorted(OUR_NGINX_SITES.items()):
        path = "/etc/nginx/sites-available/%s" % name
        if (owner != "panel" or panel) and _is_ours(path):
            yield name, path, what


def _net_filters(panel, node):
    """--filter для docker network ls: только сети сносимых компонентов."""
    names = [n for n, on in (("remnawave", panel), ("remnanode", node)) if on]
    return " ".join("--filter name=" + n for n in names)


def _front_leftovers(panel=True, node=True):
    """Остатки веб-фронта прошлой установки.

    Удаление /opt/remnawave и контейнеров их не убирает, а мешают они по-разному:
    Caddy с прошлого запуска держит :443 и новый nginx на порт не встаёт, а
    старый sites-enabled/default оставляет включённым прежний путь туннеля.

    panel/node — какие компоненты ставятся заново. Режим 3 ставит фронт перед
    РАБОЧЕЙ нодой: её правила ufw на 2222 и конфиг панели трогать нельзя.
    """
    found = [what for _, _, what in _our_sites(panel)]
    if _is_ours(CADDYFILE):
        found.append("Caddyfile прошлой установки")
        if run("systemctl is-active --quiet caddy")[1] == 0:
            found.append("caddy занимает :80/:443")
    filters = _net_filters(panel, node)
    if filters:
        nets, _ = run("docker network ls --format '{{.Name}}' %s 2>/dev/null" % filters)
        found += ["docker-сеть " + n for n in nets.split()]
    if node and "2222/tcp" in run("ufw status 2>/dev/null")[0]:
        found.append("правила ufw на порт ноды 2222")
    return found


def _wipe_front(panel=True, node=True):
    """Снести веб-фронт прошлой установки: конфиги, caddy, сети, правила ufw."""
    for name, path, _ in list(_our_sites(panel)):
        run("rm -f %s /etc/nginx/sites-enabled/%s" % (path, name))
    if _is_ours(CADDYFILE):
        # disable, а не только stop: иначе caddy вернётся после перезагрузки
        # и заберёт :443 у nginx.
        run("systemctl disable --now caddy 2>/dev/null")
        run("rm -f " + CADDYFILE)
    filters = _net_filters(panel, node)
    if filters:
        run("docker network ls -q %s 2>/dev/null | xargs -r docker network rm "
            "2>/dev/null" % filters)
    if not node:
        # Нода работает и остаётся: без её правил панель к ней не достучится
        # (ufw с deny incoming), а firewall_setup(keep_listening) их не вернёт.
        return
    # Правила ufw на 2222 привязаны к IP прошлой панели: он мог смениться, а
    # правило пережило бы снос и пускало чужой сервер. Номера сдвигаются после
    # каждого удаления, поэтому идём с конца и ограничиваем число проходов.
    run("for i in 1 2 3 4 5 6 7 8; do "
        "n=$(ufw status numbered 2>/dev/null | grep -E ' 2222/(tcp|udp)' | tail -1 "
        r"| sed -n 's/^\[ *\([0-9]*\).*/\1/p'); "
        "[ -n \"$n\" ] || break; "
        "ufw --force delete $n >/dev/null 2>&1 || break; done")


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
    found += _front_leftovers(panel, node)
    if not found:
        return
    warn("Найдены остатки прошлой установки:")
    for f in found:
        say("    - %s" % f)
    if panel:
        say("  Вместе с ними удалится база панели (пользователи, ноды, подписки)")
    if not assume_yes:
        # Без терминала спросить некого, а снос уносит базу панели вместе с
        # пользователями. Раньше здесь проверялся isatty() — и неинтерактивный
        # запуск (пайп, cron) сносил всё молча, из-за чего --wipe ничего не
        # решал. Теперь без терминала нужен явный --wipe.
        if not sys.stdin.isatty():
            say("  Без терминала ничего не сношу — нужен явный --wipe")
            say("  Установка продолжится поверх прошлой")
            return
        if not confirm("Снести и поставить начисто? (Y/n)", default=True):
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
    _wipe_front(panel, node)
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
    old = panel_env_value("POSTGRES_PASSWORD")
    if old:
        say("  Найден том базы от прошлой установки — использую её пароль")
        return old
    warn("Том базы remnawave-db-data остался от прошлой установки, "
         "а пароль от него утерян")
    say("  С новым паролем панель не войдёт в базу (Prisma P1000)")
    if sys.stdin.isatty() and confirm("Удалить старую базу и поставить начисто? (y/N)",
                                      default=False):
        run("cd /opt/remnawave && docker compose down -v 2>/dev/null")
        run("docker volume rm -f remnawave-db-data "
            "remnawave_remnawave-db-data 2>/dev/null")
        return rand(24)
    err("Без совпадающего пароля установка не поднимется")
    say("  Удали том вручную: cd /opt/remnawave && docker compose down -v")
    sys.exit(1)


def remnawave_bringup(cfg):
    """Docker + compose + .env + запуск контейнеров + регистрация админа + API-токен.

    Общая часть подъёма панели Remnawave. Возвращает API-токен
    (или '' при неудаче)."""
    domain   = panel_host(cfg)
    admin_pw = cfg["admin_pass"]

    step("Установка панели Remnawave 3.x")
    say("  Порядок: Docker → образы панели → контейнеры → админ и API-токен")
    check_disk(5)
    require_docker()

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
    write_file(PANEL_ENV, env, mode=0o600)          # пароль БД, JWT

    say("  Качаю образы панели — дольше всего тут:")
    for image in (REMNAWAVE_IMAGE, POSTGRES_IMAGE, VALKEY_IMAGE):
        say("    · %s" % image)
    run("cd /opt/remnawave && docker compose down 2>/dev/null")
    out, rc = run("cd /opt/remnawave && docker compose pull 2>&1", timeout=900)
    if rc != 0:
        err("docker compose pull не прошёл — образы не скачались:")
        say("  " + "\n  ".join(out.strip().splitlines()[-8:]))
        if "no space left" in out.lower():
            say(run("df -h /")[0])
            say("  Освободи место (docker system prune -af) или возьми диск побольше")
        sys.exit(1)
    say("  Образы скачаны, запускаю контейнеры...")
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
        code, _ = run("curl -s -X POST -H %s "
                      "-H 'Content-Type: application/json' -d '{}' "
                      "http://127.0.0.1:%d/api/auth/register "
                      "-H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1' "
                      "-o /dev/null -w '%%{http_code}'"
                      % (shq("Host: " + domain), PANEL_PORT))
        if code.strip() in ("200", "201", "400", "409", "422"):
            up = True
            break
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
        time.sleep(5)
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
    domain   = panel_host(cfg)
    path     = cfg["path"]
    xport    = cfg["xport"]

    tune_os()
    token = remnawave_bringup(cfg)
    api = functools.partial(rw_api_local, token)

    # Веб-слой: без него панель остаётся на 127.0.0.1:3000, а CDN-origin
    # не существует — провайдеру нечего забирать.
    setup_panel_web(cfg, xport, path)

    # ── профиль + инбаунд CDN xhttp ──
    step("Создание профиля, ноды, хоста и юзера через API")
    user_uuid = str(_uuid.uuid4())
    ok("Вход: VLESS XHTTP packet-up, 127.0.0.1:%d, путь %s" % (xport, path))
    inbounds = build_node_inbounds(cfg, xport, path)
    prof_uuid, tag2uuid = create_config_profile(api, profile_name(cfg["cdn"]),
                                                inbounds)
    inbound_uuids = inbound_uuids_of(inbounds, tag2uuid)

    # ── нода (remnanode на 127.0.0.1:2222 внутри docker gateway) ──
    step("Настройка ноды Remnawave")
    say("  Порядок: регистрация в панели → бинарник xray → образ ноды → "
        "файрвол → ожидание старта")
    gw, _ = run("docker network inspect remnawave-network "
                "-f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'")
    gw = gw.strip() or "172.18.0.1"
    say("  Docker gateway: %s" % gw)
    secret = create_remnawave_node(api, NODE_NAME, gw, prof_uuid, inbound_uuids)
    # Как и в режиме 2: без secretKey remnanode встаёт с пустым SECRET_KEY,
    # панель его не признаёт, а установка рапортует «ГОТОВО».
    if not secret:
        say("  Панель работает, но нода без secretKey к ней не подключится — "
            "проверь ответы API выше и запусти установку снова")
        sys.exit(1)

    deploy_remnanode_files(secret)
    say("  Запуск контейнера remnanode...")
    start_remnanode()
    # Файрвол ставим до ограничения 2222: тогда правило ноды уходит в ufw и
    # переживает перезагрузку.
    firewall_setup()
    restrict_node_port_2222(gw)
    node_wait_ready()

    host_uuid, sub_url, user_uuid = publish_for_clients(
        api, cfg, prof_uuid, inbounds, tag2uuid, user_uuid, domain)
    node_reload_clients()

    return {"token": token, "user_uuid": user_uuid, "sub_url": sub_url,
            "prof_uuid": prof_uuid,
            "inbound_uuids": inbound_uuids,
            "host_uuid": host_uuid, "api": api}


def require_docker():
    """Docker и compose обязательны: без них дальше ставить нечего."""
    if not install_docker() or not ensure_compose():
        err("Docker не установился! Попробуй вручную: curl -fsSL https://get.docker.com | sh")
        sys.exit(1)


def inbound_uuids_of(inbounds, tag2uuid):
    """uuid, которые панель выдала нашим инбаундам, в порядке инбаундов."""
    return [u for u in (tag2uuid.get(i["tag"]) for i in inbounds) if u]


def publish_for_clients(api, cfg, prof_uuid, inbounds, tag2uuid, user_uuid, sub_domain):
    """Хост CDN, сквад и юзер — общий хвост режимов 1 и 2.

    Без них нода поднимается, но панель не выдаёт ей ни одного клиента, и
    подписки, по которой можно подключиться, тоже не появляется. Адрес хоста —
    origin: домена CDN на этом шаге ещё нет, провайдер выдаёт его позже, и
    main() переставит хост через update_host_address().
    Возвращает (host_uuid, sub_url, user_uuid).
    """
    tag = inbounds[0]["tag"]
    host_uuid = create_remnawave_host(api, prof_uuid, tag,
                                      cfg.get("origin_domain", cfg["domain"]),
                                      cfg["path"], inbound_uuid=tag2uuid.get(tag),
                                      remark=host_remark(cfg["cdn"]))
    add_inbounds_to_squad(api, inbound_uuids_of(inbounds, tag2uuid))
    sub_url, user_uuid = create_remnawave_user(api, "user1", user_uuid, sub_domain)
    return host_uuid, sub_url, user_uuid


def build_node_inbounds(cfg, xport, path):
    """Инбаунды профиля ноды. Вход один: CDN xhttp через origin."""
    return [build_xhttp_inbound(xport, path, "%s_CDN" % cfg["cdn"].upper())]


def panel_node_secret(api):
    """SECRET_KEY для remnanode. В 3.x это ОДИН ключ на всю панель.

    Раньше ключ искали в ответе POST /api/nodes — в 3.x его там нет, нода
    создаётся (HTTP 201), а установка обрывалась «панель не создала ноду».
    Ключ отдаёт GET /api/keygen: в 3.x полем secretKey, в 2.x тем же
    эндпоинтом, но полем pubKey (там он ехал в ноду как SSL_CERT).
    """
    resp, code = api("GET", "keygen")
    r = api_response(resp)
    for field in ("secretKey", "pubKey", "certificate"):
        value = r.get(field)
        if isinstance(value, str) and value.strip():
            if field != "secretKey":
                warn("keygen отдал %s вместо secretKey — панель старее 3.x" % field)
            return value.strip()
    err("Панель не отдала ключ ноды (GET keygen, HTTP %s): %s"
        % (code, json.dumps(resp, ensure_ascii=False)[:200]))
    return ""


def create_remnawave_node(api, name, address, prof_uuid, inbound_uuids,
                          country=NODE_COUNTRY):
    """Зарегистрировать ноду в панели. Возвращает SECRET_KEY для неё или ''.

    activeInbounds — uuid инбаундов из ответа профиля, не теги.
    countryCode — только подпись с флагом в панели: без него нода значится
    как Unknown. Ставим страну входа клиента (через российский CDN), а не
    страну, где физически стоит сервер.
    """
    resp, code = api("POST", "nodes", {
        "name": name, "address": address, "port": 2222,
        "countryCode": country,
        "configProfile": {"activeConfigProfileUuid": prof_uuid,
                          "activeInbounds": [u for u in inbound_uuids if u]}})
    r = api_response(resp)
    if not r.get("uuid"):
        err("Панель не создала ноду %s (HTTP %s): %s"
            % (name, code, json.dumps(resp, ensure_ascii=False)[:200]))
        return ""
    say("  Node UUID: %s" % r["uuid"])
    # 2.x отдавал ключ прямо здесь, 3.x — только через keygen
    return r.get("secretKey") or panel_node_secret(api)


def deploy_remnanode_files(secret):
    """Каталог, бинарник xray, compose и .env ноды."""
    run("mkdir -p /opt/remnanode")
    custom_xray = download_xray_binary("/opt/remnanode/xray-custom")
    write_file("/opt/remnanode/docker-compose.yml", remnanode_compose(custom_xray))
    write_file("/opt/remnanode/.env",
               "NODE_PORT=2222\nSECRET_KEY=%s\n" % secret, mode=0o600)


def start_remnanode():
    """docker compose pull + up для remnanode."""
    say("  Качаю образ ноды %s..." % REMNANODE_IMAGE)
    run("cd /opt/remnanode && docker compose pull", timeout=600)
    say("  Запускаю контейнер remnanode...")
    out, rc = run("cd /opt/remnanode && docker compose up -d 2>&1")
    if rc != 0:
        warn("remnanode не запустился: %s" % out.strip()[-200:])
    return rc == 0


def download_xray_binary(dest):
    """Скачать бинарник xray XRAY_MIN_VERSION под bind-mount в remnanode.

    Возвращает True, только если по dest лежит запускаемый файл — вызывающий по
    этому флагу решает, добавлять ли mount в compose (см. remnanode_compose).
    Проверка через `xray version`, а не через `test -x`: на каталоге, который
    docker мог насоздавать на месте пропавшего бинарника, `test -x` проходит.
    """
    _, rc = run("test -f %s && %s version >/dev/null 2>&1" % (shq(dest), shq(dest)))
    if rc == 0:
        ok("Xray %s уже скачан" % XRAY_MIN_VERSION)
        return True
    say("  Скачивание xray %s..." % XRAY_MIN_VERSION)
    arch, _ = run("uname -m")
    zipname = ("Xray-linux-arm64-v8a.zip" if "aarch64" in arch or "arm64" in arch
               else "Xray-linux-64.zip")
    url = ("https://github.com/XTLS/Xray-core/releases/download/v%s/%s"
           % (XRAY_MIN_VERSION, zipname))
    # Распаковка: unzip есть не на всяком образе, python3 — тоже не всюду
    # (сам установщик крутится на ДРУГОЙ машине), поэтому пробуем оба.
    # rm -rf dest перед mv — на случай каталога от прошлой сломанной установки.
    # Каталог — через mktemp: фиксированное имя в /tmp под root позволяет
    # подложить симлинк, и curl -o перезапишет чужой файл.
    d = shq(dest)
    out, rc = run(
        "T=$(mktemp -d) && cd \"$T\" && curl -fsSL -o xray_dl.zip %s && "
        "( unzip -o -q xray_dl.zip xray || "
        "python3 -c \"import zipfile;zipfile.ZipFile('xray_dl.zip').extract('xray')\" ) && "
        "rm -rf %s && mv xray %s && chmod +x %s && test -x %s; "
        "rc=$?; cd / && rm -rf \"$T\"; exit $rc"
        % (shq(url), d, d, d, d), timeout=300)
    if rc != 0:
        warn("Не удалось скачать xray: %s" % out[:120])
        say("     Нода поедет на xray из образа remnanode")
        return False
    ok("Xray %s готов" % XRAY_MIN_VERSION)
    return True


def detect_ssh_ports():
    """Порты sshd — чтобы политика deny incoming не отрезала доступ к серверу.

    Одного sshd_config мало: на Ubuntu 22.10+ порт живёт в sshd_config.d/ или
    в ssh.socket, и чтение только основного файла давало 22 при sshd на 2222 —
    ufw enable после этого закрывал SSH. Поэтому объединяем источники:
    `sshd -T` (разворачивает Include), сам sshd_config и порт ТЕКУЩЕЙ
    SSH-сессии из $SSH_CONNECTION — тот, через который мы сейчас работаем;
    плюс ListenStream у ssh.socket, если sshd запускается сокетом.
    """
    out, _ = run("{ sshd -T 2>/dev/null | awk '$1==\"port\"{print $2}'; "
                    "awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2}' "
                    "/etc/ssh/sshd_config 2>/dev/null; "
                    "systemctl show -p Listen ssh.socket 2>/dev/null "
                    "| grep -oE '[0-9]+ \\(Stream\\)' | cut -d' ' -f1; "
                    "echo \"${SSH_CONNECTION##* }\"; }")
    ports = {int(p) for p in out.split() if p.isdigit() and 0 < int(p) < 65536}
    return sorted(ports) or [22]


def ufw_active():
    out, _ = run("ufw status 2>/dev/null")
    return "Status: active" in out or "активен" in out


def persist_iptables():
    """Сохранить правила iptables, иначе они исчезнут после перезагрузки."""
    run("echo 'iptables-persistent iptables-persistent/autosave_v4 boolean true' "
           "| debconf-set-selections; "
           "echo 'iptables-persistent iptables-persistent/autosave_v6 boolean true' "
        "| debconf-set-selections; "
        + APT_GET + " install -y -qq iptables-persistent >/dev/null 2>&1")
    _, rc = run("netfilter-persistent save >/dev/null 2>&1")
    if rc != 0:
        # без пакета — сохраняем дамп руками, восстановление на старте сети
        _, rc = run("mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4")
    if rc == 0:
        ok("Правила iptables сохранены (переживут перезагрузку)")
    else:
        warn("Не удалось сохранить правила iptables — после ребута их не будет.\n"
             "     Проверь вручную: netfilter-persistent save")
    return rc == 0


def _is_loopback(addr):
    """Адрес из ss: '127.0.0.53%lo', '[::1]', '[::ffff:127.0.0.1]' — только локальные."""
    a = addr.strip("[]").split("%")[0]
    return a.startswith("127.") or a == "::1" or a.startswith("::ffff:127.")


def listening_ports():
    """Порты, которые сервер прямо сейчас слушает не на loopback.

    Возвращает {"tcp": set, "udp": set}. Нужны режиму 3: там фронт ставится
    перед уже работающей нодой, и её порты (2222 для панели и всё, что она
    слушает ещё) должны пережить включение deny incoming.
    """
    found = {}
    for proto, flag in (("tcp", "t"), ("udp", "u")):
        out, _ = run("ss -l%snH 2>/dev/null" % flag)
        ports = set()
        for line in out.splitlines():
            cols = line.split()
            if len(cols) < 5:
                continue
            addr, _, port = cols[3].rpartition(":")
            if port.isdigit() and not _is_loopback(addr):
                ports.add(int(port))
        found[proto] = ports
    return found


def firewall_setup(keep_listening=False):
    """ufw с политикой deny incoming: наружу открыты только SSH и 80/443.

    Порт sshd открывается ПЕРВЫМ и только потом включается политика, иначе
    установка обрывает сама себя вместе с SSH-сессией.

    keep_listening — сервер уже работает (режим 3), и ломать его нельзя:
    включённый ufw не трогаем вовсе, кроме 80/443, а при выключенном
    оставляем открытым всё, что уже слушает наружу. Иначе deny incoming
    закрыл бы и порт 2222 панели, и остальные входы работающей ноды.
    """
    if run("which ufw")[1] != 0:
        pkg_install("ufw")
    if run("which ufw")[1] != 0:
        warn("ufw не установился — базовый файрвол не настроен")
        return False
    if keep_listening and ufw_active():
        for p in (80, 443):
            run("ufw allow %d/tcp >/dev/null 2>&1" % p)
        ok("ufw уже включён — его правила не тронуты, добавлены только 80/443")
        return True
    ssh_ports = detect_ssh_ports()
    tcp = set(ssh_ports) | {80, 443}
    udp = set()
    if keep_listening:
        live = listening_ports()
        kept = sorted((live["tcp"] - tcp)) + sorted(live["udp"] - udp)
        tcp |= live["tcp"]
        udp |= live["udp"]
        if kept:
            say("  Оставляю открытыми порты, которые уже слушаются: %s"
                % ", ".join(map(str, kept)))
    for p in sorted(tcp):
        run("ufw allow %s/tcp >/dev/null 2>&1" % p)
    for p in sorted(udp):
        run("ufw allow %s/udp >/dev/null 2>&1" % p)
    run("ufw default deny incoming >/dev/null 2>&1")
    run("ufw default allow outgoing >/dev/null 2>&1")
    run("ufw --force enable >/dev/null 2>&1")
    if ufw_active():
        ok("Файрвол: deny incoming, открыты SSH %s, 80, 443"
           % "/".join(map(str, ssh_ports)))
        return True
    warn("ufw не включился — правила не применены")
    return False


def restrict_node_port_2222(panel_ip):
    """Порт ноды 2222 доступен только панели.

    При активном ufw правила уходят в него (переживают перезагрузку сами),
    иначе — сырой iptables с последующим сохранением.
    """
    ip = (panel_ip or "").strip()
    if not is_ipv4(ip):
        # ahostsv4, а не hosts: у домена с AAAA getent hosts отдаёт IPv6,
        # is_ipv4 его не пропускает, и порт 2222 оставался открытым всем
        out, _ = run("getent ahostsv4 %s | awk 'NR==1{print $1}'" % shq(ip))
        ip = out.strip()
    if not is_ipv4(ip):
        warn("Не удалось определить IP панели из '%s' — порт 2222 оставлен открытым"
             % panel_ip)
        return
    if ufw_active():
        run("ufw allow from %s to any port 2222 proto tcp >/dev/null 2>&1" % ip)
        run("ufw allow from 172.16.0.0/12 to any port 2222 proto tcp >/dev/null 2>&1")
        run("ufw deny 2222/tcp >/dev/null 2>&1")
        ok("Порт 2222 ограничен через ufw: панель %s" % ip)
        return
    # Идемпотентно: -C проверяет наличие правила, добавляем только если нет,
    # иначе повторные запуски скрипта плодят дубликаты в INPUT.
    def _rule(spec, where="-I"):
        run("iptables -C INPUT %s 2>/dev/null || iptables %s INPUT %s"
               % (spec, where, spec))
    _rule("-p tcp --dport 2222 -s %s -j ACCEPT" % ip)
    _rule("-p tcp --dport 2222 -s 127.0.0.1 -j ACCEPT")
    _rule("-p tcp --dport 2222 -s 172.16.0.0/12 -j ACCEPT")
    _rule("-p tcp --dport 2222 -j DROP", where="-A")
    ok("Порт 2222 ограничен: панель %s" % ip)
    persist_iptables()


def node_wait_ready():
    """Дождаться 'XRay Core' в логах remnanode (нода запустилась)."""
    say("  Ожидание запуска ноды...")
    for _ in range(24):
        out, _ = run("docker logs remnanode --tail=15 2>&1")
        if "XRay Core" in out or "is up and running" in out:
            ok("Нода запущена!")
            return True
        time.sleep(5)
    warn("Нода не отрапортовала о запуске — проверь: docker logs remnanode")
    return False


def node_reload_clients():
    """Перезапустить ноду, чтобы она сразу забрала пользователей из панели.

    Конфиг нода получает при старте, а юзер создаётся позже — на свежей
    установке она остаётся с пустым списком клиентов. Панель дошлёт его сама,
    но не сразу, и всё это время клиент подключается «успешно» и не передаёт
    ни байта: nginx отдаёт 200 на каждый запрос, а xray рвёт поток на
    авторизации, потому что такого id он не знает. Перезапуск убирает это
    окно: на старте нода запрашивает конфиг заново, уже с юзером.
    """
    say("  Перезапуск ноды, чтобы она забрала пользователей...")
    _, rc = run("docker restart remnanode", timeout=120)
    if rc != 0:
        warn("нода не перезапустилась — пользователи появятся на ней с задержкой")
        say("  Если сразу после установки соединение есть, а трафика нет: "
            "docker restart remnanode")
        return False
    return node_wait_ready()


def build_xray_profile(name, inbounds):
    """Тело POST /api/config-profiles.

    Панель 3.x ждёт целый конфиг Xray в поле config — плоское {name, inbounds}
    отбивается валидацией («expected object, received undefined» по пути
    config). Пустой inbounds она тоже не берёт: конфиг без входов невалиден
    для xray, и создание падает с A112.
    """
    return {"name": name, "config": {
        "log": {"loglevel": "warning"},
        # DNS через 8.8.8.8 и только IPv4: без этого xray на серверах с
        # кривым IPv6 упирается в таймауты резолва
        "dns": {"servers": [{"address": "8.8.8.8", "skipFallback": False}],
                "queryStrategy": "UseIPv4"},
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom"},
                      {"tag": "block", "protocol": "blackhole"}],
        # Локальные сети — напрямую, торренты — в блок: жалобы abuse на exit-IP
        # это главное, из-за чего теряют и сервер, и CDN-аккаунт
        "routing": {"rules": [
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}]}}}


def create_config_profile(api, name, inbounds, tries=3):
    """Создать профиль. Возвращает (uuid профиля, {тег: uuid инбаунда}).

    Панель раздаёт каждому инбаунду собственный uuid, и дальше на него
    ссылаются и сквад, и нода — теги для этого не годятся.
    api(method, path, data) -> (resp, code): работает и локально, и по SSH.
    """
    resp, code = None, 0
    base_name = name        # хвост к занятому имени — к исходному, а не к прошлому хвосту
    for attempt in range(tries):
        resp, code = api("POST", "config-profiles", build_xray_profile(name, inbounds))
        # Имя профиля осмысленное (CDN-YANDEX), а на чужой панели такое
        # может уже существовать: тогда добавляем хвост и пробуем ещё раз
        if code in (400, 409) and re.search(
                r"exist|unique|taken|занят", json.dumps(resp), re.I):
            name = "%s-%s" % (base_name, rand(4, LOWER_ALNUM))
            say("  Профиль с таким именем уже есть — беру «%s»" % name)
            continue
        if code != 0:
            break            # ответ получен — повтор его не изменит
        if attempt + 1 < tries:      # после последней попытки ждать нечего
            say("  API не ответил (%d/%d), жду 10 сек..." % (attempt + 1, tries))
            time.sleep(10)
    if code not in (200, 201):
        warn("Профиль отвергнут: %s" % json.dumps(resp)[:160])
    r = api_response(resp)
    prof_uuid = r.get("uuid")
    tag2uuid = {i.get("tag"): i.get("uuid") for i in (r.get("inbounds") or [])}
    if not prof_uuid:
        warn("Ответ создания профиля: %s" % json.dumps(resp)[:200])
    else:
        say("  Profile UUID: %s" % prof_uuid)
        ok("Инбаундов в профиле: %d (%s)"
           % (len(tag2uuid), ", ".join(sorted(t for t in tag2uuid if t))))
    return prof_uuid, tag2uuid


def create_remnawave_host(api, prof_uuid, inbound_tag, cdn_domain, path,
                          inbound_uuid=None, remark=None):
    """Создать CDN-хост и привязать к профилю/инбаунду.

    Привязка едет ВЛОЖЕННЫМ объектом inbound — так с 3.4: плоские
    configProfileUuid/configProfileInboundUuid панель отвергает целиком
    («Validation failed», path ["inbound"], expected object), и хост не
    создавался вовсе.

    Имя поля xhttp-extra в разных ревизиях панели пишется то xhttpExtraParams,
    то xHttpExtraParams. Ставим ОБА — лишнее валидатор срезает.
    api(method, path, data) -> (resp, code): работает и локально, и по SSH.
    """
    if not prof_uuid:
        warn("нет profile_uuid — хост CDN не создан")
        return None
    host = {
        "inbound": {"configProfileUuid": prof_uuid,
                    "configProfileInboundUuid": inbound_uuid},
        "remark": remark or "CDN %s" % cdn_domain,
        "address": cdn_domain,
        "port": 443,
        # SNI и Host — домен CDN, а не origin: клиент открывает TLS именно к
        # CDN, и его сертификат выписан на этот домен. С origin в SNI
        # соединение отвалится по имени.
        "sni": cdn_domain,
        "host": cdn_domain,
        "path": tunnel_dir(path),
        "alpn": "h3,h2,http/1.1",
        "fingerprint": "random",
        # Клиенту — тот же набор, что и ноде: иначе он шлёт POST и обычный
        # паддинг, а CDN и xray это отбивают (405 и 400 соответственно)
        "xhttpExtraParams": xhttp_settings(path),
        "xHttpExtraParams": xhttp_settings(path),
        "securityLayer": "TLS",
    }
    resp, _ = api("POST", "hosts", host)
    huuid = api_response(resp).get("uuid")
    if huuid:
        ok("Host UUID: %s — привязан к ноде" % huuid)
    else:
        warn("Хост CDN не создан — клиенту некуда подключаться:")
        say("  " + json.dumps(resp, ensure_ascii=False)[:400])
    return huuid


def update_host_address(api, host_uuid, cdn_domain, remark=None):
    """Переставить хост на домен CDN, когда провайдер его наконец выдал.

    Хост создаётся до настройки CDN — там ещё нечего прописать, кроме origin,
    а клиент по такому адресу пошёл бы мимо CDN прямо на сервер и заодно
    засветил бы его IP. Домен известен только в конце, поэтому адрес, SNI и
    Host правим отдельным запросом.
    """
    if not (host_uuid and cdn_domain):
        return False
    resp, code = api("PATCH", "hosts", {
        "uuid": host_uuid,
        "remark": remark or "CDN %s" % cdn_domain,
        "address": cdn_domain,
        "sni": cdn_domain,
        "host": cdn_domain,
    })
    if code in (200, 201):
        ok("Хост в панели переставлен на CDN-домен %s" % cdn_domain)
        return True
    warn("Не удалось переставить хост на %s: %s"
         % (cdn_domain, json.dumps(resp)[:160]))
    say("  Поправь адрес хоста в панели вручную — сейчас там origin")
    return False


def find_default_squad(api):
    """Сквад Default-Squad целиком (иначе первый попавшийся) или None.

    Возвращается весь объект, а не только uuid: обновление сквада требует
    полного списка его инбаундов, иначе чужие потерялись бы.
    """
    resp, _ = api("GET", "internal-squads")
    squads = [s for s in (api_response(resp).get("internalSquads") or [])
              if isinstance(s, dict) and s.get("uuid")]
    if not squads:
        return None
    for s in squads:
        if s.get("name") == "Default-Squad":
            return s
    return squads[0]


def squad_inbound_uuids(squad):
    """uuid инбаундов, уже привязанных к скваду (в разных ревизиях — разный вид).

    3.x отдаёт inbounds списком объектов {uuid, tag, ...}, но встречается и
    голый список uuid — берём оба вида и молча пропускаем остальное.
    """
    uuids = []
    for item in (squad.get("inbounds") or []):
        if isinstance(item, dict):
            item = item.get("uuid")
        if isinstance(item, str) and item:
            uuids.append(item)
    return uuids


def add_inbounds_to_squad(api, inbound_uuids):
    """Добавить инбаунды в Default-Squad (иначе нода получает пустой список клиентов).

    Обновление принимается только на корне коллекции: uuid сквада едет в теле,
    инбаунды — своими uuid. PATCH/POST/PUT по пути /internal-squads/<uuid>
    отвечают 404 (проверено на 3.2.3).

    В теле уходит ПОЛНЫЙ список инбаундов сквада, поэтому свои uuid
    объединяются с теми, что там уже есть. Раньше отправлялись только свои —
    на существующей панели (режим 2) это выбрасывало из Default-Squad инбаунды
    чужих нод, и их пользователи теряли подключения.
    """
    squad = find_default_squad(api)
    if not squad:
        warn("Default-Squad не найден")
        return
    mine = [u for u in (inbound_uuids or []) if u]
    if not mine:
        warn("нет uuid инбаундов — сквад не обновлён")
        return
    existing = squad_inbound_uuids(squad)
    merged = existing + [u for u in mine if u not in existing]
    if len(merged) == len(existing):
        ok("Инбаунды уже в Default-Squad")
        return
    resp, code = api("PATCH", "internal-squads",
                     {"uuid": squad["uuid"], "inbounds": merged})
    if code in (200, 201):
        ok("%d инбаунд(ов) добавлено в Default-Squad (всего %d)"
           % (len(merged) - len(existing), len(merged)))
    else:
        warn("Не удалось добавить инбаунды в сквад: %s" % json.dumps(resp)[:160])


def create_remnawave_user(api, username, vless_uuid, domain):
    """Создать юзера user1 и вернуть URL подписки."""
    squad = find_default_squad(api)
    body = {
        "username": username,
        "vlessUuid": vless_uuid,
        "trafficLimitBytes": 0,
        "expireAt": "2099-12-31T23:59:59.000Z",
        "activeInternalSquads": [squad["uuid"]] if squad else [],
    }
    resp, _ = api("POST", "users", body)
    r = api_response(resp)
    short = r.get("shortUuid") or ""
    # 3.x не кладёт в ответ uuid — признак успеха тут shortUuid, по нему и
    # строится подписка. Раньше по отсутствию uuid печаталось предупреждение
    # о «неудаче» при полностью созданном пользователе.
    if short:
        ok("Юзер %s создан, Short: %s" % (username, short))
    else:
        warn("Юзер не создан — подписки не будет:")
        say("  " + json.dumps(resp, ensure_ascii=False)[:400])
    # Панель может выдать клиенту свой vless-uuid: в ссылку должен уйти именно
    # он, иначе клиент подключается с id, которого нода не знает.
    real_uuid = r.get("vlessUuid") or vless_uuid
    if real_uuid != vless_uuid:
        say("  Панель выдала свой VLESS UUID: %s" % real_uuid)
    return ("https://%s/api/sub/%s" % (domain, short) if short else ""), real_uuid


# ─────────────────────────────────────────────────────────────────────────────
#  Let's Encrypt (certbot webroot)
# ─────────────────────────────────────────────────────────────────────────────

def le_rate_limited(out):
    """Отказ certbot — это недельный лимит Let's Encrypt, а не сбой проверки.

    Лимит на повторный выпуск одинакового набора имён (5 в неделю) выбирают
    несколько переустановок подряд. Повторять попытки бесполезно, а молчаливое
    «certbot не прошёл» отправляет искать проблему в DNS, которого тут нет.
    """
    low = (out or "").lower()
    return "too many certificates" in low or "ratelimited" in low


def issue_le_cert(domain, crt=CDN_CRT, key=CDN_KEY):
    """Выпустить LE через certbot webroot, скопировать в cdn.crt/cdn.key.

    Requires nginx с location /.well-known/acme-challenge/ -> /var/www/certbot.
    Возвращает True при успехе.
    """
    pkg_install("certbot")
    run("mkdir -p /var/www/certbot")
    # дождаться, пока DNS домена укажет на этот сервер
    myip = get_ip()
    for _ in range(12):
        # ahostsv4: при AAAA-записи getent hosts отдаёт IPv6, и сравнение с
        # IPv4 сервера не сходилось никогда — две минуты ожидания впустую
        out, _ = run("getent ahostsv4 %s | awk 'NR==1{print $1}'" % shq(domain))
        if out.strip() == myip:
            break
        say("  жду DNS %s -> %s ..." % (domain, myip))
        time.sleep(10)
    for attempt in range(3):
        say("  certbot: запрашиваю сертификат для %s (попытка %d из 3)..."
            % (domain, attempt + 1))
        out, _ = run("certbot certonly --webroot -w /var/www/certbot -d %s "
                     "--non-interactive --agree-tos "
                     "--register-unsafely-without-email 2>&1" % shq(domain),
                     timeout=180)
        live = "/etc/letsencrypt/live/%s" % domain
        if os.path.isfile(live + "/fullchain.pem"):
            # crt=None — копия не нужна: vhost смотрит прямо в live-каталог,
            # тогда и продление подхватывается без deploy-хука.
            if crt:
                run("cp %s/fullchain.pem %s && cp %s/privkey.pem %s && "
                       "nginx -s reload 2>/dev/null; docker restart remnanode 2>/dev/null || true"
                       % (live, crt, live, key))
                # deploy-hook на автопродление
                hook = ("#!/bin/bash\ncp %s/fullchain.pem %s\ncp %s/privkey.pem %s\n"
                        "nginx -s reload\ndocker restart remnanode 2>/dev/null || true\n"
                        % (live, crt, live, key))
                write_file("/etc/letsencrypt/renewal-hooks/deploy/cert.sh",
                           hook, mode=0o755)
            else:
                run("nginx -s reload 2>/dev/null || true")
            ok("Сертификат LE получен для %s" % domain)
            return True
        if le_rate_limited(out):
            # Повторы бессмысленны: лимит недельный, он не «отпустит» через 20 с
            warn("Let's Encrypt: лимит на %s исчерпан" % domain)
            say("  5 сертификатов в неделю на один и тот же набор имён — "
                "обычно упираются после нескольких переустановок подряд")
            say("  Обход: поставить панель на другой поддомен, например "
                "--domain panel2.%s — у него свой счётчик" % domain)
            break
        say("  certbot не прошёл (попытка %d/3), повтор через 20с..." % (attempt + 1))
        if attempt + 1 < 3:      # после последней попытки ждать нечего
            time.sleep(20)
    warn("сертификат для %s не выпущен — self-signed" % domain)
    return False


def setup_panel_web(cfg, xport, path):
    """nginx (или caddy) перед панелью и CDN-origin: режим 1, всё на одном сервере.

    Схема снята с работающего сервера: panel.conf на server_name <домен>
    проксирует в 127.0.0.1:3000, а default_server отдаёт CDN-origin на
    origin.<домен> и заглушку на всё остальное. Панель светит сертификат
    браузеру, поэтому её vhost смотрит прямо в /etc/letsencrypt/live —
    продление подхватывается само. Origin остаётся на cdn.crt: его CDN всё
    равно не проверяет.
    """
    domain = panel_host(cfg)
    origin = cfg.get("origin_domain", cfg["domain"])
    step("nginx: панель и CDN")
    say("  Порядок: пакеты → самоподписанный сертификат → конфиги → "
        "Let's Encrypt для панели и origin")
    pkg_install("nginx openssl curl ca-certificates certbot")
    ensure_nginx_base()
    self_signed_cert(origin)      # чтобы nginx поднялся до выпуска LE
    write_decoy(origin)
    if apply_origin_front(cfg, xport, path,
                          panel_domain=domain, panel_port=PANEL_PORT) == "caddy":
        ok("caddy: CDN :443 -> 127.0.0.1:%d + панель %s (авто-TLS)" % (xport, domain))
        return
    nginx_write_conf("panel.conf", nginx_panel_proxy(domain, PANEL_PORT))
    ok("nginx: CDN :443 -> 127.0.0.1:%d, панель %s -> 127.0.0.1:%d"
       % (xport, domain, PANEL_PORT))
    # LE для домена панели: без копирования, vhost переписываем на live-пути
    if issue_le_cert(domain, crt=None, key=None):
        live = "/etc/letsencrypt/live/%s" % domain
        nginx_write_conf("panel.conf", nginx_panel_proxy(
            domain, PANEL_PORT, live + "/fullchain.pem", live + "/privkey.pem"))
        ok("Панель на сертификате Let's Encrypt")
    else:
        warn("Панель осталась на self-signed — браузер будет ругаться")
    upgrade_origin_cert(origin, skip=cfg.get("no_origin_le"))


def upgrade_origin_cert(origin_domain, skip=False):
    """Заменить self-signed на Let's Encrypt для origin, если получится.

    Self-signed CDN не может проверить — у провайдера приходится включать
    «игнорировать сертификат origin», то есть канал шифруется, но origin не
    аутентифицируется. С настоящим LE этого костыля не нужно. Вызывать ПОСЛЕ
    старта nginx: certbot ходит через /.well-known/acme-challenge/.
    При неудаче остаётся self-signed — установка не прерывается.
    """
    if skip:
        say("  Let's Encrypt для источника не выпускаю — CDN к нему по HTTPS "
            "не ходит (переспорить: --origin-le)")
        return False
    say("  Пробую выпустить Let's Encrypt для origin %s..." % origin_domain)
    if issue_le_cert(origin_domain):
        # Выпущенный сертификат публикуется в CT-логах: имя origin становится
        # видно через поиск вроде crt.sh, и случайный поддомен уже не прячет
        # сервер. Кому это важно — ставить с --no-origin-le.
        say("  Имя %s теперь видно в публичных CT-логах сертификатов; "
            "чтобы не светить его — ставь с --no-origin-le" % origin_domain)
        run("chmod 600 %s" % shq(CDN_KEY))
        return True
    say("  Остаётся self-signed — у CDN-провайдера включи "
        "«игнорировать сертификат origin»")
    return False


def nginx_panel_proxy(domain, upstream_port, crt=CDN_CRT, key=CDN_KEY):
    """nginx-конфиг для проксирования панели (80->443 redirect + proxy)."""
    return CONF_MARK + """
server {
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
}
""" % (domain, domain, crt, key, upstream_port)


# ─────────────────────────────────────────────────────────────────────────────
#  Инструкции по настройке CDN (ручной шаг у провайдера)
# ─────────────────────────────────────────────────────────────────────────────

def print_cdn_instructions(provider, origin, client_domain, my_ip, path):
    """Инструкция провайдеру — с подставленными значениями, а не примерами.

    client_domain — домен, который увидят клиенты; он обязателен: вашего
    сертификата на техническом домене Yandex нет.
    """
    print("", flush=True)
    print("  " + _c("1;" + C_TITLE, "Настройка CDN у провайдера")
          + _c(C_DIM, " · %s" % provider), flush=True)
    hr()
    say("  Origin:              %s   (A -> %s)" % (origin, my_ip))
    if client_domain:
        say("  Домен для клиентов:  %s" % client_domain)
    say("  Путь туннеля:        /%s/\n" % path.strip("/"))

    if provider == "yandex":
        cert = (client_domain or "").replace(".", "-")
        say("""  ШАГ 1 · Сертификат на клиентский домен
  console.yandex.cloud -> Certificate Manager -> Создать сертификат
       - Имя:            %s
       - Домены:         %s
       - Тип проверки:   DNS
  Yandex покажет запись для проверки. Заведите её у DNS-провайдера так
  (в Cloudflare: Add record; ИМЯ слева, ЧУЖОЕ значение справа):
       Type:   CNAME
       Name:   _acme-challenge.%s
               (в Cloudflare зону дописывать не надо)
       Target: <значение со страницы сертификата>.cm.yandexcloud.net
       Proxy:  DNS only, серое облачко
  Значение копируйте кнопкой со страницы сертификата: строка длинная и
  бессмысленная, руками её набирают с ошибками. В Target идёт именно
  оно, а НЕ ваш домен — иначе запись ведёт сама на себя.
  Проверить:  dig +short _acme-challenge.%s @1.1.1.1
  Должен вернуться домен .cm.yandexcloud.net. Дальше ждите статуса
  "Issued" — это 5-30 минут. После выпуска запись НЕ удалять: по ней
  идёт автопродление сертификата.

  ШАГ 2 · Ресурс
  console.yandex.cloud -> Cloud CDN -> Создать ресурс
  В форме участвуют ДВА разных домена, и поля называются похоже. Три
  поля подряд — про ВАШ СЕРВЕР, и в них одно и то же имя. Четвёртое,
  ниже, — про КЛИЕНТОВ.
    Контент:
       - Запрос контента:        Из одного источника
       - Тип источника:          Сервер
       - Доменное имя источника: %s   <- ВАШ СЕРВЕР
       - Протокол к источникам:  HTTPS
       - Задать SNI вручную:     ВКЛ
       - Имя SNI-хоста:          %s   <- ВАШ СЕРВЕР
       - Заголовок Host:         Своё значение
       - Значение заголовка:     %s   <- ВАШ СЕРВЕР
       - Доменное имя:           %s   <- ДЛЯ КЛИЕНТОВ
    Дополнительно:
       - Тип сертификата:        Сертификат из Certificate Manager
       - Сертификат:             %s
       - Переадресация клиентов: с HTTP на HTTPS
    Кеширование:
       - Кеш CDN:                ВЫКЛ
       - Кеш браузера:           ВЫКЛ
       - Сегментация файлов:     ВЫКЛ
       - Сжатие (Gzip/Brotli):   ВЫКЛ
       - Query-параметры:        НЕ игнорировать
    HTTP-заголовки и методы:
       - Разрешённые методы:     GET, HEAD, OPTIONS
         Отметьте все три. POST в списке нет вовсе, и это не мешает:
         туннель настроен на аплинк GET-запросами.
  Группа источников тут не нужна: она для нескольких серверов. Если
  всё же создаёте ресурс через "Копирование конфигурации" с другого —
  проверьте источник, подтянется чужой, и CDN пойдёт не к вам.

  ШАГ 3 · DNS
  На странице ресурса, внизу, блок "Настройки DNS". Там две строки:
       $ORIGIN %s          <- ваш домен, он уже известен
       CNAME   xxxxxxxx.topology.gslb.yccdn.ru   <- нужно ЭТО
  Вторую и копируйте — её же введёте ниже в ответ на вопрос. Заведите
  запись так:
       Type:   CNAME
       Name:   %s
       Target: <значение из блока "Настройки DNS">
       Proxy:  DNS only, серое облачко
  Правило то же: слева ваше имя, справа чужое. Cloudflare показывает
  итог строкой "<ваш домен> is an alias of <технический>" — если
  написано наоборот, поля перепутаны местами.
  Проверить:  dig +short %s @1.1.1.1

  Ресурс раскатывается по узлам до 15 минут, и всё это время коды ответа
  скачут между 000, 502 и 200 — так и должно быть. Повторные сохранения
  только перезапускают отсчёт.
""" % (cert, client_domain, client_domain, client_domain,
       origin, origin, origin, client_domain, cert,
       client_domain, client_domain, client_domain))


def cdn_dns_records(origin, my_ip, cdn_domain, client_domain=""):
    """Строки DNS-записей под CDN: A на origin и CNAME своего домена.

    Домен CDN провайдер выдаёт технический (xxxxxxxx.topology.gslb.yccdn.ru).
    Если клиентам показывают свой — он направляется на
    технический именно CNAME-записью, A тут не годится: адреса edge-узлов
    провайдер меняет без предупреждения.
    """
    rows = ["A      %s  ->  %s   (источник CDN, DNS only)" % (origin, my_ip)]
    if client_domain and cdn_domain:
        rows.append("CNAME  %s  ->  %s   (домен для клиентов)"
                    % (client_domain, cdn_domain))
    return rows


def ask_domain(prompt, preset=""):
    """Спросить домен, не принимая мусор. '' — пропущено или читать нечего."""
    while True:
        value = (preset or ask(prompt) or "").strip()
        if not value or RE_DOMAIN.match(value):
            return value
        warn("'%s' не похож на домен" % value)
        say_homoglyph_hint(value)
        if preset or not sys.stdin.isatty():
            return ""


def dns_wait(lines, skip=False):
    """Показать нужные DNS-записи и подождать ENTER (если не skip)."""
    callout("DNS-записи в Cloudflare", lines)
    if not skip:
        pause("Enter когда записи созданы")


def pause(msg):
    """Ждать Enter. EOF и Ctrl-C — не повод падать: просто едем дальше."""
    try:
        input("\n  " + _c(C_ACC, "❯") + " " + msg + _c(C_DIM, "  "))
    except (EOFError, KeyboardInterrupt):
        pass


# ─────────────────────────────────────────────────────────────────────────────
#  Режим 2: только нода/CDN к существующей панели (Remnawave, по SSH API)
# ─────────────────────────────────────────────────────────────────────────────

def install_node_only(cfg):
    """Режим 2: нода + CDN-origin на ЭТОМ сервере, панель — существующая, по SSH."""
    step("Проверка подключения к панели")
    panel = {"ip": cfg["panel_url"], "user": cfg.get("panel_ssh_user", "root"),
             "pass": cfg.get("panel_ssh_pass", ""), "key": cfg.get("panel_key")}
    # sshpass нужен ДО первого run_remote — на чистой ноде его ещё нет
    if not panel["key"] and not ensure_sshpass():
        sys.exit(1)
    out, _ = run_remote(panel, "echo ok")
    if "ok" not in out:
        err("SSH к панели %s не удался" % panel["ip"])
        if out.strip():
            say("  " + out.strip().splitlines()[-1][:200])
        sys.exit(1)
    ok("SSH к панели: OK")
    token = resolve_panel_token(panel, cfg)
    if not token:
        sys.exit(1)
    api = functools.partial(rw_api_ssh, panel, token)

    origin = cfg.get("origin_domain", cfg["domain"])
    path = cfg["path"]

    step("Подготовка системы")
    pkg_install("nginx openssl curl ca-certificates gnupg certbot")
    tune_os()
    ensure_nginx_base()
    self_signed_cert(origin)
    write_decoy(origin)
    # Без docker нода не поднимется, а профиль и нода в панели уже были бы
    # созданы — останавливаемся до первого обращения к API
    require_docker()

    # создать профиль/инбаунд/ноду через API панели, поднять remnanode здесь
    step("Создание профиля через API панели")
    user_uuid = str(_uuid.uuid4())
    xport = XHTTP_PORT
    inbounds = build_node_inbounds(cfg, xport, path)
    prof_uuid, tag2uuid = create_config_profile(api, profile_name(cfg["cdn"]),
                                                inbounds)
    inbound_uuids = inbound_uuids_of(inbounds, tag2uuid)

    my_ip = get_ip()
    # К чужой панели нода приезжает не одна: адрес в имени отличает её от
    # соседних локаций
    secret = create_remnawave_node(api, "%s-%s" % (NODE_NAME, my_ip), my_ip,
                                   prof_uuid, inbound_uuids)
    # Без secretKey remnanode поднимется, но панель его не признает: получилась
    # бы установка, которая «прошла», а трафика через ноду нет. Останавливаемся
    # здесь — на этом сервере ещё ничего не запущено, откатывать нечего.
    if not secret:
        say("  Профиль в панели создан, но без secretKey нода работать не будет")
        say("  Проверь доступность панели %s и срок жизни токена" % panel["ip"])
        sys.exit(1)
    deploy_remnanode_files(secret)
    if apply_origin_front(cfg, xport, path) == "nginx":
        upgrade_origin_cert(origin, skip=cfg.get("no_origin_le"))
    firewall_setup()
    # Панель стоит на другом сервере и стучится к ноде на 2222 снаружи: без этого
    # правила политика deny incoming закрывает порт вообще для всех, и нода
    # появляется в панели, но остаётся неуправляемой.
    restrict_node_port_2222(panel["ip"])
    start_remnanode()
    node_wait_ready()
    ok("Нода подключена к панели %s" % panel["ip"])

    step("Создание хоста, сквада и юзера на панели")
    pdom, _ = run_remote(panel, env_grep_cmd("PANEL_DOMAIN"))
    host_uuid, sub_url, user_uuid = publish_for_clients(
        api, cfg, prof_uuid, inbounds, tag2uuid, user_uuid,
        pdom.strip() or panel["ip"])
    node_reload_clients()
    return {"user_uuid": user_uuid, "prof_uuid": prof_uuid, "my_ip": my_ip,
            "sub_url": sub_url, "host_uuid": host_uuid, "api": api}


# ─────────────────────────────────────────────────────────────────────────────
#  Режим 3: только CDN-origin
# ─────────────────────────────────────────────────────────────────────────────


def install_cdn_only(cfg):
    """Режим 3: только origin-фронт CDN перед уже работающей нодой на ЭТОМ сервере.

    Не трогает панель и docker-ноду — поднимает фронт (nginx, либо caddy при
    --front caddy) с self-signed сертом и заглушкой на upstream
    127.0.0.1:<xport> с путём <path> и печатает инструкцию провайдеру."""
    origin = cfg.get("origin_domain", cfg["domain"])
    xport = cfg["xport"]
    path = cfg["path"]
    step("Установка CDN-фронта")
    say("  Upstream: 127.0.0.1:%d   path: %s   фронт: %s"
        % (xport, path, cfg.get("front", "nginx")))
    self_signed_cert(origin)
    write_decoy(origin)
    # Подъём фронта и откат caddy->nginx живут в apply_origin_front — здесь
    # раньше лежала его вторая копия, которая при этом забывала поднять
    # worker_connections в nginx.conf.
    front = apply_origin_front(cfg, xport, path)
    if front == "nginx":
        upgrade_origin_cert(origin, skip=cfg.get("no_origin_le"))
    firewall_setup(keep_listening=True)     # нода уже работает — её порты не закрывать
    ok("CDN-фронт (%s) поднят на :443 -> 127.0.0.1:%d" % (front, xport))
    return {}


# ─────────────────────────────────────────────────────────────────────────────
#  Аргументы и главный сценарий
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse CLI args for non-interactive mode."""
    p = argparse.ArgumentParser(description="CDN Installer v%s" % INSTALLER_VERSION)
    p.add_argument("--mode", help="1=Panel+node here, "
                   "2=Node+CDN to existing panel, 3=CDN origin only")
    # Панель только Remnawave: флаг остался ради старых команд (--panel 1)
    p.add_argument("--panel", help=argparse.SUPPRESS)
    # Провайдер остался один; флаг принимается, чтобы не ломать старые команды.
    p.add_argument("--cdn", help=argparse.SUPPRESS)
    p.add_argument("--front", choices=["nginx", "caddy"], default="nginx",
                   help="Origin-фронт: nginx (по умолчанию) или caddy "
                        "(в режиме с панелью caddy обслуживает и панель "
                        "с авто-TLS)")
    p.add_argument("--domain", help="Domain name")
    p.add_argument("--path", help="Existing xhttp path (mode 3 CDN-only), e.g. /abc123")
    p.add_argument("--xport", type=int,
                   help="Existing local xray upstream port on 127.0.0.1 (mode 3 CDN-only)")
    # --node-key — прежнее имя ключа к панели (когда-то он же вёл на удалённую
    # ноду). Принимается молча, чтобы не ломать чужие команды.
    p.add_argument("--panel-key", "--node-key", dest="panel_key",
                   help="Path to SSH private key for the panel (mode 2)")
    p.add_argument("--panel-url", help="Panel IP (mode 2)")
    # Секреты берутся и из окружения (SECRET_ENV): значение флага видно в ps
    # всем пользователям сервера и оседает в истории shell.
    p.add_argument("--panel-token", default=os.environ.get("CDN_PANEL_TOKEN"),
                   help="Remnawave API token (mode 2), или $CDN_PANEL_TOKEN. "
                   "Если не задан — берётся /opt/remnawave/.panel_token с панели, "
                   "иначе логин по --panel-user/--panel-pass")
    p.add_argument("--panel-user", help="Panel Remnawave username (mode 2)")
    p.add_argument("--panel-pass", default=os.environ.get("CDN_PANEL_PASS"),
                   help="Panel Remnawave password (mode 2), или $CDN_PANEL_PASS")
    p.add_argument("--panel-ssh-user", default="root", help="Panel SSH user (mode 2)")
    p.add_argument("--panel-ssh-pass", default=os.environ.get("CDN_PANEL_SSH_PASS"),
                   help="Panel SSH password (mode 2), или $CDN_PANEL_SSH_PASS")
    # Hysteria2 убран: это отдельный проект, а не протокол xray-core, и нода
    # запускает стоковый xray. Флаг принимается молча, чтобы не ломать старые
    # команды в чужих скриптах.
    p.add_argument("--no-hy2", action="store_true", help=argparse.SUPPRESS)
    # Запасной gRPC Reality-вход убран: флаг принимается молча, чтобы не
    # ломать старые команды и автозапуски.
    p.add_argument("--no-grpc", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--no-origin-le", action="store_true",
                   help="Не выпускать Let's Encrypt для источника "
                   "(оставить самоподписанный)")
    p.add_argument("--wipe", action="store_true",
                   help="Снести прошлую установку без вопросов. Без терминала "
                   "(пайп, cron) снос без этого флага не делается вовсе")
    p.add_argument("--no-wipe", action="store_true",
                   help="Не трогать прошлую установку (ставить поверх)")
    p.add_argument("--fresh", action="store_true",
                   help="Забыть сохранённый прогресс и начать с нуля")
    p.add_argument("--origin-domain", help="Домен источника для CDN. Без него "
                   "берётся случайный поддомен вида a7f3k2.<домен>")
    p.add_argument("--panel-domain", help="Домен панели. Без него берётся "
                   "случайный поддомен вида k9x2mt.<домен>")
    p.add_argument("--cdn-domain", help="Технический домен ресурса CDN "
                   "(вида xxxxxxxx.topology.gslb.yccdn.ru) — иначе спросим в конце")
    p.add_argument("--client-domain", help="Свой домен для клиентов: CNAME на "
                   "технический домен CDN. Без него клиенты идут на технический")
    p.add_argument("--skip-dns-wait", action="store_true")
    p.add_argument("--skip-cdn-wait", action="store_true")
    return p.parse_args()


SECRET_ENV = {"--panel-pass": "CDN_PANEL_PASS",
              "--panel-ssh-pass": "CDN_PANEL_SSH_PASS",
              "--panel-token": "CDN_PANEL_TOKEN"}


def warn_secret_flags(argv):
    """Предупредить о секретах в командной строке и подсказать замену."""
    for flag, var in SECRET_ENV.items():
        if any(a == flag or a.startswith(flag + "=") for a in argv):
            warn("%s в командной строке виден в ps и в истории shell — "
                 "передай его через окружение: %s" % (flag, var))
            say("  read -rs %s && export %s && sudo --preserve-env=%s python3 ..."
                % (var, var, var))


def check_mode_renumbering(mode):
    """Предупредить про смену нумерации режимов (был «панель + удалённая нода»).

    Старый режим 2 (нода на другом сервере по SSH) убран, режимы сдвинулись:
    3 -> 2 и 4 -> 3. Команда `--mode 3` из старого скрипта сделала бы теперь не
    то, что делала раньше, поэтому о ней говорим вслух, а несуществующий
    `--mode 4` объясняем вместо глухого «режим не существует».
    """
    if mode == "4":
        err("Режим 4 больше не существует: нумерация сдвинулась, "
            "«только CDN» — это теперь --mode 3")
        sys.exit(1)
    if mode == "3":
        warn("Нумерация режимов изменилась: --mode 3 теперь «только CDN», "
             "а «нода + CDN к существующей панели» — это --mode 2")
        if sys.stdin.isatty() and not confirm("Ставить «только CDN»? (y/N)",
                                              default=False):
            say("  Перезапусти с нужным номером режима")
            sys.exit(1)
    return mode


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


STATE_PATH = "/var/lib/node-installer-cdn/state.json"
_STATE = {"answers": {}, "done": [], "values": {}}
_RESUME = False          # True, когда продолжаем прошлый запуск


def state_load():
    """Прочитать состояние прошлого запуска. Возвращает True, если оно есть."""
    global _STATE
    try:
        with open(STATE_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("answers") is not None:
            _STATE = {"answers": data.get("answers") or {},
                      "done": data.get("done") or [],
                      "values": data.get("values") or {}}
            return bool(_STATE["answers"] or _STATE["done"])
    except Exception:
        pass
    return False


def state_save():
    """Сохранить состояние. Внутри пароль админа, поэтому файл только для root."""
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        write_file(STATE_PATH, json.dumps(_STATE, ensure_ascii=False, indent=1),
                   mode=0o600)
    except OSError:
        pass          # не смогли сохранить — установка всё равно должна ехать


def state_clear():
    _STATE["answers"].clear()
    _STATE["done"].clear()
    _STATE["values"].clear()
    try:
        os.remove(STATE_PATH)
    except OSError:
        pass


def state_done(phase):
    """Отметить фазу пройденной, чтобы не повторять её при продолжении."""
    if phase not in _STATE["done"]:
        _STATE["done"].append(phase)
        state_save()


def state_is_done(phase):
    return _RESUME and phase in _STATE["done"]


def state_value(key, produce):
    """Значение, которое должно совпадать между запусками (путь, пароль).

    При продолжении берётся прошлое: сгенерировать новое — значит разойтись
    с тем, что уже прописано в панели, nginx и .env.
    """
    if _RESUME and key in _STATE["values"]:
        return _STATE["values"][key]
    val = produce()
    _STATE["values"][key] = val
    state_save()
    return val


def no_input(what):
    """Спросить не у кого — выйти с внятным текстом, а не крутиться вхолостую.

    Без tty (пайп, cron) input() сразу отдаёт EOF, и цикл «спроси заново»
    превращается в бесконечный. Такой запуск лечится только флагами.
    """
    err("Нечего прочитать со stdin — %s" % what)
    say("  Запусти интерактивно или передай значение флагом "
        "(--mode, --panel, --cdn, --domain, ...)")
    sys.exit(1)


def ask(prompt, default=None, remember=True):
    # При продолжении прошлый ответ становится подсказкой по умолчанию: Enter
    # — оставить как было, иначе набрать новое. Именно подсказкой, а не молчаливой
    # подстановкой: перезапускают обычно из-за неверного ответа.
    if _RESUME and default is None and remember:
        default = _STATE["answers"].get(prompt)
    tail = _c(C_DIM, " [%s]" % default) if default else ""
    line = "  " + _c(C_ACC, "❯") + " " + prompt + tail + _c(C_DIM, "  ")
    while True:
        flush_stdin()
        try:
            v = input(line).strip()
        except EOFError:
            v = ""
        except KeyboardInterrupt:
            # Ctrl+C ловим тут (input уже развернулся — readline свободен, повторно
            # войти в него безопасно). Спрашиваем подтверждение отмены.
            print("", flush=True)
            try:
                a = input("  Прервать установку? / Cancel? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                a = "y"
            if a in ("y", "yes", "д", "да"):
                print("", flush=True)
                warn("Установка отменена")
                sys.exit(130)
            continue                      # «нет» — переспросить исходный вопрос
        except UnicodeDecodeError:
            warn("Ввод не похож на UTF-8 (обрывок прошлого нажатия) — повтори")
            continue
        v = v or (default or "")
        if v and remember:
            _STATE["answers"][prompt] = v
            state_save()
        return v


YES = ("y", "yes", "д", "да")
NO = ("n", "no", "н", "нет")


def confirm(prompt, default):
    """Вопрос да/нет. default=True — «да» всё, кроме явного «нет», и наоборот."""
    answer = ask(prompt, "y" if default else "n").lower()
    return answer not in NO if default else answer in YES


def ask_required(prompt, why):
    """Спросить и не пускать дальше с пустым значением."""
    while True:
        v = ask(prompt)
        if v:
            return v
        if not sys.stdin.isatty():
            no_input(why)
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
    # ключ ответа — текст вопроса, иначе все «Выбор» слились бы в один
    prev = _STATE["answers"].get(prompt) if _RESUME else None
    while True:
        v = ask("Выбор", default=prev, remember=False)
        if v.isdigit() and 1 <= int(v) <= len(options):
            _STATE["answers"][prompt] = v
            state_save()
            return int(v)
        if not sys.stdin.isatty():
            no_input("нужен ответ на «%s»" % prompt)
        # Молча переспрашивать нельзя: человек не понимает, что ввод отвергнут
        warn("Нужен номер от 1 до %d%s" % (len(options),
             (", а не '%s'" % v[:20]) if v else ""))


CDN_NAMES = {1: "yandex"}
CDN_LABELS = {1: "Yandex Cloud"}


def resolve_cdn(value):
    """Провайдер из --cdn: имя ('yandex') или номер. '' — значение негодное.

    Провайдер остался один. Timeweb убран: его CDN пропускает на источник
    только запросы, последний сегмент пути которых похож на файл (есть
    расширение), а XHTTP шлёт /<путь>/<сессия>/<номер> — и каждый такой
    запрос отбивается 403, не доходя до сервера. Проверено на живом ресурсе:
    /a/b/t.m3u8 -> 404 от источника, /a/b/t.m3u8/abc123/0 -> 403 от CDN.
    """
    value = (value or "").strip().lower()
    if value in CDN_NAMES.values():
        return value
    if value == "timeweb":
        err("Timeweb убран: его CDN отбивает запросы туннеля (403), потому "
            "что в последнем сегменте пути нет расширения файла")
        say("  Остался Yandex Cloud — ставлю его")
        return "yandex"
    if not value.isdigit():
        return ""
    num = int(value)
    if num not in CDN_NAMES:
        err("CDN '%s' не существует: остался только 1 = Yandex Cloud" % value)
        return ""
    return CDN_NAMES[num]


def vless_link(uuid, domain, path, cdn_name):
    """Ссылка для ручного импорта — с теми же xhttpSettings, что у ноды.

    Без параметра extra клиент берёт умолчания (аплинк POST, паддинг
    ?x_padding=) и туннель не поднимается: CDN отбивает POST, xray — чужой
    паддинг. Подписка панели такой extra отдаёт, а печатаемая ссылка раньше
    нет, из-за чего по ней не работало, а по подписке работало.
    """
    def q(v):
        return urllib.parse.quote(v, safe="")

    return ("vless://%s@%s:443?type=xhttp&security=tls&sni=%s&fp=random"
            "&alpn=%s&path=%s&host=%s&mode=packet-up&extra=%s"
            "&encryption=none#user1-%s"
            % (uuid, domain, domain, q("h3,h2,http/1.1"),
               q(tunnel_dir(path)), domain,
               q(json.dumps(xhttp_settings(path), separators=(",", ":"))),
               cdn_name))


def final_selfcheck(cfg, xport, path):
    """Локальная проверка готовности origin-фронта после установки.

    Не падает и ничего не чинит — только печатает ✔/▲ по каждому пункту, чтобы
    сразу видеть, что xray слушает upstream, фронт поднят на :443, сертификат
    на месте и голый путь туннеля отвечает как надо. Проверки локальные
    (127.0.0.1), состояние самого CDN у провайдера отсюда не видно.
    """
    step("Проверка служб и портов")
    front = cfg.get("front", "nginx")

    def check(passed, what, good, bad):
        (ok if passed else warn)("%s — %s" % (what, good if passed else bad))

    # 1. xray upstream на 127.0.0.1:xport
    out, _ = run("ss -ltnH 2>/dev/null | grep -E '(127\\.0\\.0\\.1|\\*):%d[[:space:]]' "
                 "| head -1" % xport)
    check(out.strip(), "xray upstream 127.0.0.1:%d" % xport,
          "слушает", "порт не слушается")

    # 2. фронт на :443
    out, _ = run("ss -ltnH 2>/dev/null | grep -E ':443\\b' | head -1")
    check(out.strip(), "origin-фронт :443", "слушает", "порт закрыт")

    # 3. сервис фронта активен
    svc = "caddy" if front == "caddy" else "nginx"
    out, _ = run("systemctl is-active %s 2>/dev/null" % svc)
    check(out.strip() == "active", "служба %s" % svc, "active",
          out.strip() or "не активна")

    # 4. сертификат origin на месте
    check(os.path.exists(CDN_CRT) and os.path.exists(CDN_KEY),
          "сертификат origin", "найден", "нет %s/%s" % (CDN_CRT, CDN_KEY))

    # 5. health-заглушка отвечает (нода жива, TLS снимается)
    out, _ = run("curl -sk --max-time 5 https://127.0.0.1/health")
    check('"status":"ok"' in out, "health origin", "ответ ok", "нет ответа")

    # 6. голый путь туннеля обязан отдавать 404 (неотличим от 404 несущест-ей)
    bare = path.strip("/")
    code, _ = run("curl -sk -o /dev/null -w '%%{http_code}' --max-time 5 "
                  "https://127.0.0.1/%s" % bare)
    code = code.strip()
    check(code == "404", "голый путь /%s" % bare,
          "404 как надо", "код %s (ожидался 404)" % code)


# Ключ ответа в состоянии — текст вопроса; по нему же main() показывает домен
# незаконченного запуска, поэтому строка одна на оба места.
DOMAIN_PROMPT = "Домен без http:// (Domain)"


def main():
    args = parse_args()
    banner()
    warn_secret_flags(sys.argv[1:])

    if os.geteuid() != 0:
        err("Нужны права root — запусти через sudo")
        sys.exit(1)
    check_ubuntu()

    my_ip = get_ip() or "<SERVER_IP>"
    say("   " + _c(C_DIM, "◦ Server IP: ") + _c(C_VAL, my_ip))

    # ── продолжить прошлый запуск? ──
    global _RESUME
    if args.fresh:
        state_clear()
    elif state_load():
        dom = _STATE["answers"].get(DOMAIN_PROMPT, "?")
        steps = ", ".join(_STATE["done"]) or "ни одна"
        callout("Найден незакончённый запуск", [
            "домен: %s" % dom,
            "пройдено: %s" % steps,
            "продолжив, скрипт подставит прошлые ответы (Enter — оставить)",
            "и не станет снова снашивать уже поднятое"])
        _RESUME = confirm("Продолжить с того места? (Y/n)", default=True)
        if not _RESUME:
            state_clear()
            say("  Начинаем с чистого листа")

    # ── режим ──
    mode = args.mode or str(choose("Режим установки?", [
        "Панель + нода (всё на этом сервере)",
        "Нода + CDN к существующей панели",
        "Только CDN (перед уже работающей нодой)"]))
    if args.mode:
        mode = check_mode_renumbering(args.mode)
    if mode not in ("1", "2", "3"):
        err("Режим '%s' не существует — есть 1, 2 и 3" % mode)
        sys.exit(1)

    # ── панель ──
    # Выбора больше нет: 3x-ui убран, ставится Remnawave. Флаг --panel 1
    # принимается молча, чтобы не ломать старые команды.
    if args.panel and args.panel != "1":
        err("Панель '%s' не поддерживается: 3x-ui убран, ставится Remnawave"
            % args.panel)
        sys.exit(1)

    # ── CDN ──
    # Провайдер один, спрашивать нечего: флаг принимается ради старых команд.
    cdn_name = resolve_cdn(args.cdn) if args.cdn else "yandex"
    if not cdn_name:
        sys.exit(1)

    domain = (args.domain or ask(DOMAIN_PROMPT) or "").strip()
    if not domain:
        err("Домен обязателен")
        sys.exit(1)
    if not RE_DOMAIN.match(domain):
        err("Домен '%s' не похож на домен (ожидается вид example.com)" % domain)
        say_homoglyph_hint(domain)
        sys.exit(1)
    # Поддомен origin — случайный, но постоянный между перезапусками: он уже
    # прописан в nginx, в сертификате и в ресурсе CDN (state_value).
    origin = (args.origin_domain or "").strip()
    if origin and not RE_DOMAIN.match(origin):
        err("Origin '%s' не похож на домен" % origin)
        say_homoglyph_hint(origin)
        sys.exit(1)
    origin = origin or state_value("origin", lambda: "%s.%s" % (rand_label(), domain))

    # путь/upstream-порт: режим 3 (только CDN) берёт СУЩЕСТВУЮЩИЕ, остальные — новые
    if mode == "3":
        path = (args.path or ask("Существующий xhttp путь (например /abc123)") or "").strip()
        if not RE_XPATH.match(path):
            err("Путь '%s' невалиден: ожидается вид /abc123 "
                "(латиница, цифры, - _ . ~ /)" % path)
            say_homoglyph_hint(path)
            sys.exit(1)
        if args.xport:
            xport = args.xport
        else:
            xp = ask("Локальный upstream-порт xray на 127.0.0.1",
                     default=str(XHTTP_PORT))
            xport = int(xp) if str(xp).isdigit() else XHTTP_PORT
        if not 0 < xport < 65536:
            err("Порт %s вне диапазона 1..65535" % xport)
            sys.exit(1)
    else:
        # путь и пароль обязаны совпадать между запусками: они уже прописаны
        # в инбаунде панели, в nginx и в .env
        path = state_value("path", rand_path)
        xport = XHTTP_PORT
    admin_pw = state_value("admin_pw", rand_password)

    # Домен панели — свой поддомен, как и у источника. На корне панель стояла
    # бы по угадываемому адресу, а её сертификат выпускался бы на один и тот
    # же набор имён при каждой переустановке — и упирался в недельный лимит
    # Let's Encrypt. Постоянный между перезапусками: он уже в .env и в vhost.
    pdom = (args.panel_domain or "").strip()
    if pdom and not RE_DOMAIN.match(pdom):
        err("Домен панели '%s' не похож на домен" % pdom)
        say_homoglyph_hint(pdom)
        sys.exit(1)
    pdom = pdom or state_value("panel_domain",
                               lambda: "%s.%s" % (rand_label(), domain))

    cfg = {"mode": mode, "cdn": cdn_name, "domain": domain,
           "origin_domain": origin, "panel_domain": pdom, "path": path,
           "admin_pass": admin_pw, "xport": xport,
           "no_origin_le": args.no_origin_le, "front": args.front}

    # ── DNS ──
    # Обе записи — A на этот сервер. Домен панели CNAME'ить на CDN нельзя:
    # Let's Encrypt проверяет его прямо здесь, по webroot. Домен CDN клиенту
    # выдаёт провайдер, он в DNS не заводится.
    records = ["A     %s   ->  %s   (DNS only, серое облако) — источник CDN"
               % (origin, my_ip)]
    if mode != "3":
        records.append("A     %s   ->  %s   (DNS only) — панель и её сертификат"
                       % (pdom, my_ip))
    dns_wait(records, skip=args.skip_dns_wait)

    # ── снести прошлую установку тех компонентов, которые ставим сейчас ──
    if state_is_done("wipe"):
        say("  Прошлая установка уже снесена на прошлом запуске — пропускаю")
    elif not args.no_wipe:
        wipe_previous(panel=(mode == "1"), node=(mode in ("1", "2")),
                      assume_yes=args.wipe)
        state_done("wipe")

    # ── установка ──
    result = {}
    if mode == "1":
        result = install_remnawave(cfg)
    elif mode == "2":
        cfg["panel_url"] = ssh_host(args.panel_url or ask_required(
            "IP/URL панели Remnawave", "без адреса панели подключиться некуда"))
        cfg["panel_ssh_user"] = args.panel_ssh_user
        cfg["panel_key"] = args.panel_key
        cfg["panel_token"] = args.panel_token
        cfg["panel_user"] = args.panel_user
        cfg["panel_pass"] = args.panel_pass
        cfg["panel_ssh_pass"] = args.panel_ssh_pass or ""
        if not cfg["panel_key"]:
            while not cfg["panel_ssh_pass"]:
                if not sys.stdin.isatty():
                    no_input("нужен --panel-ssh-pass или --panel-key")
                cfg["panel_ssh_pass"] = ask_secret("SSH пароль панели")
                if not cfg["panel_ssh_pass"]:
                    warn("Пустой пароль — SSH к панели не пройдёт "
                         "(или запусти с --panel-key /путь/к/ключу)")
        result = install_node_only(cfg)
    elif mode == "3":
        result = install_cdn_only(cfg)

    # ── CDN-инструкция + ожидание ──
    # Клиентский домен нужен уже в инструкции: у Yandex он указывается и в
    # сертификате, и в самом ресурсе, поэтому придумываем его заранее, а не
    # спрашиваем в конце. Постоянный между запусками — как origin и путь.
    client_domain = (args.client_domain or "").strip()
    if client_domain and not RE_DOMAIN.match(client_domain):
        err("Домен клиентов '%s' не похож на домен" % client_domain)
        sys.exit(1)
    if not client_domain and cdn_name == "yandex":
        client_domain = state_value(
            "client_domain", lambda: "%s.%s" % (rand_label(), domain))

    print_cdn_instructions(cdn_name, origin, client_domain, my_ip, path)
    if not args.skip_cdn_wait:
        pause("Enter когда CDN настроен и серт выпущен")
    # Технический домен уходит в CNAME; опечатка здесь даёт рабочую на вид,
    # но неподключаемую подписку
    # В блоке «Настройки DNS» две строки: $ORIGIN с вашим же доменом и CNAME
    # со значением провайдера. Нужна вторая, и спросить надо именно так.
    cdn_domain = ask_domain(
        "Значение CNAME из блока «Настройки DNS» (вида ...yccdn.ru)",
        args.cdn_domain)
    if not client_domain:
        client_domain = ask_domain(
            "Свой домен для клиентов, CNAME на %s (Enter — пропустить)"
            % (cdn_domain or "домен CDN"), "")
    if cdn_domain or client_domain:
        callout("DNS для CDN",
                cdn_dns_records(origin, my_ip, cdn_domain, client_domain))
    public_domain = client_domain or cdn_domain

    # Хост в панели создавался до того, как провайдер выдал домен — переставить
    if public_domain and result.get("host_uuid"):
        update_host_address(result["api"], result["host_uuid"], public_domain,
                            remark=host_remark(cdn_name))

    # ── проверка служб/портов/конфига ──
    try:
        final_selfcheck(cfg, xport, path)
    except Exception as e:
        warn("Само-проверка не завершилась: %s" % e)

    # ── финальный отчёт ──
    cdn_val = public_domain or "— укажи после настройки провайдера"
    origin_row = ("Origin", "%s  (A → %s)" % (origin, my_ip))
    if mode == "3":
        rows = [("Режим", "только CDN"),
                origin_row,
                ("Фронт", ":443 → 127.0.0.1:%d  путь %s" % (xport, path)),
                ("CDN", cdn_val)]
    elif mode == "2":
        rows = [("Режим", "нода + CDN к существующей панели"),
                ("Панель", cfg["panel_url"]),
                origin_row,
                ("CDN", cdn_val)]
    else:
        rows = [("Панель", "https://%s/" % pdom),
                ("Логин", "admin"),
                ("Пароль", admin_pw),
                origin_row,
                ("CDN", cdn_val)]
    if mode in ("1", "2") and not result.get("host_uuid"):
        # Без хоста подписка пустая: клиенту не к чему подключаться
        rows.append(("Хост", "НЕ создан — добавь в панели вручную"))
    if client_domain:
        rows.append(("CNAME", "%s → %s" % (client_domain,
                                           cdn_domain or "<домен CDN>")))
    if result.get("sub_url"):
        rows.append(("Подписка", result["sub_url"]))
    card("ГОТОВО · УСТАНОВКА ЗАВЕРШЕНА", rows, color=C_OK)
    state_clear()      # дошли до конца — продолжать нечего

    if public_domain and result.get("user_uuid"):
        link = vless_link(result["user_uuid"], public_domain, path, cdn_name)
        callout("VLESS CDN ссылка", [link], color=C_TITLE)
    print("", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("", flush=True)
        warn("Установка отменена")
        sys.exit(130)
