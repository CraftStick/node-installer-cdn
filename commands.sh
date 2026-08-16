#!/bin/bash
# Shell-команды, извлечённые из node-installer-cdn.py (скомпилированный бинарник).
# Порядок = порядок констант в модуле, близок к порядку в исходнике.
# {} — плейсхолдеры Python .format(), подставляются на исполнении.
# НЕ ЗАПУСКАТЬ. Материал для аудита.
# Всего: 321

# ---- @0x013e152c ----
 && docker compose down -v 2>/dev/null

# ---- @0x013e157c ----
    docker compose down: 

# ---- @0x013e15b1 ----
 2>/dev/null; systemctl disable 

# ---- @0x013e1658 ----
/etc/nginx/sites-enabled/

# ---- @0x013e1673 ----
/etc/nginx/sites-available/

# ---- @0x013e1690 ----
    nginx site удалён: 

# ---- @0x013e16d4 ----
iptables -D INPUT -p tcp --dport 

# ---- @0x013e175a ----
~/.acme.sh/acme.sh --remove -d 

# ---- @0x013e178e ----
systemctl stop xray 2>/dev/null; systemctl disable xray 2>/dev/null

# ---- @0x013e17d9 ----
    xray остановлен

# ---- @0x013e17fa ----
nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null

# ---- @0x013e1bd4 ----
curl -s -m 5 -w '%{http_code}' https://registry-1.docker.io/v2/ 2>/dev/null | tail -c 3

# ---- @0x013e1cc5 ----
cat /etc/docker/daemon.json 2>/dev/null

# ---- @0x013e1d7e ----
mkdir -p /etc/docker && echo '{"registry-mirrors":["https://huecker.io","https://dockerhub.timeweb.cloud","https://mirror.gcr.io"]}' > /etc/docker/daemon.json && systemctl restart docker

# ---- @0x013e1f2d ----
Configure Docker Hub mirror if registry-1.docker.io is blocked or rate-limited.

# ---- @0x013e221e ----
curl -s4 --max-time 5 

# ---- @0x013e26aa ----
download_xray_binary.<locals>._run

# ---- @0x013e2720 ----
  Скачивание xray 

# ---- @0x013e27c3 ----
cd /tmp && curl -sL -o xray_dl.zip '

# ---- @0x013e27e9 ----
' && python3 -c "import zipfile;z=zipfile.ZipFile('xray_dl.zip');z.extract('xray','xray_dl');z.close()" && mv xray_dl/xray '

# ---- @0x013e2878 ----
' && rm -rf xray_dl.zip xray_dl

# ---- @0x013e289b ----
xu  ⚠ Не удалось скачать xray: 

# ---- @0x013e28ee ----
  ⚠ Не удалось верифицировать xray: 

# ---- @0x013e292d ----
:nldnuDownload xray XRAY_MIN_VERSION binary to host for volume mount into remnanode.

# ---- @0x013e2a2f ----
 2>/dev/null || iptables 

# ---- @0x013e2a51 ----
Add iptables rule only if it doesn't already exist.

# ---- @0x013e2aa8 ----
Домен -> IP. Уже-IP возвращается как есть, при неудаче — None.

    В `-s` у iptables домен подставлять нельзя: он резолвится один раз в момент
    добавления, и если DNS на ноде в этот миг лежит, правило не создаётся вовсе.
    А следующий за ним `-j DROP` создаётся всегда — нода отрезает себя от панели
    и висит с 'timeout of 15000ms exceeded'.
    

# ---- @0x013e2f0a ----
     iptables -I INPUT -p tcp --dport 2222 -s <IP панели> -j ACCEPT && iptables -A INPUT -p tcp --dport 2222 -j DROP

# ---- @0x013e330f ----
RDOM=$(grep -oP "PANEL_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -X {method} -H "Content-Type: application/json" -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: ${RDOM:-localhost}" -H "Authorization: Bearer $(cat /opt/remnawave/.panel_token 2>/dev/null)" -d "$(echo 

# ---- @0x013e3478 ----
RDOM=$(grep -oP "PANEL_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -X {method} -H "Content-Type: application/json" -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: ${RDOM:-localhost}" -d "$(echo 

# ---- @0x013e3579 ----
RDOM=$(grep -oP "PANEL_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -X {method} -H "Content-Type: application/json" -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: ${RDOM:-localhost}" -H "Authorization: Bearer $(cat /opt/remnawave/.panel_token 2>/dev/null)" "

# ---- @0x013e36ba ----
RDOM=$(grep -oP "PANEL_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -X {method} -H "Content-Type: application/json" -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" -H "Host: ${RDOM:-localhost}" "

# ---- @0x013e37b1 ----
SSH curl failed: 

# ---- @0x013e380d ----
Make API call to Remnawave panel via SSH (curl to 127.0.0.1:3000). Bypasses nginx auth.

# ---- @0x013e3914 ----
docker ps --format '{{.Names}}' | grep -iE '^remnawave$|remnawave-backend' | head -1

# ---- @0x013e396a ----
docker ps --format '{{.Names}}' | grep -i remnawave | grep -v 'db\|redis\|nginx\|subscription\|page' | head -1

# ---- @0x013e39da ----
docker ps --format '{{.Names}}' | grep -iE 'backend|panel|app' | head -1

# ---- @0x013e3a2f ----
docker ps --format '{{.Names}}' | grep -iE 'remnawave.*db|postgres' | head -1

# ---- @0x013e3aa2 ----
for f in /opt/remnawave/.env /root/remnawave/.env /opt/remnawave-backend/.env /opt/panel/.env $(find /opt /root /home -maxdepth 3 -name ".env" -path "*remnawave*" 2>/dev/null) $(find /opt /root /home -maxdepth 3 -name ".env" -path "*panel*" 2>/dev/null); do grep -qE "JWT_|APP_SECRET" "$f" 2>/dev/null && cat "$f" && break; done 2>/dev/null

# ---- @0x013e3c0c ----
 env 2>/dev/null | grep -E "^(POSTGRES_USER|POSTGRES_DB|JWT_API_TOKENS_SECRET|JWT_AUTH_SECRET|APP_SECRET)="

# ---- @0x013e4155 ----
grep -oP "FRONT_END_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null || grep -roP "FRONT_END_DOMAIN=\K.*" $(find /opt /root /home -maxdepth 3 -name ".env" -path "*remnawave*" 2>/dev/null) 2>/dev/null | head -1

# ---- @0x013e4555 ----
mkdir -p /opt/remnawave && echo 

# ---- @0x013e4c6d ----
set +e
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


# ---- @0x013e5c94 ----
If the configured apt mirror is unreachable, switch to archive.ubuntu.com.
    Private VPS images (Fornex mirror.fornex.org, Beget и др.) часто ставят своё
    зеркало, которое отваливается -> падает и apt install, и get.docker.com
    (внутри тоже apt). Ubuntu-only, no-op на прочих ОС и при рабочем зеркале.
    Кешируется per-host, чтобы не гонять apt-get update повторно.

# ---- @0x013e5e8a ----
ensure_nginx_base.<locals>._r

# ---- @0x013e5eab ----
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/ssl /var/www/html

# ---- @0x013e5f1c ----
test -s /etc/nginx/nginx.conf

# ---- @0x013e5f52 ----
DEBIAN_FRONTEND=noninteractive apt-get install -y nginx-common nginx-core 2>&1 | tail -3

# ---- @0x013e5fb1 ----
DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall -o Dpkg::Options::=--force-confmiss nginx-common 2>&1 | tail -3

# ---- @0x013e6062 ----
 | base64 -d > /etc/nginx/nginx.conf

# ---- @0x013e6088 ----
[ -s /etc/nginx/mime.types ] || echo 

# ---- @0x013e60af ----
 | base64 -d > /etc/nginx/mime.types

# ---- @0x013e60ec ----
nginx.conf восстановлен (минимальный конфиг)

# ---- @0x013e6137 ----
Guarantee /etc/nginx/nginx.conf exists. Две причины отсутствия:
    (1) битое зеркало -> nginx-common не доустановился; (2) conffile удалён извне
    -> dpkg при обычной установке его НЕ восстанавливает. Чиним зеркало, ставим/
    переустанавливаем nginx-common с --force-confmiss, иначе пишем минимальный конфиг.

# ---- @0x013e6317 ----
install_docker.<locals>._r

# ---- @0x013e6338 ----
install_docker.<locals>._ok

# ---- @0x013e6357 ----
curl -fsSL https://get.docker.com | sh 2>&1 | tail -5

# ---- @0x013e6391 ----
get.docker.com не сработал, чиню apt-зеркало и ставлю docker.io...

# ---- @0x013e63f3 ----
DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io 2>&1 | tail -5

# ---- @0x013e6442 ----
пробую официальный репозиторий docker-ce...

# ---- @0x013e648d ----
install -m 0755 -d /etc/apt/keyrings && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc && chmod a+r /etc/apt/keyrings/docker.asc && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list && apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin 2>&1 | tail -5

# ---- @0x013e66af ----
пробую статический бинарник docker...

# ---- @0x013e66f1 ----
cd /tmp && A=$(uname -m) && curl -fsSL https://download.docker.com/linux/static/stable/$A/docker-27.3.1.tgz -o d.tgz && tar xzf d.tgz && cp docker/* /usr/bin/ && rm -rf docker d.tgz && cat > /etc/systemd/system/docker.service <<EOF
[Unit]
Description=Docker
After=network.target
[Service]
ExecStart=/usr/bin/dockerd
Restart=always
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now docker && sleep 6

# ---- @0x013e68c1 ----
Robustly install Docker engine. Returns True on success.
    Routes: get.docker.com -> (repair apt mirror) docker.io -> official docker-ce
    repo -> static binary + systemd unit. Compose plugin ставится отдельно после.

# ---- @0x013e69b6 ----
docker --version

# ---- @0x013e6a28 ----
setup_xray_ru_geo.<locals>._dl

# ---- @0x013e6a9c ----
 && test -s geoip_RU.dat && test -s geosite_RU.dat && echo GEO_OK

# ---- @0x013e6adf ----
setup_xray_ru_geo.<locals>._r

# ---- @0x013e6b11 ----
mkdir -p /etc/systemd/system/xray.service.d && printf '[Service]\nEnvironment=XRAY_LOCATION_ASSET=

# ---- @0x013e6b75 ----
\n' > /etc/systemd/system/xray.service.d/asset.conf && systemctl daemon-reload

# ---- @0x013e6bc7 ----
  ⚠ RU гео-файлы не скачались — xray может не стартовать (роутинг .ru)

# ---- @0x013e6c3e ----
Download RU geo files (geoip_RU.dat / geosite_RU.dat) referenced by routing
    rules (ext:geoip_RU.dat:ru). БЕЗ них xray НЕ стартует — 'failed to open file:
    geoip_RU.dat' -> service failed -> nginx 502 -> CDN 'Empty reply'. Источник —
    runetfreedom (категории ru / ru-available-only-inside).

# ---- @0x013e6d90 ----
( curl -fsSL --max-time 900 -o 

# ---- @0x013e6dc9 ----
 || curl -fsSL --max-time 900 -o 

# ---- @0x013e6df2 ----
systemctl stop xray 2>/dev/null; systemctl disable xray 2>/dev/null; systemctl mask xray 2>/dev/null; pkill -9 -f '/usr/local/bin/xray' 2>/dev/null; true

# ---- @0x013e6f2d ----
3x-ui запускает СВОЙ встроенный xray на 127.0.0.1:2053. Если на сервере
    остался standalone xray-core (systemd 'xray.service', /usr/local/bin/xray,
    /usr/local/etc/xray/config.json) от предыдущего запуска (например сначала
    mode 3, потом перезапуск как 3x-ui) — он держит 2053, и xray от 3x-ui падает:
    'bind: address already in use' -> инбаунд панели не слушает -> nginx проксирует
    на ЧУЖОЙ xray без нужного юзера -> через CDN клиент видит 'Empty reply from
    server'. Останавливаем/маскируем standalone, чтобы 3x-ui смог занять 2053.

# ---- @0x013e7318 ----
nslookup google.com >/dev/null 2>&1 && exit 0; systemctl disable --now systemd-resolved 2>/dev/null; rm -f /etc/resolv.conf; printf 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n' > /etc/resolv.conf; nslookup google.com >/dev/null 2>&1 && echo DNS_FIXED || echo DNS_STILL_BROKEN

# ---- @0x013e7610 ----
fuser /var/lib/dpkg/lock-frontend 2>/dev/null

# ---- @0x013e76a1 ----
kill -9 $(pgrep -f unattended-upgr) 2>/dev/null; rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock 2>/dev/null

# ---- @0x013e7790 ----
dpkg --configure -a 2>/dev/null

# ---- @0x013e77b3 ----
<uapt-get clean 2>/dev/null

# ---- @0x013e77e9 ----
DEBIAN_FRONTEND=noninteractive apt-get install -y 

# ---- @0x013e781d ----
  [удалённая] apt-get install ошибка: 

# ---- @0x013e78a6 ----
apt-get --fix-broken install -y 2>/dev/null

# ---- @0x013e78d3 ----
apt-get update --fix-missing

# ---- @0x013e798f ----
: apt-get update && apt-get install -y 

# ---- @0x013e7b33 ----
apt-get update -qq

# ---- @0x013e7b47 ----
Flxu  apt ошибка: 

# ---- @0x013e7c20 ----
  Попробуй вручную: apt-get update && apt-get install -y 

# ---- @0x013e7c6a ----
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent netfilter-persistent 2>/dev/null; netfilter-persistent save 2>/dev/null

# ---- @0x013e7e48 ----
     Вручную: apt-get update && apt-get install -y sshpass

# ---- @0x013e7e8b ----
Гарантировать наличие sshpass. True — можно ходить по SSH с паролем.

    Раньше на местах ставили голый `apt-get install -y sshpass` — без fix_dns и
    без apt-get update. На сервере со сломанным systemd-resolved это молча
    падает, run_remote() возвращает пустой stdout, и установка вылетает с
    «не могу подключиться», хотя SSH на той стороне полностью исправен.
    pkg_install() чинит DNS, зеркала и повторяет установку.
    

# ---- @0x013e8298 ----
  → sshpass отсутствует: apt-get update && apt-get install -y sshpass

# ---- @0x013e83ad ----
ensure_nginx_base

# ---- @0x013e83d0 ----
Write nginx config and create symlink.

# ---- @0x013e83f8 ----
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

# ---- @0x013e8449 ----
/etc/nginx/sites-available/default

# ---- @0x013e846d ----
rm -f /etc/nginx/sites-enabled/default && ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

# ---- @0x013e84e2 ----
sed -i 's/worker_connections[[:space:]]*[0-9]*/worker_connections 16384/' /etc/nginx/nginx.conf

# ---- @0x013e8543 ----
if grep -qE '^[[:space:]]*#?[[:space:]]*server_names_hash_bucket_size' /etc/nginx/nginx.conf; then sed -i -E 's/^[[:space:]]*#?[[:space:]]*server_names_hash_bucket_size[[:space:]]+[0-9]+;/    server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf; else sed -i '0,/http {/s//http {\n    server_names_hash_bucket_size 128;/' /etc/nginx/nginx.conf; fi

# ---- @0x013e86a5 ----
nginx -t && systemctl restart nginx

# ---- @0x013e870a ----
Fanginx_write_conf

# ---- @0x013e8ca7 ----
=uParse 'openssl pkey -text -noout' output for X25519.

# ---- @0x013e8ce1 ----
/usr/local/x-ui/bin/xray-linux-amd64

# ---- @0x013e8d07 ----
/usr/local/x-ui/bin/xray-linux-arm64

# ---- @0x013e8d4c ----
docker exec remnanode xray x25519 2>/dev/null

# ---- @0x013e8d80 ----
xray x25519 2>/dev/null

# ---- @0x013e8d9e ----
docker run --rm ghcr.io/remnawave/node:latest xray x25519 2>/dev/null

# ---- @0x013e8dea ----
openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null

# ---- @0x013e8eac ----
Generate x25519 key pair for Reality using xray binary.

# ---- @0x013e8fff ----
/etc/nginx/ssl/cdn.crt

# ---- @0x013e9017 ----
/etc/nginx/ssl/cdn.key

# ---- @0x013e902f ----
Build Hysteria2 inbound config for xray-core.

# ---- @0x013e905e ----
openssl x509 -in 

# ---- @0x013e9206 ----
Build VLESS Reality gRPC inbound config for xray-core.

# ---- @0x013e9316 ----
iptables -C INPUT -p udp --dport 

# ---- @0x013e9339 ----
 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 

# ---- @0x013e93bc ----
iptables -C INPUT -p tcp --dport 

# ---- @0x013e93df ----
 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 

# ---- @0x013e9465 ----
pkg_iptables_persist

# ---- @0x013e9773 ----
upstream xray_xhttp {
    server 127.0.0.1:

# ---- @0x013e9852 ----
;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location = /health {
        default_type application/json;
        return 200 '{"status":"ok","service":"media-gateway","version":"4.2.1"}';
    }

    

# ---- @0x013e9969 ----
        proxy_pass http://xray_xhttp;
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
    }


# ---- @0x013e9f3d ----
Generate nginx CDN origin config.

    nginx_style:
      "prefix"  — путь-каталог (/content/media/), обычный prefix-location.
      "rewrite" — путь-файл (/static/getFile/video/segment.ts): нужен ^~ и
                  rewrite, добавляющий слеш, иначе xhttp не матчится.
                  Проверено на Beeline 28.07.2026 (4/4 оператора).
    

# ---- @0x013ea253 ----
nginx openssl curl ca-certificates gnupg

# ---- @0x013ea27d ----
ufw status 2>/dev/null

# ---- @0x013ea2f1 ----
ufw allow 80/tcp >/dev/null 2>&1 && ufw allow 443/tcp >/dev/null 2>&1 && ufw reload >/dev/null 2>&1

# ---- @0x013ea420 ----
!asetup_docker_mirror

# ---- @0x013ea437 ----
docker compose version 2>/dev/null

# ---- @0x013ea45d ----
  [удалённая] docker compose plugin не найден, устанавливаю...

# ---- @0x013ea4ba ----
apt-get install -y -qq docker-compose-plugin 2>/dev/null || apt-get install -y -qq docker-compose-v2 2>/dev/null || (mkdir -p /usr/local/lib/docker/cli-plugins && curl -fsSL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m) -o /usr/local/lib/docker/cli-plugins/docker-compose && chmod +x /usr/local/lib/docker/cli-plugins/docker-compose)

# ---- @0x013ea671 ----
/etc/sysctl.d/99-vpn-tuning.conf

# ---- @0x013ea6a2 ----
sysctl --system > /dev/null 2>&1

# ---- @0x013ea72f ----
mkdir -p /etc/nginx/ssl /etc/nginx/conf.d /var/www/html

# ---- @0x013ea768 ----
test -f /etc/nginx/ssl/cdn.crt || openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN=cdn-origin'

# ---- @0x013ea842 ----
swapon --show | grep -q / || (fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab)

# ---- @0x013ea90f ----
  [удалённая] Настройка nginx CDN origin...

# ---- @0x013ea95f ----
nginx_cdn_origin

# ---- @0x013ea9b4 ----
nginx_write_and_restart

# ---- @0x013ea9fe ----
  [удалённая] ВНИМАНИЕ: проблема с nginx: 

# ---- @0x013eaaed ----
mkdir -p /opt/remnanode

# ---- @0x013eab06 ----
/opt/remnanode/docker-compose.yml

# ---- @0x013eab29 ----
services:
  remnanode:
    container_name: remnanode
    hostname: remnanode
    image: ghcr.io/remnawave/node:latest
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


# ---- @0x013ead08 ----
download_xray_binary

# ---- @0x013ead67 ----
cd /opt/remnanode && docker compose pull

# ---- @0x013eadc5 ----
cd /opt/remnanode && docker compose up -d

# ---- @0x013eae55 ----
docker logs remnanode --tail=5 2>&1

# ---- @0x013eaf46 ----
Install Docker, nginx CDN origin, and remnanode on remote server via SSH.

# ---- @0x013eafab ----
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot 2>/dev/null

# ---- @0x013eaff6 ----
mkdir -p /var/www/certbot

# ---- @0x013eb0cf ----
  Позже выпусти вручную: certbot certonly --webroot -w /var/www/certbot -d 

# ---- @0x013eb12f ----
certbot certonly --webroot -w /var/www/certbot -d 

# ---- @0x013eb1bb ----
  HY2: certbot не прошёл (попытка 

# ---- @0x013eb264 ----
  Выпусти вручную: certbot certonly --webroot -w /var/www/certbot -d 

# ---- @0x013eb2e2 ----
/fullchain.pem /etc/nginx/ssl/cdn.crt && cp /etc/letsencrypt/live/

# ---- @0x013eb326 ----
/privkey.pem /etc/nginx/ssl/cdn.key && nginx -s reload && docker restart remnanode

# ---- @0x013eb395 ----
/privkey.pem /etc/nginx/ssl/cdn.key && nginx -s reload 2>/dev/null; docker restart remnanode 2>/dev/null || true

# ---- @0x013eb434 ----
/fullchain.pem /etc/nginx/ssl/cdn.crt\ncp /etc/letsencrypt/live/

# ---- @0x013eb476 ----
/privkey.pem /etc/nginx/ssl/cdn.key\nnginx -s reload\ndocker restart remnanode 2>/dev/null || true

# ---- @0x013eb4da ----
mkdir -p /etc/letsencrypt/renewal-hooks/deploy && printf '%b' '

# ---- @0x013eb51b ----
' > /etc/letsencrypt/renewal-hooks/deploy/hy2-cert.sh && chmod +x /etc/letsencrypt/renewal-hooks/deploy/hy2-cert.sh

# ---- @0x013eb601 ----
  Установка acme.sh...

# ---- @0x013eb624 ----
curl -fsSL https://get.acme.sh | sh 2>/dev/null

# ---- @0x013eb65a ----
  ⚠ acme.sh не установился, используем self-signed

# ---- @0x013eb6a9 ----
  Остановка nginx для HTTP-01 challenge...

# ---- @0x013eb6e3 ----
systemctl stop nginx

# ---- @0x013eb729 ----
~/.acme.sh/acme.sh --issue --server letsencrypt -d 

# ---- @0x013eb80b ----
systemctl start nginx

# ---- @0x013eb825 ----
mkdir -p /root/cert/ip

# ---- @0x013eb83d ----
Fu~/.acme.sh/acme.sh --install-cert -d 

# ---- @0x013eb865 ----
 --fullchain-file /root/cert/ip/fullchain.pem --key-file /root/cert/ip/privkey.pem --reloadcmd "systemctl reload nginx"

# ---- @0x013eb9db ----
Issue LE cert for IP address via acme.sh with shortlived profile.

# ---- @0x013ebafb ----
swapon --show | grep -q / || (fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab) 2>/dev/null

# ---- @0x013ebc0e ----
systemctl is-active x-ui 2>/dev/null

# ---- @0x013ebc34 ----
test -f /usr/local/x-ui/x-ui && echo yes || echo no

# ---- @0x013ebcde ----
curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3xui_install.sh

# ---- @0x013ebd43 ----
XUI_NONINTERACTIVE=1 bash /tmp/3xui_install.sh v3.3.1

# ---- @0x013ebd7a ----
systemctl is-active x-ui

# ---- @0x013ebd94 ----
systemctl restart x-ui

# ---- @0x013ebdac ----
stop_conflicting_standalone_xray

# ---- @0x013ebe4d ----
setup_xray_ru_geo

# ---- @0x013ebed9 ----
certbot nginx sqlite3

# ---- @0x013ebf1a ----
;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location /health { return 200 'ok'; add_header Content-Type text/plain; }
    location / { return 301 https://$host$request_uri; }
}


# ---- @0x013ec007 ----
nginx -t 2>/dev/null && systemctl restart nginx

# ---- @0x013ec0a5 ----
mkdir -p /etc/nginx/ssl && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN=

# ---- @0x013ec2a9 ----
/usr/local/x-ui/bin/xray

# ---- @0x013ec2c3 ----
/usr/local/bin/xray

# ---- @0x013ec30a ----
find /usr/local/x-ui -name 'xray*' -type f -executable 2>/dev/null | head -1

# ---- @0x013ec358 ----
docker exec $(docker ps -q --filter ancestor=ghcr.io/mhsanaei/3x-ui 2>/dev/null | head -1) xray x25519 2>/dev/null || docker run --rm ghcr.io/remnawave/node:latest xray x25519 2>/dev/null

# ---- @0x013ed7e7 ----
' WHERE key='xrayTemplateConfig';
INSERT OR IGNORE INTO settings (key, value) VALUES ('xrayTemplateConfig', '

# ---- @0x013ed999 ----
/tcp 2>/dev/null; iptables -I INPUT -p tcp --dport 

# ---- @0x013ed9e6 ----
ss -tlnp | grep :443

# ---- @0x013eda86 ----
journalctl -u x-ui --no-pager -n 20 2>/dev/null | grep -i 'error\|fail\|443' | tail -5

# ---- @0x013edb1c ----
  ⚠ [cascade] Порт 443 не слушает на exit (возможно конфликт с nginx)

# ---- @0x013edbcc ----
systemctl stop nginx && systemctl restart x-ui

# ---- @0x013edbfe ----
  [cascade] Exit: Reality inbound 443 OK (nginx остановлен)

# ---- @0x013edc45 ----
ss -tlnp | grep :8888

# ---- @0x013edccc ----
ss -tlnp | grep :

# ---- @0x013edfd7 ----
curl -fsSL --max-time 60 https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3xui_install.sh || curl -fsSL --max-time 60 https://gh-proxy.com/https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3xui_install.sh

# ---- @0x013ee273 ----
 bash /tmp/3xui_install.sh v3.3.1

# ---- @0x013ee54c ----
journalctl -u x-ui --no-pager -n 10

# ---- @0x013ee625 ----
Fu;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}


# ---- @0x013ee7c4 ----
;
            location /.well-known/acme-challenge/ { root /var/www/certbot; }
            location / { return 301 https://$host$request_uri; }
        }
        server {
            listen 443 ssl http2;

# ---- @0x013eed37 ----
nginx -t && systemctl reload nginx

# ---- @0x013eedc0 ----
Настройка nginx CDN origin

# ---- @0x013eee3c ----
/etc/nginx/sites-enabled/panel.conf

# ---- @0x013eee97 ----
  ❌ Проблема с nginx: 

# ---- @0x013eeebc ----
  Попробуй: nginx -t и systemctl restart nginx

# ---- @0x013efbc1 ----
Fu  Ожидание запуска xray на порту 

# ---- @0x013efbfb ----
  Inbound создан, xray слушает порт 

# ---- @0x013efc32 ----
  ВНИМАНИЕ: xray не слушает порт 

# ---- @0x013efd18 ----
journalctl -u x-ui --no-pager -n 15

# ---- @0x013f0fac ----
curl -s http://127.0.0.1/health

# ---- @0x013f1042 ----
systemctl is-active nginx

# ---- @0x013f1069 ----
curl -sk https://

# ---- @0x013f1463 ----
 systemctl status x-ui

# ---- @0x013f1499 ----
test -f /etc/x-ui/x-ui.db && echo OK

# ---- @0x013f15fb ----
Установка xray на ноде

# ---- @0x013f1624 ----
xray version 2>/dev/null || /usr/local/bin/xray version 2>/dev/null

# ---- @0x013f16a4 ----
  Скачивание xray...

# ---- @0x013f16c6 ----
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install 2>&1 | tail -5

# ---- @0x013f1736 ----
Flxu  ❌ Не удалось установить xray: 

# ---- @0x013f1772 ----
/usr/local/bin/xray version

# ---- @0x013f1a19 ----
mkdir -p /usr/local/etc/xray

# ---- @0x013f1a37 ----
Fu/usr/local/etc/xray/config.json

# ---- @0x013f1a69 ----
  Конфиг xray записан (порт 

# ---- @0x013f1aa6 ----
systemctl enable xray 2>/dev/null

# ---- @0x013f1acc ----
systemctl restart xray

# ---- @0x013f1b52 ----
journalctl -u xray --no-pager -n 10

# ---- @0x013f1bc2 ----
mkdir -p /etc/nginx/ssl

# ---- @0x013f1bdb ----
Fuopenssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj '/CN=

# ---- @0x013f1c1e ----
' -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt 2>/dev/null

# ---- @0x013f1dee ----
/usr/local/x-ui/x-ui version 2>/dev/null || echo unknown

# ---- @0x013f1ee4 ----
curl -sf -k -c /tmp/.xcook '

# ---- @0x013f1f44 ----
' | base64 -d | curl -sf -k -c /tmp/.xcook -b /tmp/.xcook -X POST '

# ---- @0x013f1fdb ----
Fucurl -sf -b /tmp/.xcook '

# ---- @0x013f201e ----
curl -sf -b /tmp/.xcook -X POST '

# ---- @0x013f209b ----
' | base64 -d | curl -sf -b /tmp/.xcook -X POST '

# ---- @0x013f2f45 ----
Add CDN node to an existing remote 3x-ui panel. Installs xray standalone + nginx on THIS server, creates inbound on remote panel (API-first, SQLite fallback).

# ---- @0x013f3a43 ----
Инбаунд должен быть в activeInbounds ноды, иначе xray его не поднимет.

    Нужно отдельно: при уже существующей ноде activeInbounds не пересобирается.
    

# ---- @0x013f3f6a ----
Завести BRIDGE_IN в профиле, который РЕАЛЬНО активен на exit-ноде.

    Если нода уже была заведена в панели раньше, она сидит на своём профиле, а
    наш свежесозданный к ней не привязан. Положить BRIDGE_IN в «свой» профиль
    мало: xray на ноде о нём не узнает и не поднимет :8888. Со стороны relay это
    выглядит как Connection refused, а установщик при этом рапортует «КАСКАД
    НАСТРОЕН» — вторая половина цепочки молча не работает.

    Возвращает uuid BRIDGE_IN или None.
    

# ---- @0x013f42ae ----
timeout 8 bash -c "</dev/tcp/

# ---- @0x013f42cd ----
/8888" 2>/dev/null && echo BRIDGE_OK || echo BRIDGE_DOWN

# ---- @0x013f48b7 ----
  [cascade] Panel на том же сервере — добавляю xhttp в nginx...

# ---- @0x013f497e ----
 {
        proxy_pass http://127.0.0.1:7443;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;
    }

    root /var/www/html;
    index index.html;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;

    ssl_certificate /etc/nginx/ssl/cdn.crt;
    ssl_certificate_key /etc/nginx/ssl/cdn.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location 

# ---- @0x013f4d92 ----
systemctl stop caddy 2>/dev/null; systemctl disable caddy 2>/dev/null; nginx -t 2>&1 && systemctl restart nginx && systemctl enable nginx

# ---- @0x013f4edd ----
caddy version 2>/dev/null

# ---- @0x013f4ef8 ----
vuapt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null 2>&1 && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --batch --yes --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg 2>/dev/null && curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null && apt-get update -qq && apt-get install -y caddy 2>&1 | tail -3

# ---- @0x013f5132 ----
curl -fsSL 'https://caddyserver.com/api/download?os=linux&arch=amd64' -o /usr/bin/caddy && chmod +x /usr/bin/caddy && groupadd --system caddy 2>/dev/null; useradd --system --gid caddy --create-home --home-dir /var/lib/caddy --shell /usr/sbin/nologin caddy 2>/dev/null; mkdir -p /etc/caddy /var/log/caddy /var/lib/caddy && cat > /etc/systemd/system/caddy.service << 'CADDYSVC'
[Unit]
Description=Caddy
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=caddy
Group=caddy
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile --force
TimeoutStopSec=5s
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
CADDYSVC
systemctl daemon-reload

# ---- @0x013f54b1 ----
{
    log {
        output file /var/log/caddy/access.log
        format json
    }
}

:80 {
    @xhttp path 

# ---- @0x013f5520 ----

    reverse_proxy @xhttp 127.0.0.1:7443 {
        flush_interval -1
        transport http {
            read_buffer 16384
            write_buffer 16384
        }
    }
    root * /var/www/html
    file_server
}

:443 {
    tls /etc/nginx/ssl/cdn.crt /etc/nginx/ssl/cdn.key
    @xhttp path 

# ---- @0x013f571e ----
/etc/caddy/Caddyfile

# ---- @0x013f5734 ----
mkdir -p /var/www/html

# ---- @0x013f574c ----
mkdir -p /etc/nginx/ssl && test -f /etc/nginx/ssl/cdn.crt || openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj '/CN=cdn-origin' 2>/dev/null

# ---- @0x013f581d ----
chmod 644 /etc/nginx/ssl/cdn.key /etc/nginx/ssl/cdn.crt 2>/dev/null

# ---- @0x013f5899 ----
iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null; iptables -I INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null

# ---- @0x013f5910 ----
systemctl stop nginx 2>/dev/null; systemctl disable nginx 2>/dev/null; systemctl stop apache2 2>/dev/null; systemctl disable apache2 2>/dev/null; fuser -k 80/tcp 2>/dev/null

# ---- @0x013f59e1 ----
systemctl enable caddy >/dev/null 2>&1 && systemctl restart caddy

# ---- @0x013f5a24 ----
systemctl is-active caddy

# ---- @0x013f5a3f ----
fuser -k 80/tcp 2>/dev/null; sleep 2; systemctl restart caddy

# ---- @0x013f5aa2 ----
journalctl -u caddy --no-pager -n 10 2>&1

# ---- @0x013f5b51 ----
 ss -tlnp | grep :80

# ---- @0x013f5deb ----
docker network inspect remnawave-network -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'

# ---- @0x013f64a5 ----
docker restart remnanode

# ---- @0x013f64de ----
docker logs remnanode --tail=10 2>&1

# ---- @0x013f665f ----
     xray на exit-ноде не поднял BRIDGE_IN. Обычно причина одна из:

# ---- @0x013f67ee ----
     Проверить на exit: ss -ltn | grep 8888 ; docker logs remnanode | tail -20

# ---- @0x013f6b4a ----
  ❌ Docker не установился! Попробуй вручную: curl -fsSL https://get.docker.com | sh

# ---- @0x013f6be6 ----
  docker compose plugin не найден, устанавливаю...

# ---- @0x013f6db2 ----
  ❌ docker compose не установился!

# ---- @0x013f6de5 ----
  docker compose: 

# ---- @0x013f6e2e ----
mkdir -p /opt/remnawave

# ---- @0x013f6e9e ----
cd /opt/remnawave && docker compose down -v 2>/dev/null

# ---- @0x013f6edc ----
docker volume ls -q --filter name=remnawave

# ---- @0x013f6f0c ----
docker volume rm -f 

# ---- @0x013f7425 ----
/opt/remnawave/docker-compose.yml

# ---- @0x013f7611 ----
cd /opt/remnawave && docker compose down 2>/dev/null

# ---- @0x013f7678 ----
cd /opt/remnawave && docker compose pull

# ---- @0x013f76a8 ----
cd /opt/remnawave && docker compose up -d 2>&1

# ---- @0x013f76dc ----
  docker compose up ошибка: 

# ---- @0x013f7748 ----
RDOM=$(grep PANEL_DOMAIN /opt/remnawave/.env 2>/dev/null | head -1 | cut -d= -f2); curl -s -H "Host: ${RDOM:-localhost}" http://127.0.0.1:3000/api/auth/register -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 127.0.0.1' -o /dev/null -w '%{http_code}'

# ---- @0x013f7908 ----
docker compose -f /opt/remnawave/docker-compose.yml ps -a 2>&1

# ---- @0x013f796b ----
docker compose -f /opt/remnawave/docker-compose.yml logs --tail=50 2>&1

# ---- @0x013f79cb ----
dmesg | grep -i 'oom\|killed process' | tail -5 2>&1

# ---- @0x013f7ac2 ----
  После установки выполни: certbot --nginx -d 

# ---- @0x013f7b4e ----
;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;

# ---- @0x013f7fab ----
docker exec remnawave-db psql -U postgres -c "DELETE FROM api_tokens WHERE name = 'installer';"

# ---- @0x013f800c ----
Fudocker exec remnawave-db psql -U postgres -c "INSERT INTO api_tokens (uuid, name) VALUES ('

# ---- @0x013f8b20 ----
    ssl_certificate /etc/nginx/ssl/cdn.crt;

# ---- @0x013f8b4d ----
    ssl_certificate_key /etc/nginx/ssl/cdn.key;

# ---- @0x013f8bc7 ----
}u/etc/nginx/conf.d/hy2-ping.conf

# ---- @0x013f8c16 ----
 (nginx SSL) для пинга HY2

# ---- @0x013f8c84 ----
ufw allow 8888/tcp 2>/dev/null; iptables -I INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null

# ---- @0x013f8ce1 ----
Fuufw allow 8888/tcp 2>/dev/null; iptables -I INPUT -p tcp --dport 8888 -j ACCEPT 2>/dev/null

# ---- @0x013f8e20 ----
  HY2: self-signed, после DNS: certbot certonly --webroot -w /var/www/certbot -d 

# ---- @0x013f92f4 ----
docker logs remnanode --tail=15 2>&1

# ---- @0x013f936a ----
  Нода синхронизирована, xray слушает :

# ---- @0x013f93bd ----
  xray так и не занял :

# ---- @0x013f93f7 ----
  ВНИМАНИЕ: xray ноды не поднялся на :

# ---- @0x013f945c ----
  Исправь вручную: docker restart remnanode (2-3 раза), затем ss -ltn | grep :

# ---- @0x013fb2ec ----
ss -ltn 2>/dev/null | grep -c ':

# ---- @0x013fbcd7 ----
  Проверь: ss -ltn | grep :

# ---- @0x013fbcfb ----
 ; docker logs remnanode | tail -20

# ---- @0x013fbf42 ----
docker ps --format '{{.Names}} {{.Status}}' | grep remnanode

# ---- @0x013fc1f0 ----
nginx openssl curl sqlite3 ca-certificates gnupg sshpass certbot

# ---- @0x013fc28e ----
ufw allow 80/tcp >/dev/null 2>&1

# ---- @0x013fc2b3 ----
ufw allow 443/tcp >/dev/null 2>&1

# ---- @0x013fc2d9 ----
ufw reload >/dev/null 2>&1

# ---- @0x013fc32b ----
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile

# ---- @0x013fc388 ----
grep -q swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab

# ---- @0x013fc46d ----
mkdir -p /etc/nginx/ssl /etc/nginx/sites-available /etc/nginx/sites-enabled

# ---- @0x013fc4bd ----
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/nginx/ssl/cdn.key -out /etc/nginx/ssl/cdn.crt -subj "/CN=cdn-origin" 2>/dev/null

# ---- @0x013fc582 ----
  ❌ openssl не смог создать сертификат — nginx не запустится без SSL!

# ---- @0x013fdfcc ----
RDOM=$(grep -oP "PANEL_DOMAIN=\K.*" /opt/remnawave/.env 2>/dev/null); curl -s -H "X-Forwarded-Proto: https" -H "X-Forwarded-For: 127.0.0.1" -H "Host: ${RDOM:-localhost}" http://127.0.0.1:3000/api/auth/login

# ---- @0x013fe09c ----
curl -s http://127.0.0.1:3001/health

# ---- @0x013fe0f5 ----
  Убедись что панель запущена: cd /opt/remnawave && docker compose up -d

# ---- @0x013ff3b3 ----
/opt/remnanode/xray-custom

# ---- @0x013ff3cf ----
nuuser www-data;
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


# ---- @0x013ff63b ----
nu/usr/local/share/xray

# ---- @0x013ff69d ----
ntu/etc/nginx/ssl/cdn.crt

# ---- @0x0140209a ----
nginx_cascade_default

