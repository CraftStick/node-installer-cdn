#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тесты node-installer-cdn.py.

Установщик целиком состоит из побочных эффектов на живом сервере, поэтому
здесь проверяется то, что можно проверить без root и без сети: генераторы
конфигов, валидация ввода, экранирование для шелла, разбор ответов API и
логика оркестрации на подставном api().

    python3 -m unittest discover -v      # или: python3 test_installer.py
"""

import io
import json
import base64
import hmac
import hashlib
import os
import re
import contextlib
import importlib.util
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC = importlib.util.spec_from_file_location(
    "installer", os.path.join(_HERE, "node-installer-cdn.py"))
inst = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(inst)


def quiet(fn, *a, **kw):
    """Вызвать fn, проглотив её вывод в терминал."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*a, **kw)
    return result, buf.getvalue()


@contextlib.contextmanager
def capture_sql(store):
    """Подменить xui_sql (и restart через run) на запись SQL в store['sql']."""
    orig_sql, orig_run = inst.xui_sql, inst.run

    def fake_sql(sql):
        store["sql"] = sql
        return True                      # «SQL применился» — иначе вызывающий бросит

    inst.xui_sql, inst.run = fake_sql, lambda cmd, **kw: ("", 0)
    try:
        yield store
    finally:
        inst.xui_sql, inst.run = orig_sql, orig_run


class TestValidation(unittest.TestCase):
    def test_domain_accepts_real_domains(self):
        for d in ("example.com", "origin.example.com", "a-b.co.uk",
                  "xn--80ak6aa92e.com", "1.2.3.example.org"):
            self.assertRegex(d, inst.RE_DOMAIN, d)

    def test_domain_rejects_junk(self):
        for d in ("example", "-example.com", "example-.com", "exa mple.com",
                  "http://example.com", "example.com/path", "приме.рф", ""):
            self.assertIsNone(inst.RE_DOMAIN.match(d), d)

    def test_xpath_accepts_generated_paths(self):
        for _ in range(200):
            self.assertIsNotNone(inst.RE_XPATH.match(inst.rand_path()))

    def test_xpath_rejects_shell_metacharacters(self):
        for p in ("/a;rm -rf /", "/a$(id)", "/a`id`", "/a|b", "abc", "",
                  "/a b", "/a'b", '/a"b'):
            self.assertIsNone(inst.RE_XPATH.match(p), p)


class TestHomoglyphHint(unittest.TestCase):
    def test_latin_domain_has_no_hint(self):
        self.assertEqual(inst.homoglyph_hint("example.com"), "")

    def test_cyrillic_lookalike_is_named_and_fixed(self):
        hint = inst.homoglyph_hint("ехample.com")   # 'е' и 'х' кириллические
        self.assertIn("кириллица вместо латиницы", hint)
        self.assertIn("example.com", hint)

    def test_full_cyrillic_domain_suggests_punycode(self):
        hint = inst.homoglyph_hint("пример.рф")
        self.assertIn("punycode", hint)

    def test_other_non_latin_is_reported_with_codepoint(self):
        hint = inst.homoglyph_hint("exαmple.com")   # греческая alpha
        self.assertIn("U+03B1", hint)


class TestSecrets(unittest.TestCase):
    PANEL_RE = re.compile(r"^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9]).{24,}$")

    def test_password_always_satisfies_panel_policy(self):
        for _ in range(500):
            self.assertRegex(inst.rand_password(), self.PANEL_RE)

    def test_password_shorter_than_24_is_raised_to_24(self):
        self.assertGreaterEqual(len(inst.rand_password(8)), 24)

    def test_rand_length_and_alphabet(self):
        v = inst.rand(32, "ab")
        self.assertEqual(len(v), 32)
        self.assertTrue(set(v) <= set("ab"))

    def test_generated_values_differ(self):
        self.assertNotEqual(inst.rand_password(), inst.rand_password())
        self.assertNotEqual(inst.rand_path(), inst.rand_path())


class TestShellQuoting(unittest.TestCase):
    def test_shq_wraps_dangerous_values_in_single_quotes(self):
        # в одинарных кавычках шелл не раскрывает ни ;, ни `, ни $
        for raw in ("a;rm -rf /", "`id`", "$(id)", "a b", "a|b"):
            quoted = inst.shq(raw)
            self.assertTrue(quoted.startswith("'") and quoted.endswith("'"), raw)
            self.assertEqual(quoted, "'%s'" % raw)

    def test_shq_closes_and_reopens_on_embedded_quote(self):
        self.assertEqual(inst.shq("it's"), "'it'\"'\"'s'")

    def test_shq_leaves_safe_values_bare(self):
        self.assertEqual(inst.shq("/opt/remnanode/.env"), "/opt/remnanode/.env")

    def test_ssh_prefix_quotes_host_and_user(self):
        pref = inst._ssh_prefix({"ip": "1.2.3.4; touch /pwned", "user": "root"})
        self.assertIn("'root@1.2.3.4; touch /pwned'", pref)

    def test_ssh_prefix_uses_key_when_given_and_no_sshpass(self):
        pref = inst._ssh_prefix({"ip": "1.2.3.4", "key": "/root/id_rsa"})
        self.assertIn("-i /root/id_rsa", pref)
        self.assertNotIn("sshpass", pref)

    def test_ssh_prefix_uses_sshpass_env_not_argv(self):
        pref = inst._ssh_prefix({"ip": "1.2.3.4", "pass": "hunter2"})
        self.assertIn("sshpass -e", pref)
        self.assertNotIn("hunter2", pref)

    def test_ssh_prefix_honours_custom_port(self):
        self.assertIn("-p 2222", inst._ssh_prefix({"ip": "1.2.3.4", "port": 2222}))

    def test_run_remote_wraps_quotes_safely(self):
        seen = {}
        orig = inst.run
        inst.run = lambda cmd, **kw: (seen.setdefault("cmd", cmd), 0)
        try:
            inst.run_remote({"ip": "1.2.3.4", "pass": "x"}, "echo 'it''s'")
        finally:
            inst.run = orig
        # каждая одинарная кавычка закрыта и снова открыта — строка остаётся
        # одним аргументом ssh
        self.assertEqual(seen["cmd"].count("'"), seen["cmd"].count("'"))
        self.assertIn("'\\''", seen["cmd"])


class TestSshHost(unittest.TestCase):
    def test_strips_scheme_path_and_credentials(self):
        cases = {
            "https://panel.example.com/xyz": "panel.example.com",
            "http://user@panel.example.com": "panel.example.com",
            "panel.example.com:8443": "panel.example.com",
            "1.2.3.4": "1.2.3.4",
            "https://1.2.3.4/admin?x=1": "1.2.3.4",
            "": "",
        }
        for raw, want in cases.items():
            self.assertEqual(inst.ssh_host(raw), want, raw)


class TestXrayInbounds(unittest.TestCase):
    def test_xhttp_inbound_shape(self):
        ib = inst.build_xhttp_inbound(4443, "/uploadfiles/abc", "VK_CDN")
        self.assertEqual(ib["listen"], "127.0.0.1")   # TLS снимает nginx
        self.assertEqual(ib["port"], 4443)
        self.assertEqual(ib["protocol"], "vless")
        self.assertEqual(ib["settings"]["clients"], [])
        xs = ib["streamSettings"]["xhttpSettings"]
        self.assertEqual(ib["streamSettings"]["security"], "none")
        self.assertEqual(xs["mode"], "packet-up")
        self.assertEqual(xs["uplinkHTTPMethod"], "get")

    def test_xhttp_path_is_normalised_to_directory(self):
        for raw in ("/abc", "abc", "/abc/", "abc/"):
            ib = inst.build_xhttp_inbound(4443, raw, "T")
            self.assertEqual(ib["streamSettings"]["xhttpSettings"]["path"], "/abc/")

    def test_xhttp_inbound_carries_client_when_uuid_given(self):
        ib = inst.build_xhttp_inbound(4443, "/a", "T", uuid="U-1")
        self.assertEqual(ib["settings"]["clients"], [{"id": "U-1", "email": "user1"}])

    def test_grpc_inbound_is_reality_on_all_interfaces(self):
        ib = inst.build_grpc_inbound(2053, "U", "priv", "pub", "ab12", "svc")
        self.assertEqual(ib["listen"], "0.0.0.0")
        rs = ib["streamSettings"]["realitySettings"]
        self.assertEqual(rs["privateKey"], "priv")
        self.assertEqual(rs["shortIds"], ["ab12"])
        self.assertEqual(rs["dest"], inst.REALITY_DEST)
        self.assertNotIn("pub", json.dumps(rs))   # публичный ключ — только клиенту

    def test_inbounds_are_json_serialisable(self):
        json.dumps(inst.build_xhttp_inbound(4443, "/a", "T"))
        json.dumps(inst.build_grpc_inbound(2053, "U", "p", "P", "s", "svc"))


class TestXrayProfile(unittest.TestCase):
    def test_config_is_wrapped_for_panel_3x(self):
        prof = inst.build_xray_profile("p1", [inst.build_xhttp_inbound(4443, "/a", "T")])
        self.assertEqual(prof["name"], "p1")
        self.assertIn("config", prof)          # плоский {name,inbounds} панель отбивает
        self.assertIn("inbounds", prof["config"])

    def test_torrents_blocked_and_private_direct(self):
        rules = inst.build_xray_profile("p", [])["config"]["routing"]["rules"]
        by_out = {r["outboundTag"]: r for r in rules}
        self.assertIn("bittorrent", by_out["block"]["protocol"])
        self.assertIn("geoip:private", by_out["direct"]["ip"])

    def test_dns_is_ipv4_only(self):
        dns = inst.build_xray_profile("p", [])["config"]["dns"]
        self.assertEqual(dns["queryStrategy"], "UseIPv4")


class TestNginxOriginConfig(unittest.TestCase):
    def setUp(self):
        self.conf = inst.nginx_cdn_origin_config(4443, "/uploadfiles/abc")

    def test_no_unsubstituted_placeholders(self):
        self.assertNotIn("%s", self.conf)
        self.assertNotIn("%d", self.conf)

    def test_bare_path_returns_404_and_subtree_is_proxied(self):
        self.assertIn("location = /uploadfiles/abc {", self.conf)
        self.assertIn("return 404;", self.conf)
        self.assertIn("location /uploadfiles/abc/ {", self.conf)

    def test_exact_404_location_precedes_prefix_location(self):
        self.assertLess(self.conf.index("location = /uploadfiles/abc {"),
                        self.conf.index("location /uploadfiles/abc/ {"))

    def test_upstream_points_at_local_xray_port(self):
        self.assertIn("server 127.0.0.1:4443;", self.conf)

    def test_buffering_and_caching_are_off(self):
        for directive in ("proxy_buffering off", "proxy_request_buffering off",
                          "proxy_cache off", "gzip off"):
            self.assertIn(directive, self.conf)

    def test_acme_webroot_is_reachable(self):
        self.assertIn("location /.well-known/acme-challenge/", self.conf)
        self.assertIn("root /var/www/certbot;", self.conf)

    def test_listens_on_v4_and_v6(self):
        self.assertIn("listen 443 ssl http2 default_server;", self.conf)
        self.assertIn("listen [::]:443 ssl http2 default_server;", self.conf)

    def test_custom_cert_paths_are_used(self):
        c = inst.nginx_cdn_origin_config(4443, "/a", crt="/x/c.pem", key="/x/k.pem")
        self.assertIn("ssl_certificate /x/c.pem;", c)
        self.assertIn("ssl_certificate_key /x/k.pem;", c)


class TestNginxPanelProxy(unittest.TestCase):
    def test_redirects_http_and_proxies_https(self):
        c = inst.nginx_panel_proxy("panel.example.com", 3000)
        self.assertNotIn("%s", c)
        self.assertIn("return 301 https://$host$request_uri;", c)
        self.assertIn("proxy_pass http://127.0.0.1:3000;", c)
        self.assertIn("server_name panel.example.com;", c)

    def test_letsencrypt_live_paths_can_be_injected(self):
        c = inst.nginx_panel_proxy("d.com", 3000,
                                   "/etc/letsencrypt/live/d.com/fullchain.pem",
                                   "/etc/letsencrypt/live/d.com/privkey.pem")
        self.assertIn("ssl_certificate /etc/letsencrypt/live/d.com/fullchain.pem;", c)


class TestDecoyAndCompose(unittest.TestCase):
    def test_decoy_page_renders_domain_and_keeps_css(self):
        html = inst.DECOY_HTML.format(domain="example.com")
        self.assertIn("<h1>example.com</h1>", html)
        self.assertIn("margin: 0;", html)          # экранированные {{ }} уцелели
        self.assertNotIn("{domain}", html)

    def test_panel_compose_has_no_leftover_format_fields(self):
        compose = inst.REMNAWAVE_COMPOSE.replace("{pg_pass}", "SECRET")
        self.assertNotIn("{", compose.replace("{pg_pass}", ""))
        self.assertIn("POSTGRES_PASSWORD: SECRET", compose)
        self.assertIn(inst.POSTGRES_IMAGE, compose)
        self.assertIn(inst.REMNAWAVE_IMAGE, compose)

    def test_panel_ports_are_bound_to_loopback_only(self):
        self.assertIn('"127.0.0.1:3000:3000"', inst.REMNAWAVE_COMPOSE)
        self.assertIn('"127.0.0.1:3001:3001"', inst.REMNAWAVE_COMPOSE)
        self.assertNotIn('"0.0.0.0:', inst.REMNAWAVE_COMPOSE)

    def test_valkey_listens_on_socket_not_tcp(self):
        self.assertIn("--port 0", inst.REMNAWAVE_COMPOSE)
        self.assertIn("--unixsocket /var/run/valkey/valkey.sock",
                      inst.REMNAWAVE_COMPOSE)

    def test_node_compose_mounts_custom_xray(self):
        self.assertIn("/opt/remnanode/xray-custom:/usr/local/bin/xray",
                      inst.REMNANODE_COMPOSE)
        self.assertIn("network_mode: host", inst.REMNANODE_COMPOSE)


class TestApiJwt(unittest.TestCase):
    def setUp(self):
        self.secret = "s3cr3t"
        self.uuid = "11111111-2222-3333-4444-555555555555"
        self.jwt = inst._sign_api_jwt(self.secret, self.uuid)

    def _decode(self, seg):
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

    def test_has_three_segments_and_hs256_header(self):
        parts = self.jwt.split(".")
        self.assertEqual(len(parts), 3)
        self.assertEqual(self._decode(parts[0]), {"alg": "HS256", "typ": "JWT"})

    def test_payload_carries_api_role_and_uuid(self):
        payload = self._decode(self.jwt.split(".")[1])
        self.assertEqual(payload["role"], "API")
        self.assertEqual(payload["uuid"], self.uuid)
        self.assertEqual(payload["exp"] - payload["iat"], 365 * 86400)

    def test_signature_verifies_against_independent_hmac(self):
        head, body, sig = self.jwt.split(".")
        want = base64.urlsafe_b64encode(hmac.new(
            self.secret.encode(), ("%s.%s" % (head, body)).encode(),
            hashlib.sha256).digest()).rstrip(b"=").decode()
        self.assertEqual(sig, want)

    def test_no_base64_padding_leaks_into_token(self):
        self.assertNotIn("=", self.jwt)

    def test_wrong_secret_produces_different_signature(self):
        other = inst._sign_api_jwt("other", self.uuid)
        self.assertNotEqual(self.jwt.split(".")[2], other.split(".")[2])


class FakeApi:
    """Подставной api(method, path, data) -> (resp, code)."""

    def __init__(self, replies):
        self.replies = replies          # {(method, path): (resp, code)}
        self.calls = []

    def __call__(self, method, path, data=None):
        self.calls.append((method, path, data))
        return self.replies.get((method, path), ({"error": "no route"}, 404))


class TestConfigProfile(unittest.TestCase):
    def test_returns_uuid_and_tag_to_uuid_map(self):
        api = FakeApi({("POST", "config-profiles"): (
            {"response": {"uuid": "P-1", "inbounds": [
                {"tag": "VK_CDN", "uuid": "I-1"},
                {"tag": "grpc-reality-2053", "uuid": "I-2"}]}}, 201)})
        (prof, tags), _ = quiet(
            inst.create_config_profile, api, "cdn-x",
            [inst.build_xhttp_inbound(4443, "/a", "VK_CDN")])
        self.assertEqual(prof, "P-1")
        self.assertEqual(tags, {"VK_CDN": "I-1", "grpc-reality-2053": "I-2"})

    def test_falls_back_to_primary_inbound_when_panel_rejects_full_config(self):
        calls = []

        def api(method, path, data=None):
            calls.append(data)
            if len(data["config"]["inbounds"]) > 1:
                return {"errorCode": "A112"}, 400
            return {"response": {"uuid": "P-2",
                                 "inbounds": [{"tag": "VK_CDN", "uuid": "I-1"}]}}, 201

        inbounds = [inst.build_xhttp_inbound(4443, "/a", "VK_CDN"),
                    inst.build_grpc_inbound(2053, "U", "p", "P", "s", "svc")]
        (prof, tags), out = quiet(inst.create_config_profile, api, "cdn-x", inbounds)
        self.assertEqual(prof, "P-2")
        self.assertEqual(len(calls), 2)                      # полный, затем урезанный
        self.assertEqual(len(calls[1]["config"]["inbounds"]), 1)
        self.assertIn("только основной вход", out)

    def test_reports_failure_without_raising(self):
        api = FakeApi({("POST", "config-profiles"): ({"message": "nope"}, 400)})
        (prof, tags), out = quiet(inst.create_config_profile, api, "cdn-x",
                                  [inst.build_xhttp_inbound(4443, "/a", "T")])
        self.assertIsNone(prof)
        self.assertEqual(tags, {})
        self.assertIn("отвергнут", out)


class TestHostAndSquad(unittest.TestCase):
    def test_host_body_points_at_cdn_and_binds_inbound_uuid(self):
        api = FakeApi({("POST", "hosts"): ({"response": {"uuid": "H-1"}}, 201)})
        huuid, _ = quiet(inst.create_remnawave_host, api, "P-1", "VK_CDN",
                         "cdn.example.net", "/uploadfiles/abc", inbound_uuid="I-1")
        self.assertEqual(huuid, "H-1")
        body = api.calls[0][2]
        self.assertEqual(body["address"], "cdn.example.net")
        self.assertEqual(body["sni"], "cdn.example.net")
        self.assertEqual(body["path"], "/uploadfiles/abc/")
        self.assertEqual(body["configProfileInboundUuid"], "I-1")
        # оба написания xhttp-extra: панели 2.7.x и 2.8+
        self.assertEqual(body["xhttpExtraParams"]["mode"], "packet-up")
        self.assertEqual(body["xHttpExtraParams"]["mode"], "packet-up")

    def test_host_is_skipped_without_profile(self):
        api = FakeApi({})
        huuid, out = quiet(inst.create_remnawave_host, api, None, "T", "c", "/a")
        self.assertIsNone(huuid)
        self.assertEqual(api.calls, [])
        self.assertIn("нет profile_uuid", out)

    def test_update_host_moves_address_sni_and_host(self):
        api = FakeApi({("PATCH", "hosts"): ({"response": {"uuid": "H-1"}}, 200)})
        okd, _ = quiet(inst.update_host_address, api, "H-1", "xxx.cdn.twcstorage.ru")
        self.assertTrue(okd)
        body = api.calls[0][2]
        self.assertEqual(body["uuid"], "H-1")
        for field in ("address", "sni", "host"):
            self.assertEqual(body[field], "xxx.cdn.twcstorage.ru")

    def test_update_host_is_noop_without_uuid_or_domain(self):
        api = FakeApi({})
        self.assertFalse(quiet(inst.update_host_address, api, None, "c.net")[0])
        self.assertFalse(quiet(inst.update_host_address, api, "H-1", "")[0])
        self.assertEqual(api.calls, [])

    def test_update_host_reports_rejection(self):
        api = FakeApi({("PATCH", "hosts"): ({"message": "bad"}, 400)})
        okd, out = quiet(inst.update_host_address, api, "H-1", "c.net")
        self.assertFalse(okd)
        self.assertIn("вручную", out)

    def test_default_squad_is_preferred_over_first(self):
        api = FakeApi({("GET", "internal-squads"): (
            {"response": {"internalSquads": [{"name": "Other", "uuid": "S-9"},
                                             {"name": "Default-Squad",
                                              "uuid": "S-1"}]}}, 200)})
        self.assertEqual(inst.find_default_squad(api), "S-1")

    def test_first_squad_used_when_no_default(self):
        api = FakeApi({("GET", "internal-squads"): (
            {"response": {"internalSquads": [{"name": "Other", "uuid": "S-9"}]}}, 200)})
        self.assertEqual(inst.find_default_squad(api), "S-9")

    def test_no_squads_returns_none(self):
        api = FakeApi({("GET", "internal-squads"): ({"response": {}}, 200)})
        self.assertIsNone(inst.find_default_squad(api))

    def test_inbounds_are_patched_on_collection_root(self):
        api = FakeApi({
            ("GET", "internal-squads"): (
                {"response": {"internalSquads": [{"name": "Default-Squad",
                                                  "uuid": "S-1"}]}}, 200),
            ("PATCH", "internal-squads"): ({"response": {}}, 200)})
        _, out = quiet(inst.add_inbounds_to_squad, api, ["I-1", None, "I-2"])
        patch = api.calls[-1]
        self.assertEqual(patch[1], "internal-squads")        # не /internal-squads/<uuid>
        self.assertEqual(patch[2], {"uuid": "S-1", "inbounds": ["I-1", "I-2"]})
        self.assertIn("2 инбаунд", out)

    def test_squad_not_touched_when_no_inbound_uuids(self):
        api = FakeApi({("GET", "internal-squads"): (
            {"response": {"internalSquads": [{"name": "Default-Squad",
                                              "uuid": "S-1"}]}}, 200)})
        _, out = quiet(inst.add_inbounds_to_squad, api, [None, None])
        self.assertNotIn("PATCH", [c[0] for c in api.calls])
        self.assertIn("сквад не обновлён", out)


class TestCreateUser(unittest.TestCase):
    def test_subscription_url_built_from_short_uuid(self):
        api = FakeApi({
            ("GET", "internal-squads"): (
                {"response": {"internalSquads": [{"name": "Default-Squad",
                                                  "uuid": "S-1"}]}}, 200),
            ("POST", "users"): (
                {"response": {"uuid": "U-1", "shortUuid": "abc123"}}, 201)})
        url, _ = quiet(inst.create_remnawave_user, api, "user1", "V-1", "d.com")
        self.assertEqual(url, "https://d.com/api/sub/abc123")
        body = [c for c in api.calls if c[0] == "POST"][0][2]
        self.assertEqual(body["vlessUuid"], "V-1")
        self.assertEqual(body["activeInternalSquads"], ["S-1"])

    def test_missing_short_uuid_yields_no_url(self):
        api = FakeApi({("GET", "internal-squads"): ({"response": {}}, 200),
                       ("POST", "users"): ({"message": "exists"}, 400)})
        url, out = quiet(inst.create_remnawave_user, api, "user1", "V-1", "d.com")
        self.assertEqual(url, "")
        self.assertIn("Ответ создания юзера", out)


class TestRwApiSsh(unittest.TestCase):
    """Ответ curl'а разбирается на тело и HTTP-код."""

    def _call(self, remote_output, token="T"):
        seen = {}
        orig = inst.run_remote

        def fake(cred, cmd, timeout=600):
            seen["cmd"] = cmd
            return remote_output, 0

        inst.run_remote = fake
        try:
            return inst.rw_api_ssh({"ip": "1.2.3.4"}, token, "GET", "nodes"), seen
        finally:
            inst.run_remote = orig

    def test_success_body_and_code(self):
        (body, code), _ = self._call('{"response":{"a":1}}\n200')
        self.assertEqual(code, 200)
        self.assertEqual(body, {"response": {"a": 1}})

    def test_error_code_is_not_masked_as_success(self):
        (body, code), _ = self._call('{"errorCode":"A112"}\n400')
        self.assertEqual(code, 400)          # раньше здесь всегда было 200
        self.assertEqual(body["errorCode"], "A112")

    def test_empty_body_keeps_code(self):
        (body, code), _ = self._call("\n401")
        self.assertEqual(code, 401)
        self.assertIn("error", body)

    def test_non_json_body_is_reported(self):
        (body, code), _ = self._call("<html>502</html>\n502")
        self.assertEqual(code, 502)
        self.assertEqual(body["error"], "invalid JSON")

    def test_token_is_sent_and_panel_file_not_read(self):
        _, seen = self._call('{}\n200', token="TOK")
        self.assertIn("Authorization: Bearer TOK", seen["cmd"])
        self.assertNotIn(".panel_token", seen["cmd"])

    def test_browser_client_type_header_always_present(self):
        _, seen = self._call('{}\n200')
        self.assertIn("X-Remnawave-Client-Type: browser", seen["cmd"])

    def test_body_travels_base64_encoded(self):
        orig = inst.run_remote
        seen = {}
        inst.run_remote = lambda cred, cmd, timeout=600: (seen.setdefault("cmd", cmd),
                                                          "{}\n200")[1:] and ("{}\n200", 0)
        try:
            inst.rw_api_ssh({"ip": "1.2.3.4"}, "T", "POST", "nodes",
                            {"name": "it's a node"})
        finally:
            inst.run_remote = orig
        payload = base64.b64encode(json.dumps({"name": "it's a node"}).encode()).decode()
        self.assertIn(payload, seen["cmd"])


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig_path, self._orig_resume = inst.STATE_PATH, inst._RESUME
        inst.STATE_PATH = os.path.join(self.tmp, "state.json")
        inst.state_clear()

    def tearDown(self):
        inst.state_clear()
        inst.STATE_PATH, inst._RESUME = self._orig_path, self._orig_resume

    def test_saved_state_round_trips(self):
        inst._STATE["answers"]["Домен"] = "example.com"
        inst.state_done("wipe")
        self.assertTrue(inst.state_load())
        self.assertEqual(inst._STATE["answers"]["Домен"], "example.com")
        self.assertIn("wipe", inst._STATE["done"])

    def test_state_file_is_root_only(self):
        inst.state_done("wipe")
        self.assertEqual(os.stat(inst.STATE_PATH).st_mode & 0o777, 0o600)

    def test_done_is_recorded_once(self):
        inst.state_done("wipe")
        inst.state_done("wipe")
        self.assertEqual(inst._STATE["done"].count("wipe"), 1)

    def test_is_done_only_counts_while_resuming(self):
        inst.state_done("wipe")
        inst._RESUME = False
        self.assertFalse(inst.state_is_done("wipe"))
        inst._RESUME = True
        self.assertTrue(inst.state_is_done("wipe"))

    def test_value_is_stable_across_resume(self):
        first = inst.state_value("path", lambda: "/generated/once")
        inst._RESUME = True
        self.assertEqual(inst.state_value("path", lambda: "/something/else"), first)

    def test_clear_removes_file_and_memory(self):
        inst.state_done("wipe")
        inst.state_clear()
        self.assertFalse(os.path.exists(inst.STATE_PATH))
        self.assertEqual(inst._STATE["done"], [])

    def test_corrupt_state_file_is_ignored(self):
        with open(inst.STATE_PATH, "w") as f:
            f.write("{not json")
        self.assertFalse(inst.state_load())


class TestWriteFile(unittest.TestCase):
    def test_creates_parents_and_applies_mode(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "deep", "nested", ".env")
        inst.write_file(path, "SECRET=1\n", mode=0o600)
        with open(path) as f:
            self.assertEqual(f.read(), "SECRET=1\n")
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_bare_filename_has_no_parent_to_create(self):
        tmp = tempfile.mkdtemp()
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            inst.write_file("plain.txt", "x")
            self.assertTrue(os.path.exists(os.path.join(tmp, "plain.txt")))
        finally:
            os.chdir(cwd)


class TestWriteRemote(unittest.TestCase):
    def test_content_travels_as_base64_and_path_is_quoted(self):
        seen = {}
        orig = inst.run_remote
        inst.run_remote = lambda cred, cmd, **kw: (seen.setdefault("cmd", cmd), ("", 0))[1]
        try:
            inst.write_remote({"ip": "1.2.3.4"}, "/opt/x/.env",
                              "SECRET='a b'\n", mode=0o600)
        finally:
            inst.run_remote = orig
        payload = base64.b64encode("SECRET='a b'\n".encode()).decode()
        self.assertIn(payload, seen["cmd"])
        self.assertIn("chmod 600 /opt/x/.env", seen["cmd"])
        # секрет уходит только внутри base64, открытым текстом его в команде нет
        self.assertNotIn("SECRET='a b'", seen["cmd"].replace(payload, ""))

    def test_path_with_spaces_is_quoted(self):
        seen = {}
        orig = inst.run_remote
        inst.run_remote = lambda cred, cmd, **kw: (seen.setdefault("cmd", cmd), ("", 0))[1]
        try:
            inst.write_remote({"ip": "1.2.3.4"}, "/opt/a b/.env", "x")
        finally:
            inst.run_remote = orig
        self.assertIn("'/opt/a b/.env'", seen["cmd"])


class TestXuiSqlEscaping(unittest.TestCase):
    def test_json_single_quotes_are_doubled_for_sqlite(self):
        captured = {}
        with capture_sql(captured):
            ok_flag, _ = quiet(inst.xui_cdn_inbound, "vk", 4443, "/upload/a",
                               "u-1", "sub-1")
        self.assertTrue(ok_flag)
        sql = captured["sql"]
        self.assertIn("'u-1'", sql)
        self.assertIn("'sub-1'", sql)
        # значения-JSON вставлены как литералы, кавычки внутри удвоены
        for chunk in re.findall(r"'(\{.*?\})'(?=[,)])", sql):
            self.assertNotIn("''", chunk.replace("''''", ""))

    def test_inbound_listens_on_loopback(self):
        captured = {}
        with capture_sql(captured):
            quiet(inst.xui_cdn_inbound, "vk", 4443, "/upload/a", "u-1", "sub-1")
        self.assertIn("'127.0.0.1',4443", captured["sql"])

    def test_xhttp_path_reaches_the_stream_settings(self):
        captured = {}
        with capture_sql(captured):
            quiet(inst.xui_cdn_inbound, "vk", 4443, "/upload/a", "u-1", "sub-1")
        self.assertIn('\\"path\\": \\"/upload/a/\\"'.replace("\\", ""),
                      captured["sql"])


class TestXuiGrpcInbound(unittest.TestCase):
    """Порт gRPC у 3x-ui случайный — его надо и вернуть, и вписать в SQL,
    иначе файрвол откроет не тот порт (см. install_3xui)."""

    def _run(self):
        captured = {}
        orig_keys = inst.gen_x25519
        inst.gen_x25519 = lambda cred=None: ("PRIV", "PUB")
        try:
            with capture_sql(captured):
                reality, _ = quiet(inst.xui_grpc_inbound, "U-1")
        finally:
            inst.gen_x25519 = orig_keys
        self.assertIsNotNone(reality)
        return reality, captured["sql"]

    def test_returns_everything_the_client_needs(self):
        reality, _ = self._run()
        self.assertEqual(reality["pbk"], "PUB")
        self.assertEqual(set(reality), {"pbk", "sid", "service", "port"})
        self.assertTrue(0 < reality["port"] < 65536)

    def test_returned_port_is_the_one_written_to_the_database(self):
        reality, sql = self._run()
        self.assertIn(",%d,'vless'" % reality["port"], sql)

    def test_private_key_never_leaves_the_server(self):
        reality, _ = self._run()
        self.assertNotIn("PRIV", json.dumps(reality))

    def test_no_keys_means_no_inbound(self):
        orig = inst.gen_x25519
        inst.gen_x25519 = lambda cred=None: (None, None)
        try:
            self.assertIsNone(quiet(inst.xui_grpc_inbound, "U-1")[0])
        finally:
            inst.gen_x25519 = orig


class TestUiHelpers(unittest.TestCase):
    def test_pad_truncates_and_fills_to_width(self):
        self.assertEqual(inst._pad("abc", 5), "abc  ")
        self.assertEqual(inst._pad("abcdef", 3), "abc")

    def test_card_rows_align_to_configured_width(self):
        _, out = quiet(inst.card, "T", [("Логин", "admin"), "просто строка"])
        lines = [ln for ln in out.splitlines() if ln.startswith(("╭", "│", "╰"))]
        self.assertTrue(lines)
        self.assertEqual({len(ln) for ln in lines}, {inst.UI_W})

    def test_banner_does_not_crash(self):
        _, out = quiet(inst.banner)
        self.assertIn(inst.INSTALLER_VERSION, out)

    def test_colour_is_disabled_off_tty(self):
        self.assertEqual(inst._c(inst.C_OK, "x"), "x" if not inst._TTY
                         else "\033[%sm%s\033[0m" % (inst.C_OK, "x"))


class TestCdnInstructions(unittest.TestCase):
    def test_every_provider_prints_origin_and_path(self):
        for provider in inst.CDN_NAMES.values():
            _, out = quiet(inst.print_cdn_instructions, provider,
                           "origin.example.com", "1.2.3.4", "/uploadfiles/abc")
            self.assertIn("origin.example.com", out, provider)
            self.assertIn("/uploadfiles/abc", out, provider)
            self.assertNotIn("%s", out, provider)

    def test_query_string_warning_present_everywhere(self):
        for provider in inst.CDN_NAMES.values():
            _, out = quiet(inst.print_cdn_instructions, provider,
                           "origin.example.com", "1.2.3.4", "/a/b")
            self.assertIn("query", out.lower(), provider)

    def test_unknown_provider_is_not_fatal(self):
        _, out = quiet(inst.print_cdn_instructions, "nope", "o.com", "1.2.3.4", "/a")
        self.assertIn("o.com", out)


class TestConstants(unittest.TestCase):
    def test_cdn_names_and_labels_match_up(self):
        self.assertEqual(set(inst.CDN_NAMES), set(inst.CDN_LABELS))

    def test_xhttp_port_is_in_range(self):
        self.assertTrue(0 < inst.XHTTP_PORT < 65536)

    def test_cert_paths_are_absolute(self):
        self.assertTrue(inst.CDN_CRT.startswith("/"))
        self.assertTrue(inst.CDN_KEY.startswith("/"))

    def test_sysctl_tuning_enables_bbr(self):
        self.assertIn("tcp_congestion_control = bbr", inst.SYSCTL_TUNING)
        self.assertIn("default_qdisc = fq", inst.SYSCTL_TUNING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
