#!/usr/bin/env python3
"""Unit tests for bola_sweep: oracle classification, swagger parsing, envelope building.

Uses the captured req.txt / res.txt as fixtures. Run:  python -m pytest test_oracle.py -q
(or plain `python test_oracle.py` for a dependency-free run).
"""

import json
import os

import bola_sweep as bs

HERE = os.path.dirname(os.path.abspath(__file__))


class FakeResponse:
    """Minimal stand-in for requests.Response for parse_envelope."""

    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code

    def json(self):
        return json.loads(self.text)


def _res_envelope_body():
    """Extract the JSON envelope body from the captured res.txt (skip HTTP headers)."""
    with open(os.path.join(HERE, "res.txt"), encoding="utf-8") as fh:
        raw = fh.read()
    # Body starts at the first line that is a JSON object.
    idx = raw.index("\n{")
    return raw[idx + 1 :].strip()


# --------------------------------------------------------------------------------------
# Oracle
# --------------------------------------------------------------------------------------


def test_real_access_response_is_access():
    body = _res_envelope_body()
    probe = bs.parse_envelope(FakeResponse(body))
    assert probe.ok
    assert probe.inner_status == 200
    assert probe.word_count >= bs.DEFAULT_WORD_THRESHOLD, probe.word_count
    assert probe.total_count == 1
    assert probe.is_access(bs.DEFAULT_WORD_THRESHOLD)


def test_denied_empty_is_not_access():
    body = json.dumps({"status": 403, "data": "", "headers": {}})
    probe = bs.parse_envelope(FakeResponse(body, status_code=200))
    assert not probe.is_access(bs.DEFAULT_WORD_THRESHOLD)


def test_denied_total_count_zero_is_not_access():
    inner = json.dumps({"items": [], "totalCount": 0, "partialResults": False})
    body = json.dumps({"status": 200, "data": inner, "headers": {}})
    probe = bs.parse_envelope(FakeResponse(body))
    assert probe.total_count == 0
    assert not probe.is_access(bs.DEFAULT_WORD_THRESHOLD)


def test_deny_marker_blocks_access():
    inner = "you are not authorized to view this object " + "word " * 40
    body = json.dumps({"status": 200, "data": inner, "headers": {}})
    probe = bs.parse_envelope(FakeResponse(body))
    assert probe.deny_marker
    assert not probe.is_access(bs.DEFAULT_WORD_THRESHOLD)


def test_non_json_is_not_ok():
    probe = bs.parse_envelope(FakeResponse("<html>login</html>", status_code=200))
    assert not probe.ok
    assert not probe.is_access(bs.DEFAULT_WORD_THRESHOLD)


# --------------------------------------------------------------------------------------
# Differential classification
# --------------------------------------------------------------------------------------


def _probe(access=True, words=200, inner=200, total=1, deny=False):
    return bs.Probe(
        ok=True,
        outer_status=200,
        inner_status=inner,
        word_count=words,
        total_count=total,
        deny_marker=deny,
    )


def test_classify_vulnerable():
    a = _probe()  # control: access
    b = _probe()  # forbidden: access
    c = bs.Probe(ok=True, inner_status=401, word_count=0, total_count=None)  # no-auth: denied
    verdict, _ = bs.classify(a, b, c, bs.DEFAULT_WORD_THRESHOLD)
    assert verdict == bs.VULNERABLE


def test_classify_denied():
    a = _probe()
    b = bs.Probe(ok=True, inner_status=200, word_count=3, total_count=0)  # forbidden: empty
    c = bs.Probe(ok=True, inner_status=401, word_count=0)
    verdict, _ = bs.classify(a, b, c, bs.DEFAULT_WORD_THRESHOLD)
    assert verdict == bs.DENIED


def test_classify_public_when_noauth_also_works():
    a = _probe()
    b = _probe()
    c = _probe()  # no-auth ALSO returns data
    verdict, _ = bs.classify(a, b, c, bs.DEFAULT_WORD_THRESHOLD)
    assert verdict == bs.PUBLIC


def test_classify_inconclusive_when_control_fails():
    a = bs.Probe(ok=True, inner_status=200, word_count=2, total_count=0)  # control failed
    b = _probe()
    c = bs.Probe(ok=True, inner_status=401, word_count=0)
    verdict, _ = bs.classify(a, b, c, bs.DEFAULT_WORD_THRESHOLD)
    assert verdict == bs.INCONCLUSIVE


def test_classify_heuristic_no_control():
    b = _probe()
    verdict, _ = bs.classify(None, b, None, bs.DEFAULT_WORD_THRESHOLD)
    assert verdict == bs.VULNERABLE


def test_negative_control_suppresses_boilerplate_fp():
    # Endpoint returns ~200 words even for a garbage id -> word count proves nothing.
    b = _probe(words=210)
    n = _probe(words=200)  # garbage id returns near-identical content
    verdict, _ = bs.classify(None, b, None, bs.DEFAULT_WORD_THRESHOLD, n)
    assert verdict == bs.INCONCLUSIVE
    # Differential mode should also refuse to call it vulnerable.
    verdict2, _ = bs.classify(_probe(), b, bs.Probe(ok=True, inner_status=401, word_count=0),
                              bs.DEFAULT_WORD_THRESHOLD, n)
    assert verdict2 == bs.INCONCLUSIVE


def test_negative_control_allows_real_access():
    # Real object returns far more than the garbage baseline -> still flagged.
    b = _probe(words=400)
    n = bs.Probe(ok=True, inner_status=200, word_count=5, total_count=0)  # garbage: empty
    verdict, _ = bs.classify(None, b, bs.Probe(ok=True, inner_status=401, word_count=0),
                             bs.DEFAULT_WORD_THRESHOLD, n)
    assert verdict == bs.VULNERABLE


def test_auth_failure_detection():
    assert bs.looks_like_auth_failure(bs.Probe(ok=True, outer_status=302))
    assert bs.looks_like_auth_failure(bs.Probe(ok=False, outer_status=200, raw_snippet="<html><body>Please sign in</body>"))
    # A normal per-object denial (valid JSON, inner 403) is NOT a session failure.
    assert not bs.looks_like_auth_failure(bs.Probe(ok=True, outer_status=200, inner_status=403))


# --------------------------------------------------------------------------------------
# Encoding + payloads
# --------------------------------------------------------------------------------------


def test_infa_path_encode():
    assert bs.infa_path_encode("$") == "~24~"
    assert bs.infa_path_encode(".") == "~2e~"
    assert bs.infa_path_encode(":") == "~3a~"
    assert bs.infa_path_encode("/") == "~2f~"
    assert bs.infa_path_encode("resource_1") == "resource_1"


def test_build_payload_doubles_resource_id():
    cfg = bs.Config(base_url="https://x")
    p = bs.build_payload("id", cfg, "resource_1$$OracleScanner$$SYS.SYS")
    assert p == "resource_1$$OracleScanner$$SYS.SYS://resource_1$$OracleScanner$$SYS.SYS"


# --------------------------------------------------------------------------------------
# Swagger parsing + envelope shape vs the real req.txt
# --------------------------------------------------------------------------------------


def _load_spec():
    with open(os.path.join(HERE, "informatica_swagger.json"), encoding="utf-8") as fh:
        return json.load(fh)


def test_swagger_parses_get_endpoints():
    spec = _load_spec()
    cfg = bs.Config(base_url="https://x", methods=["get"])
    endpoints = bs.load_endpoints(spec, cfg)
    assert len(endpoints) == 230, len(endpoints)
    objs = [e for e in endpoints if e.path == "/1/catalog/data/objects"]
    assert objs, "expected /1/catalog/data/objects to be present"
    names = {ip.name for ip in objs[0].insertion_points}
    assert "id" in names


def test_envelope_matches_real_request_shape():
    """The generated envelope for the known resource must match req.txt's path/method/encoding."""
    spec = _load_spec()
    cfg = bs.Config(base_url="https://x", methods=["get"])
    endpoints = bs.load_endpoints(spec, cfg)
    ep = next(e for e in endpoints if e.path == "/1/catalog/data/objects")
    id_ip = next(ip for ip in ep.insertion_points if ip.name == "id")

    base = "resource_1_or_2_etc$$OracleScanner$$SYS.SYS"
    payload = bs.build_payload(id_ip.kind, cfg, base)
    rest_path = bs.build_rest_path(ep, id_ip, payload)
    env = bs.build_envelope(rest_path, ep.method)

    assert env["method"] == "GET"
    assert rest_path.startswith("/1/catalog/data/objects?id=")
    # The doubled + percent-encoded id must appear exactly as in the captured request.
    expected_id = (
        "resource_1_or_2_etc%24%24OracleScanner%24%24SYS.SYS"
        "%3A%2F%2F"
        "resource_1_or_2_etc%24%24OracleScanner%24%24SYS.SYS"
    )
    assert expected_id in rest_path, rest_path


# --------------------------------------------------------------------------------------
# Bundled swagger, raw-request parsing, enumeration, id collection
# --------------------------------------------------------------------------------------


def test_bundled_swagger_loads():
    from swagger_data import load_bundled_swagger

    spec = load_bundled_swagger()
    assert spec.get("openapi", "").startswith("3.")
    assert len(spec["paths"]) == 262


def test_load_swagger_defaults_to_bundled():
    spec = bs.load_swagger(None)
    assert len(spec["paths"]) == 262


def test_parse_raw_request_from_reqtxt():
    with open(os.path.join(HERE, "req.txt"), encoding="utf-8") as fh:
        cfg = bs.parse_raw_request(fh.read())
    assert cfg["base_url"] == "https://il:9085"
    assert cfg["cookies"].startswith("username=agampt3")
    assert cfg["servlet_path"] == "/ldmcatalog/ldmProxyServlet"
    assert cfg["headers"].get("Infatoken") == "123*"
    # Cookie/Host must NOT leak into the generic headers dict.
    assert "Cookie" not in cfg["headers"]
    assert "Host" not in cfg["headers"]


# ---- browser paste formats (curl / PowerShell / fetch / XHR) ----------------

def test_parse_curl_bash():
    curl = ("curl 'https://host:9085/ldmcatalog/ldmProxyServlet' \\\n"
            "  -H 'accept: application/json' \\\n"
            "  -H 'content-type: application/json' \\\n"
            "  -b 'JSESSIONID=ABC123; Infatoken=tok-xyz' \\\n"
            "  --data-raw '{\"path\":\"/2/catalog/data/objects\",\"method\":\"GET\"}' --compressed")
    cfg = bs.parse_pasted_request(curl, "curl (bash)")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg["cookies"] == "JSESSIONID=ABC123; Infatoken=tok-xyz"
    assert cfg["servlet_path"] == "/ldmcatalog/ldmProxyServlet"
    assert cfg["headers"].get("content-type") == "application/json"
    assert "Cookie" not in cfg["headers"]          # folded into cookies
    assert "warnings" not in cfg                     # curl carries the cookie


def test_parse_curl_cmd_caret_continuations():
    curl = ('curl "https://host:9085/ldmcatalog/ldmProxyServlet" ^\n'
            '  -H "accept: application/json" ^\n'
            '  -H "cookie: JSESSIONID=CMD456; Infatoken=tok-cmd" ^\n'
            '  --data-raw "^{^\\"path^\\":^\\"/x^\\"^}"')
    cfg = bs.parse_pasted_request(curl, "curl (cmd)")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg["cookies"] == "JSESSIONID=CMD456; Infatoken=tok-cmd"
    assert cfg["servlet_path"] == "/ldmcatalog/ldmProxyServlet"
    assert cfg["headers"].get("accept") == "application/json"


def test_parse_powershell_chrome_headers_block():
    ps = ('Invoke-WebRequest -Uri "https://host:9085/access/2/catalog/data/objects" `\n'
          '-Method "GET" `\n'
          '-Headers @{\n'
          '  "accept"="application/json"\n'
          '  "cookie"="JSESSIONID=PS789; Infatoken=tok-ps"\n'
          '} `\n'
          '-ContentType "application/json"')
    cfg = bs.parse_pasted_request(ps, "curl (PowerShell)")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg["cookies"] == "JSESSIONID=PS789; Infatoken=tok-ps"
    assert cfg["headers"].get("Content-Type") == "application/json"
    assert "Cookie" not in cfg["headers"]


def test_parse_powershell_firefox_websession_cookies():
    ps = ('$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession\n'
          '$session.Cookies.Add((New-Object System.Net.Cookie("JSESSIONID", "FF000", "/", "host")))\n'
          '$session.Cookies.Add((New-Object System.Net.Cookie("Infatoken", "tok-ff", "/", "host")))\n'
          'Invoke-WebRequest -Uri "https://host:9085/access/2/catalog/data/objects" '
          '-WebSession $session -Headers @{ "accept"="application/json" }')
    cfg = bs.parse_pasted_request(ps, "curl (PowerShell)")
    assert cfg["cookies"] == "JSESSIONID=FF000; Infatoken=tok-ff"
    assert cfg["base_url"] == "https://host:9085"


def test_parse_fetch_omits_cookie_warns():
    fetch = ('fetch("https://host:9085/access/2/catalog/data/objects", {\n'
             '  "headers": {\n'
             '    "accept": "application/json",\n'
             '    "content-type": "application/json"\n'
             '  },\n'
             '  "body": null,\n'
             '  "method": "GET",\n'
             '  "credentials": "include"\n'
             '});')
    cfg = bs.parse_pasted_request(fetch, "fetch / JS")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg.get("cookies", "") == ""
    assert cfg["headers"].get("content-type") == "application/json"
    assert cfg.get("warnings"), "fetch without a cookie must warn"


def test_parse_fetch_with_cookie_no_warn():
    fetch = ('fetch("https://host:9085/ldmcatalog/ldmProxyServlet", {\n'
             '  "headers": { "accept": "application/json", "cookie": "JSESSIONID=FE111" },\n'
             '  "method": "POST"\n'
             '});')
    cfg = bs.parse_pasted_request(fetch, "fetch / JS")
    assert cfg["cookies"] == "JSESSIONID=FE111"
    assert cfg["servlet_path"] == "/ldmcatalog/ldmProxyServlet"
    assert "warnings" not in cfg
    assert "cookie" not in {k.lower() for k in cfg["headers"]}  # folded out


def test_parse_xhr():
    xhr = ('var xhr = new XMLHttpRequest();\n'
           'xhr.open("GET", "https://host:9085/access/2/catalog/data/objects", true);\n'
           'xhr.setRequestHeader("accept", "application/json");\n'
           'xhr.setRequestHeader("cookie", "JSESSIONID=XH222; Infatoken=tok-xh");\n'
           'xhr.withCredentials = true;\n'
           'xhr.send(null);')
    cfg = bs.parse_pasted_request(xhr, "XHR (JS)")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg["cookies"] == "JSESSIONID=XH222; Infatoken=tok-xh"
    assert cfg["headers"].get("accept") == "application/json"


def test_parse_pasted_auto_detects_each_format():
    samples = {
        "curl 'https://h:9085/ldmcatalog/ldmProxyServlet' -b 'a=1'": ("https://h:9085", "a=1"),
        'Invoke-WebRequest -Uri "https://h:9085/x" -Headers @{ "cookie"="b=2" }': ("https://h:9085", "b=2"),
        'fetch("https://h:9085/x", { "headers": { "cookie": "c=3" } })': ("https://h:9085", "c=3"),
        ('var xhr = new XMLHttpRequest();\nxhr.open("GET","https://h:9085/x");\n'
         'xhr.setRequestHeader("cookie","d=4");'): ("https://h:9085", "d=4"),
    }
    for text, (base, cook) in samples.items():
        cfg = bs.parse_pasted_request(text, "auto")
        assert cfg["base_url"] == base, text
        assert cfg["cookies"] == cook, text


def test_detect_paste_format():
    d = bs.detect_paste_format
    assert d("") == ""
    assert d("   ") == ""
    assert d("curl 'https://h/x' -H 'a: b'") == "curl (bash)"
    assert d('curl "https://h/x" ^\n  -H "a: b"') == "curl (cmd)"
    assert d('curl "https://h/x" -H "a: ^\"b^\""') == "curl (cmd)"
    assert d('Invoke-WebRequest -Uri "https://h/x" -Headers @{}') == "curl (PowerShell)"
    assert d('$s.Cookies.Add((New-Object System.Net.Cookie("a","b")))') == "curl (PowerShell)"
    assert d('fetch("https://h/x", { "method": "GET" })') == "fetch / JS"
    assert d('var xhr = new XMLHttpRequest();\nxhr.open("GET","https://h/x");') == "XHR (JS)"
    assert d("POST /ldmcatalog/ldmProxyServlet HTTP/1.1\nHost: h\n\n{}") == "Raw HTTP"
    assert d("just some random text") == ""


def test_parse_pasted_raw_still_routes_to_raw_parser():
    raw = ("POST /ldmcatalog/ldmProxyServlet HTTP/1.1\r\nHost: host:9085\r\n"
           "Cookie: JSESSIONID=RAW\r\nAccept: */*\r\n\r\n{}")
    cfg = bs.parse_pasted_request(raw, "Raw HTTP")
    assert cfg["base_url"] == "https://host:9085"
    assert cfg["cookies"] == "JSESSIONID=RAW"
    assert cfg["servlet_path"] == "/ldmcatalog/ldmProxyServlet"


def test_collect_ids_walks_search_payload():
    payload = {
        "items": [
            {"id": "resource_1://resource_1", "href": "/x"},
            {"id": "resource_2://resource_2"},
        ],
        "totalCount": 2,
    }
    out = []
    bs._collect_ids(payload, out)
    assert "resource_1://resource_1" in out
    assert "resource_2://resource_2" in out


def test_collect_explicit_ids_dedup_and_order():
    import argparse

    cfg = bs.Config(base_url="x", forbidden_id="res_a")
    args = argparse.Namespace(target_id=["res_b", "res_a"], ids_file=None)
    assert bs.collect_explicit_ids(cfg, args) == ["res_a", "res_b"]


# --------------------------------------------------------------------------------------
# Multi-user, enumeration, repro builders, report (with a fake HTTP session)
# --------------------------------------------------------------------------------------


class _Resp:
    def __init__(self, obj, status=200):
        self.text = json.dumps({"status": 200, "data": json.dumps(obj)})
        self.status_code = status

    def json(self):
        return json.loads(self.text)


class _RawResp:
    """Response whose body is a raw envelope string (for exact live-shape tests)."""
    def __init__(self, text, status=200):
        self.text = text
        self.status_code = status

    def json(self):
        return json.loads(self.text)


def test_search_values_shape_is_parsed():
    """Real search items use `values` [{id,value}] (not `facts`). Must extract type/resource/name."""
    item = {
        "id": "RESOURCE_NAME1://DB/SRC/COL/OFFICIAL_IND",
        "href": "/1/catalog/data/objects/RESOURCE_NAME1~3a~~2f~~2f~DB~2f~SRC~2f~COL~2f~OFFICIAL_IND",
        "values": [
            {"id": "core.resourceName", "value": "RESOURCE_NAME1"},
            {"id": "core.resourceType", "value": "Oracle"},
            {"id": "core.classType", "value": "com.infa.ldm.relational.Column"},
            {"id": "core.name", "value": "OFFICIAL_IND"},
        ],
    }

    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp({"items": [item], "totalCount": 449})

    res = bs.discover_resources(bs.Config(base_url="x"), S(), max_ids=5, page_size=1, user=bs.User("pt3"))
    r = res[0]
    assert r.id == "RESOURCE_NAME1://DB/SRC/COL/OFFICIAL_IND"   # full id kept
    assert r.kind == "com.infa.ldm.relational.Column"          # from values, not facts
    assert r.resource == "RESOURCE_NAME1"
    assert r.res_type == "Oracle"
    assert r.name == "OFFICIAL_IND"
    assert r.href.startswith("/1/catalog/data/objects/")


def test_oracle_matches_live_denial_shapes():
    # empty hit: inner 200, totalCount 0  -> NOT access
    empty = bs.parse_envelope(_RawResp('{"status":200,"data":"{\\"items\\":[],\\"totalCount\\":0}"}'))
    assert not empty.is_access()
    # real hit: inner 200, totalCount 1  -> access
    hit = bs.parse_envelope(_RawResp('{"status":200,"data":"{\\"items\\":[{\\"id\\":\\"x\\"}],\\"totalCount\\":1}"}'))
    assert hit.is_access()
    # enveloped 404 (empty data) -> NOT access
    e404 = bs.parse_envelope(_RawResp('{"status":404,"data":""}'))
    assert not e404.is_access()
    # enveloped 403 with HTML forbidden in data -> NOT access
    e403 = bs.parse_envelope(_RawResp('{"status":403,"data":"<html>HTTP Status 403 \\u2013 Forbidden</html>"}'))
    assert not e403.is_access()


def test_discover_paginates():
    import urllib.parse as up

    pages = {
        0: [{"id": "a://a", "facts": [{"name": "core.name", "value": "A"}]},
            {"id": "b://b", "facts": [{"name": "core.name", "value": "B"}]}],
        2: [{"id": "c://c", "facts": [{"name": "core.name", "value": "C"}]}],
    }

    class S:
        def post(self, url, data=None, headers=None, **k):
            q = dict(up.parse_qsl(up.urlparse(json.loads(data)["path"]).query))
            items = pages.get(int(q.get("offset", "0")), [])
            return _Resp({"items": items, "totalCount": 3})

    cfg = bs.Config(base_url="x")
    res = bs.discover_resources(cfg, S(), max_ids=10, page_size=2, user=bs.User("u"))
    # Full object ids are kept as-is (not collapsed on '://').
    assert [r.id for r in res] == ["a://a", "b://b", "c://c"], [r.id for r in res]


def test_asset_ids_not_collapsed():
    """Assets under one resource share the '://' prefix — they must stay distinct."""
    items = [
        {"id": "res1://res1", "facts": [{"name": "core.classType", "value": "core.Resource"}]},
        {"id": "res1://res1/schema/T1/COL_A", "facts": [{"name": "core.classType", "value": "col"}]},
        {"id": "res1://res1/schema/T1/COL_B", "facts": [{"name": "core.classType", "value": "col"}]},
    ]

    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp({"items": items, "totalCount": 3})

    res = bs.discover_resources(bs.Config(base_url="x"), S(), max_ids=10, page_size=10, user=bs.User("u"))
    assert len(res) == 3, [r.id for r in res]  # resource + 2 columns, all distinct


def test_full_id_not_re_doubled():
    cfg = bs.Config(base_url="x")
    # a full id (already has '://') must be used verbatim, not doubled again
    assert bs.build_payload("id", cfg, "res1://res1/T1/COL_A") == "res1://res1/T1/COL_A"
    # a bare base id (no '://') still gets doubled for convenience
    assert bs.build_payload("id", cfg, "res1") == "res1://res1"


def test_build_curl_and_raw():
    cfg = bs.Config(base_url="https://h:9085", headers={"Infatoken": "t"})
    u = bs.User("low", cookies="a=b")
    curl = bs.build_curl(cfg, "/1/x?id=1", "GET", user=u)
    assert curl.startswith("curl") and "ldmProxyServlet" in curl
    assert "Cookie: a=b" in curl and '\\"method\\": \\"GET\\"' not in curl and '"method": "GET"' in curl
    raw = bs.build_raw_request(cfg, "/1/x?id=1", "GET", user=u)
    assert raw.startswith("POST /ldmcatalog/ldmProxyServlet HTTP/1.1")
    assert "Host: h:9085" in raw and "Cookie: a=b" in raw


def test_multiuser_verdicts():
    big = {"items": [{"id": "x", "facts": [
        {"name": f"f{i}", "value": "v" * 60, "description": "d" * 90} for i in range(12)]}],
        "totalCount": 1}

    class S:
        def post(self, url, data=None, headers=None, **k):
            path = json.loads(data)["path"].lower()
            if "nonexistent" in path:  # negative control -> empty
                return _Resp({"items": [], "totalCount": 0})
            return _Resp(big)

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", min_length=1400)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
        # DECLARED ownership (authoritative): admin owns r1+r2, low owns only r1.
        admin = bs.User("admin"); admin.owned_ids = {"r1", "r2"}
        low = bs.User("low"); low.owned_ids = {"r1"}
        res = bs.run_multiuser_sweep(cfg, eps, [admin, low], ["r1", "r2"], "auto", False)
    finally:
        bs.requests.Session = orig

    def by(user, rid):
        return next(x for x in res if x.user == user and x.resource_id == rid)

    assert by("low", "r2").verdict == bs.VULNERABLE   # outside low's DECLARED scope
    assert by("low", "r1").verdict == bs.OWNED         # declared owned
    assert by("admin", "r2").verdict == bs.OWNED       # declared owned
    assert by("low", "r2").curl.startswith("curl")
    assert by("low", "r2").raw_request.startswith("POST")


def test_undeclared_ownership_never_masks_leak():
    """Without declared ownership, enumeration must NOT downgrade access to OWNED."""
    big = {"items": [{"id": "x", "facts": [
        {"name": f"f{i}", "value": "v" * 60, "description": "d" * 90} for i in range(12)]}], "totalCount": 1}

    class S:
        def post(self, url, data=None, headers=None, **k):
            path = json.loads(data)["path"].lower()
            if "nonexistent" in path:
                return _Resp({"items": [], "totalCount": 0})
            return _Resp(big)

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", min_length=1400)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
        # No declared owned. low's leaky enumeration even lists r2 (the exposed one).
        low = bs.User("low"); low.enum_ids = {"r1", "r2"}  # search leaked r2 too
        res = bs.run_multiuser_sweep(cfg, eps, [low], ["r1", "r2", "r3"], "auto", False)
    finally:
        bs.requests.Session = orig

    def by(rid):
        return next(x for x in res if x.resource_id == rid)

    # r2 is accessible AND was enumerated -> must be ACCESSIBLE? (review), NEVER silently OWNED.
    assert by("r2").verdict == bs.ACCESSIBLE, by("r2").verdict
    # r3 accessible but could NOT be enumerated -> definitive VULNERABLE.
    assert by("r3").verdict == bs.VULNERABLE, by("r3").verdict
    assert bs.OWNED not in {r.verdict for r in res}  # nothing masked as owned


def test_enum_leak_when_search_exposes_out_of_scope():
    """Detail denied, but the resource was enumerated outside the user's declared scope."""
    empty = {"items": [], "totalCount": 0}

    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp(empty)  # every detail call denies (empty)

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", min_length=1400, run_negative=False)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
        low = bs.User("low")
        low.owned_ids = {"r1"}          # declared: owns only r1
        low.enum_ids = {"r1", "r2"}     # but search exposed r2 as well
        res = bs.run_multiuser_sweep(cfg, eps, [low], ["r1", "r2"], "auto", False)
    finally:
        bs.requests.Session = orig

    by = {r.resource_id: r.verdict for r in res}
    assert by["r2"] == bs.ENUM_LEAK, by          # search leaked r2's existence though detail denied
    assert by["r1"] == bs.DENIED                 # owned + denied detail = clean


def test_enum_leak_undeclared_uses_enum_vs_read_gap():
    """Without declared owns: search-exposed but detail-denied objects are ENUM-LEAK; ones the
    user couldn't even enumerate are correctly DENIED."""
    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp({"items": [], "totalCount": 0})  # detail always denied/empty

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", min_length=1400, run_negative=False)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
        low = bs.User("low")
        low.enum_ids = {"r1", "r2"}   # search exposed r1,r2 to low; no owns declared
        res = bs.run_multiuser_sweep(cfg, eps, [low], ["r1", "r2", "r3"], "auto", False)
    finally:
        bs.requests.Session = orig

    by = {r.resource_id: r.verdict for r in res}
    assert by["r1"] == bs.ENUM_LEAK and by["r2"] == bs.ENUM_LEAK  # enumerable but not readable
    assert by["r3"] == bs.DENIED                                   # not even enumerable -> clean


def test_data_object_endpoint_scope():
    spec = bs.load_swagger(None)
    cfg = bs.Config(base_url="x")
    eps = [e for e in bs.load_endpoints(spec, cfg) if e.insertion_points]
    data_obj = [e for e in eps if bs.is_data_object_endpoint(e)]
    # The catalog data-object family is a small, meaningful subset of all id-bearing endpoints.
    assert 0 < len(data_obj) < len(eps)
    assert any(e.path == "/1/catalog/data/objects" for e in data_obj)
    # A model/config {id} endpoint (different id space) must NOT be in scope.
    assert not any("/models/attributes/{id}" in e.path for e in data_obj)


def test_enum_leak_not_fired_on_non_detail_endpoint():
    """A 404/deny on a model/config {id} endpoint (different id space) is DENIED, not ENUM-LEAK."""
    class S:
        def post(self, url, data=None, headers=None, **k):
            return _RawResp('{"status":404,"data":""}')

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", run_negative=False)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/2/catalog/models/lineageFilter/{id}"]
        assert eps, "lineageFilter endpoint should exist"
        low = bs.User("low"); low.enum_ids = {"stg://x"}   # enumerable, but this endpoint is unrelated
        res = bs.run_multiuser_sweep(cfg, eps, [low], ["stg://x"], "auto", False)
    finally:
        bs.requests.Session = orig
    assert res and all(r.verdict == bs.DENIED for r in res), [r.verdict for r in res]


def test_enum_leak_only_on_clean_denial_not_404():
    """On the object-detail endpoint: 404/400/5xx = DENIED; only 403 or empty-200 = ENUM-LEAK."""
    def run(raw):
        class S:
            def post(self, url, data=None, headers=None, **k):
                return _RawResp(raw)
        orig = bs.requests.Session
        bs.requests.Session = lambda: S()
        try:
            spec = bs.load_swagger(None)
            cfg = bs.Config(base_url="x", run_negative=False)
            eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
            low = bs.User("low"); low.enum_ids = {"r1"}
            return bs.run_multiuser_sweep(cfg, eps, [low], ["r1"], "auto", False)[0].verdict
        finally:
            bs.requests.Session = orig

    assert run('{"status":404,"data":""}') == bs.DENIED               # not found -> nothing
    assert run('{"status":400,"data":""}') == bs.DENIED               # bad request -> nothing
    assert run('{"status":200,"data":"{\\"items\\":[],\\"totalCount\\":0}"}') == bs.ENUM_LEAK  # empty
    assert run('{"status":403,"data":"<html>Forbidden</html>"}') == bs.ENUM_LEAK               # forbidden


def test_enum_leak_toggle_off_makes_denied():
    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp({"items": [], "totalCount": 0})   # empty/denied but enumerable

    orig = bs.requests.Session
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        eps = [e for e in bs.load_endpoints(spec, bs.Config(base_url="x")) if e.path == "/1/catalog/data/objects"]
        low = bs.User("low"); low.enum_ids = {"r1"}
        on = bs.run_multiuser_sweep(bs.Config(base_url="x", run_negative=False, enum_leak=True),
                                    eps, [low], ["r1"], "auto", False)
        off = bs.run_multiuser_sweep(bs.Config(base_url="x", run_negative=False, enum_leak=False),
                                     eps, [low], ["r1"], "auto", False)
    finally:
        bs.requests.Session = orig
    assert on[0].verdict == bs.ENUM_LEAK
    assert off[0].verdict == bs.DENIED     # toggle off -> plain DENIED


def test_is_object_detail_endpoint():
    mk = lambda p: bs.Endpoint(p, "get", [])
    assert bs.is_object_detail_endpoint(mk("/1/catalog/data/objects"))
    assert bs.is_object_detail_endpoint(mk("/2/catalog/data/objects/{id}"))
    assert not bs.is_object_detail_endpoint(mk("/2/catalog/data/objects/{id}/reviews"))
    assert not bs.is_object_detail_endpoint(mk("/2/catalog/models/lineageFilter/{id}"))


def test_reauth_blocks_then_resumes_with_new_cookie():
    """Session expiry triggers on_reauth (blocking); after it refreshes the cookie, the scan resumes."""
    class S:
        def post(self, url, data=None, headers=None, **k):
            if headers.get("Cookie") == "sid=new":
                return _Resp({"items": [{"id": "x"}], "totalCount": 1})   # success after refresh
            return _RawResp("<html>HTTP Status 401 – Unauthorized</html>", 401)  # expired

    calls = {"n": 0}

    def reauth(user):
        calls["n"] += 1
        user.cookies = "sid=new"   # what the GUI dialog does after you paste a fresh request

    orig_thr, orig_sess = bs.SESSION_FAIL_THRESHOLD, bs.requests.Session
    bs.SESSION_FAIL_THRESHOLD = 1
    bs.requests.Session = lambda: S()
    try:
        spec = bs.load_swagger(None)
        cfg = bs.Config(base_url="x", run_negative=False)
        eps = [e for e in bs.load_endpoints(spec, cfg) if e.path == "/1/catalog/data/objects"]
        u = bs.User("low", cookies="sid=old"); u.owned_ids = {"r1"}
        res = bs.run_multiuser_sweep(cfg, eps, [u], ["r1"], "auto", False, on_reauth=reauth)
    finally:
        bs.SESSION_FAIL_THRESHOLD, bs.requests.Session = orig_thr, orig_sess

    assert calls["n"] == 1                 # re-auth was requested once
    assert res[0].verdict == bs.OWNED      # after refresh, r1 read succeeds


def test_needs_multiple_ids():
    e2 = bs.Endpoint("/2/catalog/data/objects/{id}/reviews/{reviewId}", "get", [])
    e1 = bs.Endpoint("/1/catalog/data/objects/{id}", "get", [])
    e0 = bs.Endpoint("/1/catalog/data/objects", "get", [])
    assert e2.needs_multiple_ids and e2.path_param_count == 2
    assert not e1.needs_multiple_ids
    assert not e0.needs_multiple_ids


def test_scannable_with_param_values():
    e2 = bs.Endpoint("/2/catalog/data/objects/{id}/reviews/{reviewId}", "get", [])
    assert not e2.scannable({})                      # two unfilled path ids -> not scannable
    assert e2.scannable({"reviewId": "42"})          # supply reviewId -> id slot remains -> scannable
    assert e2.uncovered_path_params({"reviewId": "42"}) == ["id"]


def test_param_values_fill_query_not_resource_id():
    ep = bs.Endpoint("/x", "get", [{"name": "DomainName", "in": "query", "required": True, "schema": {"type": "string"}},
                                   {"name": "id", "in": "query", "required": False, "schema": {"type": "string"}}])
    ip = bs.InsertionPoint("id", "query", "id")
    path = bs.build_rest_path(ep, ip, "resource_1://resource_1", {"DomainName": "PROD"})
    assert "DomainName=PROD" in path            # tester value used, NOT the resource id
    assert "resource_1" not in path.split("DomainName=PROD")[0].split("id=")[0]  # id not leaked into DomainName


def test_xlsx_export(tmp_path=None):
    import os, tempfile
    r = bs.Result("/e", "GET", "query:id", "r2", "VULNERABLE", "note", 200, 20, "/e?id=1",
                  user="low", owned=False, resp_len=1600, data_summary="name=r2",
                  curl="curl x", raw_request="POST x", response='{"items":[{"secret":"S"}]}')
    denied = bs.Result("/e", "GET", "query:id", "r9", "DENIED", "n", 403, 0, "/e", user="low")
    out = os.path.join(tempfile.gettempdir(), "bola_test_report.xlsx")
    bs.write_report([r, denied], out)
    import openpyxl
    wb = openpyxl.load_workbook(out)
    assert "Findings" in wb.sheetnames and "All results" in wb.sheetnames and "access-matrix" in wb.sheetnames
    fs = wb["Findings"]
    headers = [c.value for c in fs[1]]
    assert "Response" in headers and "Curl" in headers and "Raw Request" in headers
    # Findings sheet holds only the finding (VULNERABLE), not the DENIED row.
    assert fs.max_row == 2
    row2 = [c.value for c in fs[2]]
    assert "VULNERABLE" in row2 and 'S' in "".join(str(x) for x in row2)   # exposed data present
    os.remove(out)


def test_readable_path_decodes_query_and_tilde():
    q = "/1/catalog/data/objects?id=res_1%24%24Scanner%3A%2F%2Fres_1%24%24Scanner"
    assert bs.readable_path(q) == "/1/catalog/data/objects?id=res_1$$Scanner://res_1$$Scanner"
    p = "/1/catalog/data/objects/res_1~24~~24~Scanner~2e~X"
    assert bs.readable_path(p) == "/1/catalog/data/objects/res_1$$Scanner.X"


def test_access_matrix():
    import bola_report as br
    results = [
        bs.Result("/o", "GET", "query:id", "resA", bs.OWNED, "n", 200, 1600, "/o", user="pt3", resp_len=1600),
        bs.Result("/o", "GET", "query:id", "resA", bs.OWNED, "n", 200, 1600, "/o", user="pt2", resp_len=1600),
        bs.Result("/o", "GET", "query:id", "resB", bs.VULNERABLE, "n", 200, 1600, "/o", user="pt3", resp_len=1600),
        bs.Result("/o", "GET", "query:id", "resB", bs.OWNED, "n", 200, 1600, "/o", user="pt2", resp_len=1600),
    ]
    users, rows = br.build_matrix(results)
    assert users == ["pt2", "pt3"]
    assert rows["resB"]["cells"]["pt3"] == bs.VULNERABLE   # pt3 reached resB (not its own)
    assert rows["resB"]["cells"]["pt2"] == bs.OWNED
    html = br.generate_html(results, {})
    assert "Access matrix" in html


def test_html_report_contains_finding_and_curl():
    import bola_report as br

    r = bs.Result("/e", "GET", "query:id", "r2", "VULNERABLE", "note", 200, 20, "/e?id=1",
                  user="low", owned=False, resp_len=1600, data_summary="name=r2",
                  curl="curl https://h/x", raw_request="POST /x HTTP/1.1")
    html = br.generate_html([r], {"Target": "https://h"})
    # curl text is HTML-escaped inside the report, so match escape-safe substrings.
    assert "VULNERABLE" in html and "curl https://h/x" in html and "Findings (1)" in html


# --------------------------------------------------------------------------------------
# Crawl → map → replay
# --------------------------------------------------------------------------------------


def test_crawl_map_follows_real_hrefs_only_data_urls():
    import bola_crawl
    # object detail like res.txt: has its own href, additionalFacts hrefs, and (noise) attribute hrefs
    detail = {
        "items": [{
            "id": "res1://res1",
            "href": "/1/catalog/data/objects/res1~3a~~2f~~2f~res1",
            "facts": [{"name": "core.name", "value": "R1"}],
            "additionalFacts": [
                {"id": "col-min-max-data-provider",
                 "href": "/1/catalog/data/objects/res1~3a~~2f~~2f~res1/additionalFacts/col-min-max-data-provider"}],
            "values": [{"id": "core.name", "href": "/1/catalog/models/attributes/core~2e~name", "value": "R1"}],
        }],
        "totalCount": 1,
    }

    class S:
        def post(self, url, data=None, headers=None, **k):
            return _Resp(detail)

    crawled = bola_crawl.crawl_map(bs.Config(base_url="x"), S(), ["res1://res1"], bs.User("admin"), max_objects=5)
    urls = [c.url for c in crawled]
    assert any("/data/objects?id=" in u for u in urls)                 # the detail request
    assert any("/additionalFacts/col-min-max-data-provider" in u for u in urls)  # followed real href
    assert not any("/models/attributes/" in u for u in urls)           # attribute noise filtered out (data_only)

    # data_only=False (the "All API endpoints" crawl) follows EVERY href, incl. /models/attributes
    all_urls = [c.url for c in bola_crawl.crawl_map(
        bs.Config(base_url="x"), S(), ["res1://res1"], bs.User("admin"), max_objects=5, data_only=False)]
    assert any("/models/attributes/" in u for u in all_urls)


def test_replay_urls_classifies_per_user():
    import bola_crawl

    class S:
        def post(self, url, data=None, headers=None, **k):
            # every crawled URL returns real content (totalCount 1)
            return _Resp({"items": [{"id": "x"}], "totalCount": 1})

    urls = [bola_crawl.CrawledUrl("/1/catalog/data/objects?id=res2", "object-detail", "res2")]
    admin = bs.User("admin"); admin.owned_ids = {"res2"}
    low = bs.User("low"); low.owned_ids = {"res1"}
    res = bola_crawl.replay_urls(bs.Config(base_url="x"), S(), urls, [admin, low])
    by = {(r.user): r.verdict for r in res}
    assert by["admin"] == bs.OWNED           # res2 is admin's
    assert by["low"] == bs.VULNERABLE        # low read res2 outside its declared scope

    # Multi-user: the mapper is skipped on replay (no duplicate self-test).
    res2 = bola_crawl.replay_urls(bs.Config(base_url="x"), S(), urls, [admin, low], mapper=admin)
    assert {r.user for r in res2} == {"low"}
    # Single user: the (mapper) user is kept -> inventory of what it can reach.
    res3 = bola_crawl.replay_urls(bs.Config(base_url="x"), S(), urls, [admin], mapper=admin)
    assert {r.user for r in res3} == {"admin"}


# --------------------------------------------------------------------------------------
# Dependency-free runner
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import traceback

    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            passed += 1
            print(f"PASS {t.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {t.__name__}")
            traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
