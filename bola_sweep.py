#!/usr/bin/env python3
"""
Informatica EDC / LDM BOLA (IDOR) sweep tool.

AUTHORIZED SECURITY TESTING ONLY.

Given a "forbidden" resource id (an object you should NOT be able to read), this tool
sweeps the catalog REST API surface described by an OpenAPI/Swagger file and reports
which endpoints actually leak access to that object.

All REST calls tunnel through the LDM proxy servlet, exactly like the real UI:

    POST /ldmcatalog/ldmProxyServlet
    Content-Type: application/json
    { "path": "/1/catalog/data/objects?id=<RESOURCE>&...", "method": "GET" }

The response is an envelope:

    { "status": 200, "data": "<escaped-json-string>", "headers": {...} }

Genuine access -> inner status 200 and `data` holds real content (items/facts, many words).
Denial        -> non-200 inner status, empty data, "totalCount":0, or an error marker.

Oracle: word-count on inner `data` (>= --word-threshold) combined, when a --control-id is
supplied, with a differential across three requests per insertion point:
    A) control/owned id   -> expected ACCESS   (baseline for "what access looks like")
    B) forbidden id       -> the actual test
    C) forbidden id, auth stripped -> expected DENY (baseline for "what denial looks like")

See README.md for full usage and safety notes.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Optional

# In a windowed/frozen build (PyInstaller --windowed) there is no console, so sys.stdout and
# sys.stderr are None. Give them a null sink so import-time isatty() and later print() calls
# never crash the GUI. (When run as a real CLI, stdout is a normal stream and is left alone.)
class _NullStream:
    def write(self, *_a, **_k):
        return 0

    def flush(self):
        pass

    def isatty(self):
        return False


if sys.stdout is None:
    sys.stdout = _NullStream()
if sys.stderr is None:
    sys.stderr = _NullStream()

try:
    import requests
except ImportError:
    sys.exit("This tool needs the 'requests' package:  pip install requests")

try:
    # The official OpenAPI spec is embedded so the tool is self-contained.
    from swagger_data import load_bundled_swagger
except Exception:  # pragma: no cover - only if swagger_data.py is missing
    load_bundled_swagger = None

# Silence the self-signed-cert warnings we deliberately opt into with --insecure/--burp.
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - urllib3 always ships with requests
    pass


# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

DEFAULT_SERVLET_PATH = "/ldmcatalog/ldmProxyServlet"
DEFAULT_WORD_THRESHOLD = 30
DEFAULT_BURP_PROXY = "http://127.0.0.1:8080"
WRITE_METHODS = {"put", "post", "delete", "patch"}

# Parameter names that are, by default, treated as candidate injection points.
DEFAULT_PARAM_FILTER = ["id", "resourcename", "name", "objectid", "userid", "q"]

# Substrings that signal an access denial inside the inner `data` payload.
DENY_MARKERS = [
    "access denied",
    "forbidden",
    "unauthorized",
    "not authorized",
]

# Header keys that carry authentication; stripped for the no-auth (C) differential leg.
AUTH_HEADER_KEYS = {"cookie", "infatoken", "authorization"}


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------


@dataclass
class InsertionPoint:
    """A single place in an endpoint where the resource-id payload can be injected."""

    name: str  # parameter / path-template name
    location: str  # "query" or "path"
    kind: str  # id | resource | userid | q | name | objectid | generic

    def label(self) -> str:
        return f"{self.location}:{self.name}"


@dataclass
class Endpoint:
    path: str
    method: str  # lower-case http verb
    params: list[dict]  # resolved swagger parameters
    insertion_points: list[InsertionPoint] = field(default_factory=list)

    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def path_param_count(self) -> int:
        """Number of ``{...}`` templates in the path (distinct ids the URL requires)."""
        return len(set(re.findall(r"\{([^}]+)\}", self.path)))

    @property
    def needs_multiple_ids(self) -> bool:
        """True if the path has 2+ id slots we cannot populate meaningfully (e.g. /objects/{id}/comments/{commentId})."""
        return self.path_param_count > 1

    def path_templates(self) -> list[str]:
        return sorted(set(re.findall(r"\{([^}]+)\}", self.path)))

    def missing_path_params(self, target_name: str, path_values: dict) -> list[str]:
        """Path templates (other than the injection target) with no tester-supplied value."""
        return [n for n in self.path_templates() if n != target_name and n not in (path_values or {})]

    def coverable(self, target_name: str, path_values: dict) -> bool:
        """Can we build a real request: only the target slot + slots we have values for?"""
        return not self.missing_path_params(target_name, path_values)

    def uncovered_path_params(self, path_values: dict = None) -> list[str]:
        """Path templates with no tester-supplied value."""
        return [t for t in self.path_templates() if t not in (path_values or {})]

    def scannable(self, path_values: dict = None) -> bool:
        """Scannable if at most one path template is unfilled (that one becomes the id slot)."""
        return len(self.uncovered_path_params(path_values)) <= 1


@dataclass
class Config:
    base_url: str
    servlet_path: str = DEFAULT_SERVLET_PATH
    cookies: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    forbidden_id: str = ""
    control_id: str = ""
    spoof_user: str = ""
    word_threshold: int = DEFAULT_WORD_THRESHOLD
    min_length: int = 1400  # response body >= this = real content (empty ~1200, content >=1500)
    param_filter: list[str] = field(default_factory=lambda: list(DEFAULT_PARAM_FILTER))
    methods: list[str] = field(default_factory=lambda: ["get"])
    proxies: Optional[dict] = None
    verify: bool = True
    timeout: float = 30.0
    delay: float = 0.0
    run_noauth: bool = True  # always probe the no-auth (C) leg to catch public leaks
    run_negative: bool = True  # probe a garbage id (N) to calibrate "not found / boilerplate"
    negative_id: str = "bola_nonexistent_probe_0xDEADBEEF$$NoSuchScanner$$NO.NE"
    enum_leak: bool = True  # flag ENUM-LEAK (search exposed a denied object); off -> those are DENIED
    path_values: dict = field(default_factory=dict)  # tester-supplied values for extra {path} params
    api_prefix: str = "/access"  # real API base (from the swagger 'servers' url) for DIRECT (non-proxy) calls


@dataclass
class User:
    """One authenticated identity (session) to test as.

    `owned_ids` is populated by per-user enumeration: the resources this user can see
    for itself. A user reaching a resource NOT in its own set is a definitive IDOR.
    """

    label: str
    cookies: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    base_url: str = ""  # optional per-user override (else Config.base_url)
    owned_ids: set = field(default_factory=set)   # TESTER-DECLARED legitimate scope (authoritative)
    enum_ids: set = field(default_factory=set)     # what this user could ENUMERATE (NOT proof of ownership)

    @property
    def owned_declared(self) -> bool:
        return bool(self.owned_ids)


@dataclass
class ResourceInfo:
    """A discovered catalog object (scanner / resource / asset)."""

    id: str  # base id (not the doubled form)
    name: str = ""
    kind: str = ""  # class type (asset type), e.g. core.Resource / core.Table / core.Column
    resource: str = ""  # parent resource name (the "scanner"/source it belongs to)
    res_type: str = ""  # resource type, e.g. Oracle / Reference resource
    href: str = ""  # the catalog's own detail URL for this object (for future replay/crawl)
    seen_by: set = field(default_factory=set)  # user labels that could enumerate it

    @property
    def is_resource(self) -> bool:
        return self.kind.endswith("Resource") or self.resource == self.name or not self.resource


# --------------------------------------------------------------------------------------
# Payload encoding
# --------------------------------------------------------------------------------------

_SAFE_PATH_SEGMENT = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)


def infa_path_encode(value: str) -> str:
    """Encode a value for an Informatica in-path id segment.

    EDC encodes special characters as ``~<hexbyte>~``. Confirmed from the `href`
    values in real responses:  ``$`` -> ``~24~``, ``.`` -> ``~2e~``,
    ``:`` -> ``~3a~``, ``/`` -> ``~2f~``.
    """
    out = []
    for ch in value:
        if ch in _SAFE_PATH_SEGMENT:
            out.append(ch)
        else:
            out.append("~%02x~" % ord(ch))
    return "".join(out)


def build_payload(kind: str, cfg: Config, resource_id: str) -> str:
    """Return the raw (un-encoded) payload string for a given insertion-point kind.

    `resource_id` is the base id to inject (forbidden id or control id). Resource-type
    slots get the doubled ``<id>://<id>`` form used by EDC object ids.
    """
    if kind == "userid":
        # userId is an identity knob, not the resource: inject the tester-supplied value.
        # (The caller only enables userId slots when a spoof value is configured.)
        return cfg.spoof_user
    if kind in ("id", "resource"):
        # Enumerated object ids are already full ids (they contain '://' — for a resource it's
        # the doubled form, for an asset it's resource://asset/path). Use them AS-IS. Only a
        # manually-typed BASE id (no '://') gets doubled, as a convenience.
        return resource_id if "://" in resource_id else f"{resource_id}://{resource_id}"
    # q / name / objectid / generic -> use as-is
    return resource_id


def encode_for_location(value: str, location: str) -> str:
    if location == "path":
        return infa_path_encode(value)
    return urllib.parse.quote(value, safe="")


# --------------------------------------------------------------------------------------
# Swagger parsing
# --------------------------------------------------------------------------------------


def _resolve_ref(spec: dict, node: dict) -> dict:
    """Resolve a single-level local ``$ref`` (``#/components/...``)."""
    ref = node.get("$ref")
    if not ref or not ref.startswith("#/"):
        return node
    cur: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict) or part not in cur:
            return node
        cur = cur[part]
    return cur if isinstance(cur, dict) else node


def _classify_kind(name: str) -> str:
    n = name.lower()
    if n == "userid":
        return "userid"
    if n == "id" or n.endswith("id") and n not in ("objectid",):
        # generic *Id params behave like ids
        return "id" if n == "id" else "resource"
    if n == "objectid":
        return "objectid"
    if "resource" in n:
        return "resource"
    if n == "q":
        return "q"
    if n == "name":
        return "name"
    return "generic"


_PATH_TEMPLATE_RE = re.compile(r"\{([^}]+)\}")


def load_endpoints(spec: dict, cfg: Config) -> list[Endpoint]:
    """Parse an OpenAPI 3 / Swagger 2 document into Endpoint objects with insertion points."""
    paths = spec.get("paths", {})
    base_path = spec.get("basePath", "") or ""  # swagger 2 only
    wanted_methods = {m.lower() for m in cfg.methods}
    filt = {p.lower() for p in cfg.param_filter}
    endpoints: list[Endpoint] = []

    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        full_path = base_path + raw_path
        # Parameters shared across all operations on this path.
        shared = [
            _resolve_ref(spec, p) for p in path_item.get("parameters", []) if isinstance(p, dict)
        ]
        template_names = set(_PATH_TEMPLATE_RE.findall(full_path))

        for method, op in path_item.items():
            if method.lower() not in wanted_methods or not isinstance(op, dict):
                continue
            op_params = [
                _resolve_ref(spec, p)
                for p in op.get("parameters", [])
                if isinstance(p, dict)
            ]
            params = _merge_params(shared, op_params)
            ips = _insertion_points(params, template_names, filt)
            endpoints.append(
                Endpoint(path=full_path, method=method.lower(), params=params, insertion_points=ips)
            )
    return endpoints


def _merge_params(shared: list[dict], op: list[dict]) -> list[dict]:
    """Merge path- and operation-level params; operation-level wins on (name, in)."""
    merged: dict[tuple, dict] = {}
    for p in shared + op:
        key = (p.get("name"), p.get("in"))
        merged[key] = p
    return list(merged.values())


def _insertion_points(
    params: list[dict], template_names: set[str], filt: set[str]
) -> list[InsertionPoint]:
    points: list[InsertionPoint] = []
    seen: set[tuple] = set()

    # Query (and other non-path) parameters that match the name filter.
    for p in params:
        name = p.get("name")
        loc = p.get("in")
        if not name or loc == "path":
            continue
        if name.lower() in filt:
            key = ("query", name)
            if key not in seen:
                seen.add(key)
                points.append(InsertionPoint(name, "query", _classify_kind(name)))

    # Path templates are always candidate injection points.
    for name in sorted(template_names):
        key = ("path", name)
        if key not in seen:
            seen.add(key)
            points.append(InsertionPoint(name, "path", _classify_kind(name)))

    return points


# --------------------------------------------------------------------------------------
# Request building
# --------------------------------------------------------------------------------------


def _benign_query_value(schema: dict) -> str:
    if "default" in schema:
        return str(schema["default"])
    t = schema.get("type")
    if t in ("integer", "number"):
        return "1"
    if t == "boolean":
        return "false"
    return "*"


def build_rest_path(endpoint: Endpoint, ip: InsertionPoint, payload: str, path_values: dict = None) -> str:
    """Construct the inner REST path (``/x/y?...``) with `payload` injected at `ip`.

    Non-target path templates are filled from `path_values` (tester-supplied) when available;
    otherwise best-effort with the payload (only reached for endpoints deemed coverable).
    """
    path = endpoint.path
    path_values = path_values or {}

    for name in _PATH_TEMPLATE_RE.findall(path):
        if ip.location == "path" and ip.name == name:
            value = encode_for_location(payload, "path")
        elif name in path_values:
            value = encode_for_location(path_values[name], "path")
        else:
            value = encode_for_location(payload, "path")  # fallback (coverable check should prevent)
        path = path.replace("{" + name + "}", value)

    # Assemble the query string.
    parts: list[str] = []
    added: set[str] = set()

    if ip.location == "query":
        parts.append(f"{ip.name}={encode_for_location(payload, 'query')}")
        added.add(ip.name)

    for p in endpoint.params:
        name = p.get("name")
        if p.get("in") != "query" or name in added:
            continue
        # A tester-supplied value wins (e.g. DomainName=PROD, type=Oracle). Otherwise fill
        # only REQUIRED params with a benign type-based default (never the resource id).
        if name in path_values:
            parts.append(f"{name}={urllib.parse.quote(str(path_values[name]), safe='')}")
            added.add(name)
        elif p.get("required"):
            schema = p.get("schema", {}) if isinstance(p.get("schema"), dict) else {}
            val = urllib.parse.quote(_benign_query_value(schema), safe="")
            parts.append(f"{name}={val}")
            added.add(name)

    if parts:
        return path + "?" + "&".join(parts)
    return path


def build_envelope(rest_path: str, method: str) -> dict:
    return {"path": rest_path, "method": method.upper()}


# --------------------------------------------------------------------------------------
# HTTP + oracle
# --------------------------------------------------------------------------------------


@dataclass
class Probe:
    """Result of parsing one proxy-servlet response."""

    ok: bool  # transport succeeded and envelope parsed
    outer_status: Optional[int] = None
    inner_status: Optional[int] = None
    word_count: int = 0
    total_count: Optional[int] = None
    deny_marker: bool = False
    error: str = ""
    raw_snippet: str = ""
    data_str: str = ""  # inner `data` payload (full)
    raw_full: str = ""  # the ENTIRE response body, untruncated (for the Response tab / evidence)
    resp_len: int = 0  # full response body length (bytes/chars)
    content_type: str = ""  # inner response Content-Type (if any)
    filename: str = ""  # filename from inner Content-Disposition (if any)
    is_file: bool = False  # response looks like a downloadable file/attachment
    file_ext: str = ""  # detected file extension

    def is_access(self, threshold: int = 0, min_length: int = 0) -> bool:
        if not self.ok:
            return False
        if self.inner_status is not None and self.inner_status >= 400:
            return False
        # `totalCount` is authoritative on this API: >=1 means real items were returned,
        # 0 means empty/denied. Confirmed from live responses (empty=totalCount:0, hit=1).
        if self.total_count is not None:
            return self.total_count > 0
        # No totalCount -> fall back to deny markers, then length, then word count.
        if self.deny_marker:
            return False
        if min_length and self.resp_len:
            return self.resp_len >= min_length
        return self.word_count >= threshold


_TOTAL_COUNT_RE = re.compile(r'"totalCount"\s*:\s*(\d+)')

# Leading bytes (as decoded chars) that identify a file the response is carrying.
FILE_MAGIC = [
    ("PK\x03\x04", "zip"), ("PK", "zip"), ("%PDF", "pdf"), ("\x89PNG", "png"),
    ("GIF8", "gif"), ("\xff\xd8\xff", "jpg"), ("\x1f\x8b", "gz"), ("Rar!", "rar"),
    ("7z\xbc\xaf", "7z"), ("BM", "bmp"), ("{\\rtf", "rtf"), ("<?xml", "xml"),
]
_CT_EXT = {"zip": "zip", "pdf": "pdf", "csv": "csv", "xml": "xml", "json": "json",
           "excel": "xlsx", "spreadsheet": "xlsx", "word": "docx", "png": "png",
           "jpeg": "jpg", "gif": "gif", "octet-stream": "bin", "gzip": "gz"}
_CDISP_RE = re.compile(r'filename\*?="?([^";]+)"?', re.I)


def detect_file(content_type: str, filename: str, data_str: str) -> tuple[bool, str]:
    """Decide whether a response is carrying a downloadable file, and its extension."""
    ct = (content_type or "").lower()
    if ct and not any(t in ct for t in ("application/json", "text/html")):
        for key, ext in _CT_EXT.items():
            if key in ct:
                if filename and "." in filename:
                    return True, filename.rsplit(".", 1)[-1].lower()
                return True, ext
    if filename and "." in filename:
        return True, filename.rsplit(".", 1)[-1].lower()
    for sig, ext in FILE_MAGIC:
        if data_str.startswith(sig):
            return True, ext
    return False, ""


def parse_envelope(resp: "requests.Response") -> Probe:
    text = resp.text or ""
    snippet = text[:600]
    try:
        env = resp.json()
    except ValueError:
        return Probe(
            ok=False,
            outer_status=resp.status_code,
            error="response was not JSON",
            raw_snippet=snippet,
            raw_full=text,
            resp_len=len(text),
        )

    inner_status = env.get("status") if isinstance(env, dict) else None
    data = env.get("data") if isinstance(env, dict) else None

    # `data` is usually an escaped JSON string; may also be a dict or None.
    if isinstance(data, (dict, list)):
        data_str = json.dumps(data)
    elif data is None:
        data_str = ""
    else:
        data_str = str(data)

    word_count = len(data_str.split())
    low = data_str.lower()
    deny = any(m in low for m in DENY_MARKERS)
    tc_match = _TOTAL_COUNT_RE.search(data_str)
    total_count = int(tc_match.group(1)) if tc_match else None

    # Inner response headers → Content-Type / filename, then detect file/attachment.
    inner_headers = env.get("headers") if isinstance(env, dict) else {}
    ctype, fname = "", ""
    if isinstance(inner_headers, dict):
        for k, v in inner_headers.items():
            lk = str(k).lower()
            if lk == "content-type":
                ctype = str(v)
            elif lk == "content-disposition":
                m = _CDISP_RE.search(str(v))
                if m:
                    fname = m.group(1)
    is_file, file_ext = detect_file(ctype, fname, data_str)

    return Probe(
        ok=True,
        outer_status=resp.status_code,
        inner_status=inner_status if isinstance(inner_status, int) else None,
        word_count=word_count,
        total_count=total_count,
        deny_marker=deny,
        raw_snippet=snippet,
        data_str=data_str,
        raw_full=text,
        resp_len=len(text),
        content_type=ctype,
        filename=fname,
        is_file=is_file,
        file_ext=file_ext,
    )


def summarize_facts(data_str: str, limit: int = 6) -> str:
    """Turn the returned object's facts into a short human-readable summary for the report."""
    if not data_str:
        return ""
    try:
        data = json.loads(data_str)
    except ValueError:
        return data_str[:200]
    items = data.get("items") if isinstance(data, dict) else None
    if not items:
        # Not an object listing; show a few top-level keys.
        if isinstance(data, dict):
            return ", ".join(f"{k}={data[k]}" for k in list(data)[:limit] if not isinstance(data[k], (dict, list)))
        return data_str[:200]
    facts = _facts_map(items[0]) if isinstance(items[0], dict) else {}
    wanted = ["core.name", "core.classType", "core.resourceName", "core.parentResourceName", "core.resourceType"]
    pairs = [f"{k.split('.')[-1]}={facts[k]}" for k in wanted if facts.get(k)]
    extra = data.get("totalCount")
    if extra is not None:
        pairs.append(f"totalCount={extra}")
    return " | ".join(pairs) if pairs else data_str[:200]


def effective_request(cfg: Config, rest_path: str, method: str, strip_auth: bool = False,
                      user: Optional[User] = None) -> tuple[str, dict, str]:
    """Return (url, headers, body) for a proxy-servlet call, honoring a per-user identity."""
    cookies = cfg.cookies
    headers = dict(cfg.headers)
    base_url = cfg.base_url
    if user is not None:
        cookies = user.cookies
        headers = {**cfg.headers, **user.headers}
        base_url = user.base_url or cfg.base_url
    if cookies and not strip_auth:
        headers["Cookie"] = cookies
    if strip_auth:
        headers = {k: v for k, v in headers.items() if k.lower() not in AUTH_HEADER_KEYS}
    headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Accept", "application/json")
    url = base_url.rstrip("/") + cfg.servlet_path
    body = json.dumps(build_envelope(rest_path, method))
    return url, headers, body


# Optional callable(str) — set by a front-end to receive a line per HTTP request (live log).
REQUEST_LOGGER = None


_TILDE_RE = re.compile(r"~([0-9a-fA-F]{2})~")


def readable_path(path: str) -> str:
    """Decode a sent path for display: percent-decode + reverse Informatica ~hh~ path encoding."""
    try:
        s = urllib.parse.unquote(path)
        return _TILDE_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
    except Exception:
        return path


def _log_request(who: str, method: str, rest_path: str, detail: str) -> None:
    cb = REQUEST_LOGGER
    if cb:
        try:
            cb(f"» {who}{method} {readable_path(rest_path)[:160]} -> {detail}")
        except Exception:
            pass


def send(cfg: Config, session: "requests.Session", rest_path: str, method: str,
         strip_auth: bool = False, user: Optional[User] = None) -> Probe:
    url, headers, body = effective_request(cfg, rest_path, method, strip_auth, user)
    who = f"[{user.label}] " if user else ("[no-auth] " if strip_auth else "")
    try:
        resp = session.post(
            url, data=body, headers=headers,
            proxies=cfg.proxies, verify=cfg.verify, timeout=cfg.timeout,
        )
    except requests.RequestException as exc:
        _log_request(who, method, rest_path, f"ERROR {exc}")
        return Probe(ok=False, error=str(exc))
    probe = parse_envelope(resp)
    _log_request(who, method, rest_path, f"outer={probe.outer_status} inner={probe.inner_status} len={probe.resp_len}")
    return probe


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def build_curl(cfg: Config, rest_path: str, method: str, user: Optional[User] = None) -> str:
    """A copy-pasteable curl command that reproduces this exact proxy-servlet request."""
    url, headers, body = effective_request(cfg, rest_path, method, user=user)
    parts = ["curl", "-sk", "-X", "POST", _shell_quote(url)]
    for k, v in headers.items():
        parts += ["-H", _shell_quote(f"{k}: {v}")]
    parts += ["--data", _shell_quote(body)]
    return " ".join(parts)


def build_raw_request(cfg: Config, rest_path: str, method: str, user: Optional[User] = None) -> str:
    """A raw HTTP request (paste into Burp Repeater) reproducing this proxy-servlet call."""
    url, headers, body = effective_request(cfg, rest_path, method, user=user)
    host = urllib.parse.urlsplit(url).netloc
    lines = [f"POST {cfg.servlet_path} HTTP/1.1", f"Host: {host}"]
    headers.setdefault("Content-Length", str(len(body.encode("utf-8"))))
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines)


SEARCH_PATH = "/1/catalog/data/search"
_ID_RE = re.compile(r'"id"\s*:\s*"([^"]+)"')


def _collect_ids(node: Any, out: list[str]) -> None:
    """Recursively pull every ``id`` string out of a parsed search payload."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "id" and isinstance(v, str):
                out.append(v)
            else:
                _collect_ids(v, out)
    elif isinstance(node, list):
        for item in node:
            _collect_ids(item, out)


def fetch_inner(cfg: Config, session: "requests.Session", rest_path: str,
                method: str = "GET", user: Optional[User] = None):
    """Send a proxy-servlet request and return the parsed inner `data` (dict/list) or None."""
    url, headers, body = effective_request(cfg, rest_path, method, user=user)
    who = f"[{user.label}] " if user else ""
    try:
        resp = session.post(url, data=body, headers=headers,
                            proxies=cfg.proxies, verify=cfg.verify, timeout=cfg.timeout)
    except requests.RequestException as exc:
        _log_request(who, method, rest_path, f"ERROR {exc}")
        return None
    _log_request(who, method, rest_path, f"{resp.status_code} len={len(resp.text or '')}")
    try:
        env = resp.json()
    except ValueError:
        return None
    data = env.get("data") if isinstance(env, dict) else None
    if isinstance(data, str):
        try:
            return json.loads(data)
        except ValueError:
            return None
    return data


def _facts_map(item: dict) -> dict:
    """Flatten an item's attributes to {attr: value}.

    Handles BOTH response shapes: the objects endpoint uses `facts` ({name,value}); the
    search endpoint uses `values` ({id,value}). First value wins for repeated keys.
    """
    m: dict = {}
    for f in item.get("facts", []):
        if isinstance(f, dict) and f.get("name") is not None:
            m.setdefault(f["name"], f.get("value"))
    for f in item.get("values", []):
        if isinstance(f, dict) and f.get("id") is not None:
            m.setdefault(f["id"], f.get("value"))
    return m


def discover_resources(cfg: Config, session: "requests.Session", max_ids: int = 500,
                       query: str = "*", page_size: int = 100,
                       user: Optional[User] = None, class_type: str = "") -> list[ResourceInfo]:
    """Enumerate catalog objects visible to a session, PAGINATING through all results.

    Pagination advances by the number of items actually returned and stops at the server's
    reported ``totalCount``. `class_type` (e.g. "core.Resource") adds a Solr filter query so
    you can enumerate just Resources (11) instead of all ~900 objects. Returns rich
    ResourceInfo (id + name + class/asset type + resource type + parent resource/scanner).
    """
    out: list[ResourceInfo] = []
    seen: set[str] = set()
    offset = 0
    total = None
    who = f"[{user.label}] " if user else ""
    fq = f"&fq={urllib.parse.quote('core.classType:' + class_type, safe='')}" if class_type else ""
    page_size = max(1, min(page_size, max_ids))
    while len(out) < max_ids:
        rest = f"{SEARCH_PATH}?q={urllib.parse.quote(query, safe='')}&offset={offset}&pageSize={page_size}{fq}"
        data = fetch_inner(cfg, session, rest, user=user)
        items = data.get("items") if isinstance(data, dict) else (data if isinstance(data, list) else None)
        if total is None and isinstance(data, dict):
            total = data.get("totalCount")
            if REQUEST_LOGGER and total is not None:
                _log_request(who, "SEARCH", rest, f"totalCount={total}")
        if not items:
            break
        for it in items:
            if not isinstance(it, dict):
                continue
            # Keep the FULL object id (do NOT split on '://' — that would collapse every asset
            # under a resource into the resource itself, losing hundreds of distinct targets).
            full = str(it.get("id", ""))
            if not full or "/additionalFacts/" in full or full in seen:
                continue
            base = full
            facts = _facts_map(it)
            info = ResourceInfo(
                id=base,
                name=facts.get("core.name", "") or base,
                kind=facts.get("core.classType", ""),
                resource=facts.get("core.resourceName") or facts.get("core.parentResourceName", ""),
                res_type=facts.get("core.resourceType", ""),
                href=it.get("href", ""),
            )
            if user is not None:
                info.seen_by.add(user.label)
            seen.add(base)
            out.append(info)
            if len(out) >= max_ids:
                break
        offset += len(items)
        if total is not None and offset >= total:
            break
        if len(items) == 0:
            break
    if total is not None and len(out) < total and len(out) >= max_ids and REQUEST_LOGGER:
        _log_request(who, "SEARCH", "", f"stopped at max_ids={max_ids} of totalCount={total} — raise Max ids to get all")
    return out


DEFAULT_OBJECT_PATH = "/1/catalog/data/objects"

# Endpoints that accept a real catalog object id (resource OR asset). Injecting a catalog
# object id into anything else (model/config {id}, jobs, {resourceName}) is a different id
# space and just yields noise, so the sweep can be scoped to these.
DATA_OBJECT_MARKERS = (
    "/catalog/data/objects",
    "/catalog/data/relationships",
    "/catalog/data/objectsChildSummary",
)


def is_data_object_endpoint(ep: "Endpoint") -> bool:
    return any(m in ep.path for m in DATA_OBJECT_MARKERS)


_OBJECT_DETAIL_RE = re.compile(r".*/catalog/data/objects(/\{[^/}]+\})?$")


def is_object_detail_endpoint(ep: "Endpoint") -> bool:
    """True only for the canonical 'read this object' endpoints:
    /catalog/data/objects and /catalog/data/objects/{id}. NOT sub-resources
    (/reviews, /comments, …) and NOT model/config {id} endpoints (different id space).
    ENUM-LEAK is only meaningful here: search exposed the object but its detail is denied."""
    return bool(_OBJECT_DETAIL_RE.match(ep.path))


def fetch_envelope(cfg: Config, session: "requests.Session", rest_path: str,
                   method: str = "GET", user: Optional[User] = None):
    """Return the full parsed proxy-servlet envelope ({status,data,headers}) or None."""
    url, headers, body = effective_request(cfg, rest_path, method, user=user)
    who = f"[{user.label}] " if user else ""
    try:
        resp = session.post(url, data=body, headers=headers,
                            proxies=cfg.proxies, verify=cfg.verify, timeout=cfg.timeout)
    except requests.RequestException as exc:
        _log_request(who, method, rest_path, f"ERROR {exc}")
        return None
    _log_request(who, method, rest_path, f"{resp.status_code} len={len(resp.text or '')}")
    try:
        return resp.json()
    except ValueError:
        return {"status": resp.status_code, "data": (resp.text or "")[:100000], "nonjson": True}


def direct_get(cfg: Config, session: "requests.Session", rest_path: str,
               user: Optional[User] = None):
    """GET the REAL endpoint DIRECTLY (base + api_prefix + rest_path), bypassing the proxy servlet.

    The proxy servlet lossily UTF-8-decodes binary, corrupting files; the direct endpoint streams
    raw bytes. Returns the requests.Response (use .content for raw bytes) or None on error.
    """
    cookies = user.cookies if user else cfg.cookies
    headers = {**cfg.headers, **(user.headers if user else {})}
    if cookies:
        headers["Cookie"] = cookies
    headers.pop("Content-Type", None)  # this is a GET, not the JSON envelope POST
    base = (user.base_url if (user and user.base_url) else cfg.base_url).rstrip("/")
    url = base + cfg.api_prefix + rest_path
    who = f"[{user.label}] " if user else ""
    try:
        resp = session.get(url, headers=headers, proxies=cfg.proxies, verify=cfg.verify, timeout=cfg.timeout)
    except requests.RequestException as exc:
        _log_request(who, "GET(direct)", url, f"ERROR {exc}")
        return None
    _log_request(who, "GET(direct)", url, f"{resp.status_code} len={len(resp.content)} ct={resp.headers.get('Content-Type','')}")
    return resp


def dump_objects(cfg: Config, session: "requests.Session", ids: list[str],
                 user: Optional[User] = None, object_path: str = DEFAULT_OBJECT_PATH,
                 on_item=None, stop_check=None, pause_check=None) -> int:
    """Fetch the FULL object detail for each id (as `user`) and hand each to `on_item`.

    Used to dump all reachable data — the complete metadata each object exposes, not just a
    verdict. `on_item` receives {"id","inner_status","data"} so the caller can stream to disk.
    """
    n = 0
    for rid in ids:
        if stop_check and stop_check():
            break
        _wait_if_paused(pause_check, stop_check)
        payload = build_payload("id", cfg, rid)
        rest = f"{object_path}?id={urllib.parse.quote(payload, safe='')}"
        env = fetch_envelope(cfg, session, rest, "GET", user=user)
        data = env.get("data") if isinstance(env, dict) else None
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                pass
        item = {"id": rid, "inner_status": (env or {}).get("status"), "data": data}
        n += 1
        if on_item:
            on_item(item)
        _sleep(cfg)
    return n


def group_by_scanner(resources: list[ResourceInfo]) -> dict[str, list[ResourceInfo]]:
    """Group discovered objects by their parent resource/scanner (the 'source')."""
    groups: dict[str, list[ResourceInfo]] = {}
    for r in resources:
        key = r.resource or r.name or "(ungrouped)"
        groups.setdefault(key, []).append(r)
    return groups


def discover_ids(cfg: Config, session: "requests.Session", max_ids: int = 25,
                 query: str = "*", user: Optional[User] = None) -> list[str]:
    """Backward-compatible helper: just the base ids (paginated)."""
    return [r.id for r in discover_resources(cfg, session, max_ids=max_ids, query=query, user=user)]


AUTH_FAIL_MARKERS = [
    "j_security_check",
    "session has expired",
    "session expired",
    "please sign in",
    "please log in",
    "authentication required",
    "authentication failed",
]


def looks_like_auth_failure(probe: Optional[Probe]) -> bool:
    """True if a probe looks like the session died (login redirect / HTML), not a normal deny.

    A normal per-object denial is a valid JSON envelope with a 403/empty inner body.
    Session loss instead yields an HTTP redirect/401 or a non-JSON login page.
    """
    if probe is None:
        return False
    if probe.outer_status in (301, 302, 401):
        return True
    if not probe.ok:  # non-JSON response from a JSON API -> most likely a login page
        low = probe.raw_snippet.lower()
        if "<html" in low or "<!doctype" in low or any(m in low for m in AUTH_FAIL_MARKERS):
            return True
    return False


def check_session(cfg: Config, session: "requests.Session", user: Optional[User] = None) -> tuple[bool, str]:
    """Pre-flight: confirm the supplied cookies still authenticate before sweeping."""
    rest_path = f"{SEARCH_PATH}?q=*&offset=0&pageSize=1"
    probe = send(cfg, session, rest_path, "GET", strip_auth=False, user=user)
    who = f"[{user.label}] " if user else ""
    if looks_like_auth_failure(probe):
        return False, f"{who}session looks invalid/expired (outer={probe.outer_status}, non-JSON={not probe.ok})"
    if not probe.ok:
        return False, f"{who}unexpected non-JSON response ({probe.error or 'parse failed'})"
    if probe.outer_status is not None and probe.outer_status >= 400:
        return False, f"{who}HTTP {probe.outer_status} — request/session invalid (check the pasted request/cookies)"
    if probe.inner_status is None:
        return False, f"{who}no inner status in response — session likely invalid (check cookies/token)"
    if probe.inner_status >= 400:
        return False, f"{who}search returned inner status {probe.inner_status} — session likely invalid"
    return True, f"{who}session OK (search inner status {probe.inner_status})"


SESSION_FAIL_THRESHOLD = 5


# Verdicts
VULNERABLE = "VULNERABLE"
DENIED = "DENIED"
INCONCLUSIVE = "INCONCLUSIVE"
ERROR = "ERROR"
PUBLIC = "PUBLIC(no-auth)"
OWNED = "OWNED"  # user accessed a resource in its DECLARED legitimate scope (expected)
ACCESSIBLE = "ACCESSIBLE?"  # user can read it, but ownership isn't declared -> needs review
ENUM_LEAK = "ENUM-LEAK"  # search exposed an out-of-scope resource even though detail was denied
SKIPPED = "NOT-SCANNED"  # endpoint needs intermediate ids we don't have; not tested


def _meaningfully_more(b: Probe, n: Optional[Probe]) -> bool:
    """True if `b` carries substantially more content than the negative-control `n`."""
    if n is None:
        return True
    return b.word_count > max(1, int(n.word_count * 1.25))


def classify(
    a: Optional[Probe],
    b: Probe,
    c: Optional[Probe],
    threshold: int,
    n: Optional[Probe] = None,
    min_length: int = 0,
) -> tuple[str, str]:
    """Return (verdict, note) for the forbidden-id probe `b`.

    `a` = control/owned probe (or None), `c` = no-auth probe (or None),
    `n` = negative-control probe using a garbage id (or None).
    """
    if not b.ok:
        return ERROR, b.error or "request failed"

    b_access = b.is_access(threshold, min_length)
    c_access = c.is_access(threshold, min_length) if c is not None else False
    n_access = n.is_access(threshold, min_length) if n is not None else False
    # If a nonexistent id already returns "access-looking" content of similar size,
    # this endpoint hands back boilerplate for ANY id -> word count proves nothing here.
    indiscriminate = n_access and not _meaningfully_more(b, n)

    # Differential mode (control baseline available).
    if a is not None:
        a_access = a.is_access(threshold, min_length)
        if not a_access:
            return (
                INCONCLUSIVE,
                f"control baseline did not return access (a={a.word_count}w inner={a.inner_status}); cannot compare",
            )
        if not b_access:
            return DENIED, f"forbidden id denied (b={b.word_count}w inner={b.inner_status} totalCount={b.total_count})"
        if indiscriminate:
            return INCONCLUSIVE, f"endpoint returns content for a garbage id too (b={b.word_count}w n={n.word_count}w)"
        if c_access:
            return PUBLIC, f"forbidden AND no-auth both returned data (b={b.word_count}w c={c.word_count}w)"
        return VULNERABLE, f"forbidden looks like control, unlike no-auth/garbage (a={a.word_count}w b={b.word_count}w n={n.word_count if n else '-'}w)"

    # Heuristic mode (no control baseline).
    if not b_access:
        return DENIED, f"data={b.word_count}w, inner={b.inner_status}, totalCount={b.total_count}"
    if indiscriminate:
        return INCONCLUSIVE, f"endpoint returns content for a garbage id too (b={b.word_count}w n={n.word_count}w); supply --control-id"
    if c is not None and c_access:
        return PUBLIC, f"data returned WITH and WITHOUT auth (b={b.word_count}w c={c.word_count}w)"
    note = f"data={b.word_count}w, inner={b.inner_status}"
    note += f", garbage={n.word_count}w" if n is not None else ""
    note += " (no-auth denied)" if c is not None else " (heuristic)"
    return VULNERABLE, note


# --------------------------------------------------------------------------------------
# Insertion-point selection
# --------------------------------------------------------------------------------------

_KIND_PRIORITY = {"id": 0, "resource": 1, "objectid": 2, "name": 3, "q": 4, "userid": 5, "generic": 6}


def select_insertion_points(ep: Endpoint, mode: str, use_userid: bool) -> list[InsertionPoint]:
    pts = [p for p in ep.insertion_points if p.kind != "userid" or use_userid]
    if not pts:
        return []
    if mode == "all":
        return pts
    if mode == "interactive":
        return _interactive_select(ep, pts)
    # auto: single best pick
    pts_sorted = sorted(pts, key=lambda p: (_KIND_PRIORITY.get(p.kind, 9), p.location != "query"))
    return [pts_sorted[0]]


def _interactive_select(ep: Endpoint, pts: list[InsertionPoint]) -> list[InsertionPoint]:
    print(f"\n{ep.label()}")
    for i, p in enumerate(pts):
        print(f"  [{i}] {p.label()}  (kind={p.kind})")
    raw = input("  select points (comma indices / 'a'=all / ''=skip): ").strip().lower()
    if raw == "":
        return []
    if raw == "a":
        return pts
    chosen = []
    for tok in raw.split(","):
        tok = tok.strip()
        if tok.isdigit() and int(tok) < len(pts):
            chosen.append(pts[int(tok)])
    return chosen


# --------------------------------------------------------------------------------------
# Sweep orchestration
# --------------------------------------------------------------------------------------


@dataclass
class Result:
    endpoint: str
    method: str
    insertion: str
    resource_id: str
    verdict: str
    note: str
    inner_status: Optional[int]
    word_count: int
    rest_path: str
    user: str = ""
    owned: Optional[bool] = None
    resp_len: int = 0
    data_summary: str = ""
    curl: str = ""
    raw_request: str = ""
    response: str = ""  # response body seen (inner data or raw snippet) — for the detail popup
    is_file: bool = False  # response carries a downloadable file/attachment
    filename: str = ""
    file_ext: str = ""

    @property
    def is_finding(self) -> bool:
        # Anything the tester must look at: confirmed leaks, undeclared-but-accessible,
        # and search/enumeration exposing out-of-scope objects.
        return self.verdict in (VULNERABLE, PUBLIC, ACCESSIBLE, ENUM_LEAK)


def _wait_if_paused(pause_check, stop_check) -> None:
    """Block while pause_check() is True, returning early if stop_check() trips."""
    while pause_check and pause_check():
        if stop_check and stop_check():
            return
        time.sleep(0.15)


def run_sweep(
    cfg: Config,
    endpoints: list[Endpoint],
    target_ids: list[str],
    insertion_mode: str,
    use_userid: bool,
    dry_run: bool,
    on_result=None,
    stop_check=None,
    on_warning=None,
    pause_check=None,
    on_reauth=None,
) -> list[Result]:
    """Sweep every (endpoint, insertion point, target id) combination.

    `target_ids` are the resource ids to test access to (forbidden / enumerated).
    `on_result` is an optional callback(Result) for live UI updates.
    `stop_check` is an optional callable; if it returns True the sweep aborts early.
    `pause_check` is an optional callable; while it returns True the sweep holds.
    `on_warning` is an optional callback(str) for out-of-band warnings (e.g. session loss).
    `on_reauth()` (optional) is called — and BLOCKS — when the session looks expired, so a
    front-end can refresh cfg.cookies before the sweep continues.
    """
    session = requests.Session()
    results: list[Result] = []
    have_control = bool(cfg.control_id)
    run_c = cfg.run_noauth and not dry_run
    run_n = cfg.run_negative and not dry_run
    consecutive_authfail = 0
    session_warned = False

    def warn(msg: str) -> None:
        print(f"  WARNING: {msg}")
        if on_warning:
            on_warning(msg)

    for ep in endpoints:
        if stop_check and stop_check():
            break
        points = select_insertion_points(ep, insertion_mode, use_userid)
        if not points:
            continue
        for ip in points:
            # Negative control: one garbage-id probe per (endpoint, insertion), reused below.
            n_probe = None
            if run_n:
                n_payload = build_payload(ip.kind, cfg, cfg.negative_id)
                n_path = build_rest_path(ep, ip, n_payload, cfg.path_values)
                n_probe = send(cfg, session, n_path, ep.method, strip_auth=False)
                _sleep(cfg)

            for rid in target_ids:
                _wait_if_paused(pause_check, stop_check)
                if stop_check and stop_check():
                    return results
                b_payload = build_payload(ip.kind, cfg, rid)
                b_path = build_rest_path(ep, ip, b_payload, cfg.path_values)

                if dry_run:
                    env = build_envelope(b_path, ep.method)
                    print(json.dumps(env, ensure_ascii=False))
                    res = Result(ep.path, ep.method.upper(), ip.label(), rid, "DRY-RUN", "not sent", None, 0, b_path)
                    results.append(res)
                    if on_result:
                        on_result(res)
                    continue

                a_probe = None
                c_probe = None
                if have_control:
                    a_payload = build_payload(ip.kind, cfg, cfg.control_id)
                    a_path = build_rest_path(ep, ip, a_payload, cfg.path_values)
                    a_probe = send(cfg, session, a_path, ep.method, strip_auth=False)
                    _sleep(cfg)

                b_probe = send(cfg, session, b_path, ep.method, strip_auth=False)
                _sleep(cfg)

                # Session-expiry watchdog: a streak of login-redirect/HTML responses means the
                # session likely died. Pause for re-auth (blocking) if a handler is provided.
                if looks_like_auth_failure(b_probe):
                    consecutive_authfail += 1
                    if consecutive_authfail >= SESSION_FAIL_THRESHOLD:
                        if on_reauth and not (stop_check and stop_check()):
                            on_reauth(None)   # BLOCKS until cfg.cookies refreshed (or stop)
                            consecutive_authfail = 0
                            b_probe = send(cfg, session, b_path, ep.method, strip_auth=False)
                            _sleep(cfg)
                        elif not session_warned:
                            session_warned = True
                            warn("session may have expired — several authenticated requests returned "
                                 "login/redirect responses. Results past this point may be false DENIEDs.")
                            consecutive_authfail = 0
                else:
                    consecutive_authfail = 0

                if run_c:
                    c_probe = send(cfg, session, b_path, ep.method, strip_auth=True)
                    _sleep(cfg)

                verdict, note = classify(a_probe, b_probe, c_probe, cfg.word_threshold, n_probe, cfg.min_length)
                res = Result(
                    endpoint=ep.path,
                    method=ep.method.upper(),
                    insertion=ip.label(),
                    resource_id=rid,
                    verdict=verdict,
                    note=note,
                    inner_status=b_probe.inner_status,
                    word_count=b_probe.word_count,
                    rest_path=b_path,
                    resp_len=b_probe.resp_len,
                    data_summary=summarize_facts(b_probe.data_str) if verdict in (VULNERABLE, PUBLIC, ACCESSIBLE, OWNED) else "",
                    curl=build_curl(cfg, b_path, ep.method),
                    raw_request=build_raw_request(cfg, b_path, ep.method),
                    response=(b_probe.raw_full or b_probe.data_str),
                    is_file=b_probe.is_file, filename=b_probe.filename, file_ext=b_probe.file_ext,
                )
                results.append(res)
                _print_row(res)
                if on_result:
                    on_result(res)

    return results


def run_multiuser_sweep(
    cfg: Config,
    endpoints: list[Endpoint],
    users: list[User],
    target_ids: list[str],
    insertion_mode: str,
    use_userid: bool,
    on_result=None,
    stop_check=None,
    on_warning=None,
    pause_check=None,
    on_reauth=None,
) -> list[Result]:
    """Cross-user IDOR sweep.

    For each user, test every target resource across the chosen endpoints. Because we know
    each user's own enumerable set (``user.owned_ids``), the verdict is DEFINITIVE:
      * access to a resource NOT in the user's own set  -> VULNERABLE (real IDOR)
      * access to one the user owns                     -> OWNED (expected baseline)
      * no access                                       -> DENIED
    The negative-control probe still confirms that "access" means real content.

    `on_reauth(user)` (optional) is called — and BLOCKS — when a user's session looks expired
    (a streak of auth failures). The callback should refresh `user.cookies`/`user.headers`
    (e.g. prompt for a fresh request) before returning; the sweep then continues with them.
    """
    session = requests.Session()
    results: list[Result] = []
    run_n = cfg.run_negative
    authfail: dict = {}  # per-user consecutive auth-failure count (session-expiry watchdog)

    def warn(msg: str) -> None:
        print(f"  WARNING: {msg}")
        if on_warning:
            on_warning(msg)

    def watchdog(user, probe) -> None:
        """Track auth-failure streaks per user; pause for re-auth when the session dies."""
        if looks_like_auth_failure(probe):
            authfail[user.label] = authfail.get(user.label, 0) + 1
            if authfail[user.label] >= SESSION_FAIL_THRESHOLD:
                if on_reauth and not (stop_check and stop_check()):
                    on_reauth(user)          # BLOCKS until fresh creds (or stop)
                    authfail[user.label] = 0
                else:
                    warn(f"[{user.label}] session may have expired (login/redirect responses).")
                    authfail[user.label] = 0
        else:
            authfail[user.label] = 0

    for ep in endpoints:
        if stop_check and stop_check():
            break
        for ip in select_insertion_points(ep, insertion_mode, use_userid):
            # Negative control per (endpoint, insertion) using the first user's session.
            n_probe = None
            if run_n and users:
                n_path = build_rest_path(ep, ip, build_payload(ip.kind, cfg, cfg.negative_id), cfg.path_values)
                n_probe = send(cfg, session, n_path, ep.method, user=users[0])
                _sleep(cfg)

            for user in users:
                for rid in target_ids:
                    _wait_if_paused(pause_check, stop_check)
                    if stop_check and stop_check():
                        return results
                    b_path = build_rest_path(ep, ip, build_payload(ip.kind, cfg, rid), cfg.path_values)
                    b_probe = send(cfg, session, b_path, ep.method, user=user)
                    _sleep(cfg)

                    if looks_like_auth_failure(b_probe):
                        watchdog(user, b_probe)   # may block for re-auth, then retry this rid
                        if stop_check and stop_check():
                            return results
                        b_probe = send(cfg, session, b_path, ep.method, user=user)  # retry with fresh creds
                        _sleep(cfg)
                    else:
                        authfail[user.label] = 0

                    access = b_probe.is_access(cfg.word_threshold, cfg.min_length)
                    indiscriminate = (
                        n_probe is not None
                        and n_probe.is_access(cfg.word_threshold, cfg.min_length)
                        and not _meaningfully_more(b_probe, n_probe)
                    )
                    declared = user.owned_declared
                    owned = rid in user.owned_ids if declared else None
                    enumerable = rid in user.enum_ids  # search returned this object to the user
                    # ENUM-LEAK only makes sense on the object-detail endpoint (search exposed the
                    # object but its DETAIL read is denied). A 404/deny on any other endpoint is just
                    # "not addressable here", not a leak.
                    detail_ep = is_object_detail_endpoint(ep)
                    # A "clean denial" of an existing object: 403 Forbidden, or 200 with empty/
                    # totalCount:0. A 400/404/5xx is a bad-request/not-found/error — NOT a leak.
                    clean_denial = b_probe.ok and (
                        b_probe.inner_status == 403
                        or (b_probe.inner_status in (None, 200) and b_probe.total_count == 0)
                    )
                    ln = f"len={b_probe.resp_len}, inner={b_probe.inner_status}"
                    if not b_probe.ok:
                        verdict, note = ERROR, b_probe.error or "request failed"
                    elif not access:
                        if cfg.enum_leak and detail_ep and enumerable and clean_denial and not (declared and owned):
                            if declared:
                                verdict, note = ENUM_LEAK, (
                                    f"object detail denied, but search returned this to {user.label} though it's "
                                    f"OUTSIDE its declared scope (existence/metadata disclosure, {ln})")
                            else:
                                verdict, note = ENUM_LEAK, (
                                    f"object detail denied, but {user.label} could enumerate it via search "
                                    f"(metadata/existence exposed; declare owns to confirm out-of-scope, {ln})")
                        else:
                            verdict, note = DENIED, f"no access ({ln})"
                    elif indiscriminate:
                        verdict, note = INCONCLUSIVE, f"endpoint returns content for a garbage id too ({ln})"
                    elif declared:
                        # Authoritative: verdict is definitive against the declared scope.
                        if owned:
                            verdict, note = OWNED, f"{user.label} owns this (declared scope, {ln})"
                        else:
                            verdict, note = VULNERABLE, f"{user.label} read a resource OUTSIDE its declared scope ({ln})"
                    else:
                        # No declared scope: enumeration is NOT proof of ownership.
                        if rid not in user.enum_ids:
                            verdict, note = VULNERABLE, (
                                f"{user.label} read a resource it could not even enumerate ({ln}) "
                                f"— search hid it, detail leaked it")
                        else:
                            verdict, note = ACCESSIBLE, (
                                f"{user.label} can read this; ownership undeclared ({ln}) "
                                f"— declare this user's owned ids to confirm leak vs. legitimate")

                    res = Result(
                        endpoint=ep.path, method=ep.method.upper(), insertion=ip.label(),
                        resource_id=rid, verdict=verdict, note=note,
                        inner_status=b_probe.inner_status, word_count=b_probe.word_count,
                        rest_path=b_path, user=user.label, owned=owned, resp_len=b_probe.resp_len,
                        data_summary=summarize_facts(b_probe.data_str) if verdict in (VULNERABLE, PUBLIC, ACCESSIBLE, OWNED) else "",
                        curl=build_curl(cfg, b_path, ep.method, user=user),
                        raw_request=build_raw_request(cfg, b_path, ep.method, user=user),
                        response=(b_probe.raw_full or b_probe.data_str),
                        is_file=b_probe.is_file, filename=b_probe.filename, file_ext=b_probe.file_ext,
                    )
                    results.append(res)
                    _print_row(res)
                    if on_result:
                        on_result(res)

    return results


def _sleep(cfg: Config) -> None:
    if cfg.delay > 0:
        time.sleep(cfg.delay)


# --------------------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------------------

_COLORS = {
    VULNERABLE: "\033[91m",  # red
    PUBLIC: "\033[95m",  # magenta
    ACCESSIBLE: "\033[35m",  # dim magenta
    ENUM_LEAK: "\033[33m",  # orange
    SKIPPED: "\033[94m",  # blue
    DENIED: "\033[92m",  # green
    OWNED: "\033[96m",  # cyan
    INCONCLUSIVE: "\033[93m",  # yellow
    ERROR: "\033[90m",  # grey
}
_RESET = "\033[0m"


def _color(verdict: str, use_color: bool) -> str:
    if not use_color:
        return verdict
    return f"{_COLORS.get(verdict, '')}{verdict}{_RESET}"


try:
    _USE_COLOR = bool(sys.stdout.isatty())
except Exception:
    _USE_COLOR = False


def _short(value: str, width: int = 28) -> str:
    return value if len(value) <= width else value[: width - 1] + "…"


def _print_row(res: Result) -> None:
    print(
        f"  {_color(res.verdict, _USE_COLOR):<24} "
        f"{res.method:<6} inner={str(res.inner_status):<5} "
        f"words={res.word_count:<5} {res.endpoint}  [{res.insertion}]  id={_short(res.resource_id)}"
    )


def print_summary(results: list[Result]) -> None:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    print("\n=== Summary ===")
    for verdict in (VULNERABLE, PUBLIC, ACCESSIBLE, ENUM_LEAK, DENIED, OWNED, INCONCLUSIVE, SKIPPED, ERROR, "DRY-RUN"):
        if verdict in counts:
            print(f"  {_color(verdict, _USE_COLOR):<24} {counts[verdict]}")
    vulns = [r for r in results if r.verdict in (VULNERABLE, PUBLIC, ACCESSIBLE, ENUM_LEAK)]
    if vulns:
        print("\n!! Potential access leaks:")
        for r in vulns:
            who = f"user={r.user} " if r.user else ""
            print(f"   {who}{r.method} {r.endpoint}  [{r.insertion}]  id={_short(r.resource_id)}  -> {r.note}")


REPORT_COLUMNS = [
    "verdict", "user", "owned", "method", "endpoint", "insertion", "resource_id",
    "inner_status", "resp_len", "word_count", "note", "data_summary", "rest_path",
    "curl", "raw_request", "response",
]

# Findings-sheet columns (admin-facing: what's vulnerable + what data was exposed + how to replay).
FINDING_COLUMNS = [
    "verdict", "user", "resource_id", "method", "endpoint", "inner_status", "resp_len",
    "data_summary", "response", "curl", "raw_request",
]
FINDING_VERDICTS = (VULNERABLE, PUBLIC, ACCESSIBLE, ENUM_LEAK)
_XLSX_CELL_MAX = 32000  # Excel hard limit is 32767 chars per cell


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= _XLSX_CELL_MAX else s[:_XLSX_CELL_MAX] + " …[truncated]"


def _report_row(r: Result) -> list:
    return [getattr(r, c, "") for c in REPORT_COLUMNS]


def write_report(results: list[Result], out_path: str, meta: Optional[dict] = None) -> None:
    """Write the report. Format by extension: .csv / .xlsx / .html / .json — all carry the
    full evidence (curl + raw request) so any finding can be replayed."""
    low = out_path.lower()
    if low.endswith(".csv"):
        with open(out_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(REPORT_COLUMNS)
            for r in results:
                w.writerow(_report_row(r))
    elif low.endswith((".xlsx", ".xls")):
        _write_xlsx(results, out_path, meta)
    elif low.endswith((".html", ".htm")):
        import bola_report
        bola_report.write_html_report(results, out_path, meta)
    else:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump([r.__dict__ for r in results], fh, indent=2)
    print(f"\nReport written to {out_path}")


def _write_xlsx(results: list[Result], out_path: str, meta: Optional[dict] = None) -> None:
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        raise SystemExit("Excel export needs openpyxl:  pip install openpyxl  (or export .csv, which Excel opens)")

    wb = openpyxl.Workbook()
    fills = {
        VULNERABLE: "C0392B", PUBLIC: "8E44AD", ACCESSIBLE: "B0568A",
        ENUM_LEAK: "E0932F", SKIPPED: "3A6EA5", OWNED: "1E8449",
    }
    hdr_font = Font(bold=True, color="FFFFFF")
    hdr_fill = PatternFill("solid", fgColor="1F6AA5")

    def _sheet(name, columns, rows_):
        ws = wb.create_sheet(name)
        ws.append([c.replace("_", " ").title() for c in columns])
        for cell in ws[1]:
            cell.font, cell.fill = hdr_font, hdr_fill
        for r in rows_:
            ws.append([_cell(getattr(r, c, "")) for c in columns])
            fill = fills.get(r.verdict)
            if fill:
                ws.cell(row=ws.max_row, column=1).fill = PatternFill("solid", fgColor=fill)
                ws.cell(row=ws.max_row, column=1).font = hdr_font
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                cell.alignment = Alignment(vertical="top", wrap_text=True)
        ws.freeze_panes = "A2"
        if ws.max_row >= 1:
            ws.auto_filter.ref = ws.dimensions
        return ws

    # Sheet 1 — Findings: only the rows that matter, with the exposed data + how to replay.
    findings = [r for r in results if r.verdict in FINDING_VERDICTS]
    fs = _sheet("Findings", FINDING_COLUMNS, findings)
    for col, w in {"A": 14, "B": 12, "C": 46, "E": 40, "H": 44, "I": 60, "J": 60, "K": 60}.items():
        fs.column_dimensions[col].width = w
    if not findings:
        fs.append(["(no VULNERABLE / PUBLIC / ACCESSIBLE? / ENUM-LEAK findings)"])

    # Optional run-meta sheet.
    if meta:
        ms = wb.create_sheet("Run info")
        for k, v in meta.items():
            ms.append([str(k), str(v)])

    # Sheet — All results (full dump).
    allsheet = _sheet("All results", REPORT_COLUMNS, results)
    for col, w in {"E": 42, "G": 30, "L": 40, "M": 50, "N": 60, "O": 60, "P": 60}.items():
        allsheet.column_dimensions[col].width = w

    if "Sheet" in wb.sheetnames:   # drop the default empty sheet
        del wb["Sheet"]

    # Access-matrix sheet: object rows x user columns -> verdict (the admin "who can reach what").
    try:
        import bola_report
        users, rows = bola_report.build_matrix(results)
        if users and rows:
            ms = wb.create_sheet("access-matrix")
            ms.append(["resource_id"] + users)
            for cell in ms[1]:
                cell.font = Font(bold=True, color="FFFFFF")
                cell.fill = PatternFill("solid", fgColor="1F6AA5")
            for rid, row in sorted(rows.items()):
                line = [rid] + [row["cells"].get(u, "") for u in users]
                ms.append(line)
                for ci, u in enumerate(users, start=2):
                    fill = fills.get(row["cells"].get(u))
                    if fill:
                        ms.cell(row=ms.max_row, column=ci).fill = PatternFill("solid", fgColor=fill)
                        ms.cell(row=ms.max_row, column=ci).font = Font(bold=True, color="FFFFFF")
            ms.column_dimensions["A"].width = 60
            ms.freeze_panes = "B2"
    except Exception:
        pass

    wb.save(out_path)


# --------------------------------------------------------------------------------------
# Config assembly + CLI
# --------------------------------------------------------------------------------------


def load_swagger(path: Optional[str]) -> dict:
    """Load the OpenAPI spec: explicit --swagger path if given, else the embedded copy."""
    if path:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    if load_bundled_swagger is not None:
        return load_bundled_swagger()
    raise SystemExit("No --swagger given and the bundled swagger_data.py is missing.")


def parse_raw_request(text: str) -> dict:
    """Parse a raw HTTP request (e.g. copied from Burp) into config fields.

    Extracts base_url (from the request line + Host), cookies, and all headers.
    Returns a dict suitable for merging into a Config.
    """
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        return {}

    # Request line:  METHOD /path HTTP/1.1
    parts = lines[0].split()
    req_path = parts[1] if len(parts) >= 2 and parts[1].startswith("/") else ""

    headers: dict[str, str] = {}
    cookies = ""
    host = ""
    for line in lines[1:]:
        if not line.strip():
            break  # blank line -> body begins
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        key, val = key.strip(), val.strip()
        low = key.lower()
        if low == "host":
            host = val
        elif low == "cookie":
            cookies = val
        else:
            headers[key] = val

    scheme = "https"
    base_url = f"{scheme}://{host}" if host else ""

    out: dict = {"headers": headers}
    if base_url:
        out["base_url"] = base_url
    if cookies:
        out["cookies"] = cookies
    # If the captured request is itself a proxy-servlet call, remember its servlet path.
    if req_path and "ldmProxyServlet" in req_path:
        out["servlet_path"] = req_path.split("?")[0]
    return out


# --------------------------------------------------------------- paste formats
# Order matters: the GUI shows these verbatim in the per-user "format" dropdown,
# and the CLI accepts them (case-insensitively) via --paste-format.
PASTE_FORMATS = [
    "Raw HTTP",
    "curl (bash)",
    "curl (cmd)",
    "curl (PowerShell)",
    "fetch / JS",
    "XHR (JS)",
]

COOKIE_MISSING_WARN = (
    "No Cookie found in this paste. Chrome/Firefox omit cookies from 'Copy as fetch' "
    "(they ride the browser cookie jar via credentials:'include'). Use 'Copy as cURL' "
    "for this user, or add the session cookie manually."
)


def _finalize_parsed(url: str, headers: dict, cookies: str = "") -> dict:
    """Normalise (url, headers, cookies) captured from any browser paste format into the
    same config dict that :func:`parse_raw_request` returns.

    A ``Cookie`` header (any casing) is folded into ``cookies``; the URL yields ``base_url``
    (scheme+host) and, when it targets the proxy servlet, ``servlet_path``. When no cookie is
    present a ``warnings`` list is added (curl includes cookies, fetch/XHR usually do not).
    """
    headers = dict(headers or {})
    for key in list(headers):  # fold a Cookie header into cookies (fetch/xhr put it here)
        if key.lower() == "cookie":
            cookies = cookies or headers.pop(key)

    out: dict = {"headers": headers}
    path = ""
    if url:
        split = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        if split.scheme and split.netloc:
            out["base_url"] = f"{split.scheme}://{split.netloc}"
        path = split.path or ""
    if cookies and cookies.strip():
        out["cookies"] = cookies.strip()
    else:
        out["warnings"] = [COOKIE_MISSING_WARN]
    if path and "ldmProxyServlet" in path:
        out["servlet_path"] = path
    return out


def _walk_curl_tokens(tokens: list[str]) -> tuple[str, dict, str]:
    """Given shell-split curl argv, pull the URL, headers, and cookie string."""
    url, cookies = "", ""
    headers: dict[str, str] = {}
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if tok in ("curl", "curl.exe"):
            i += 1
            continue
        if tok in ("-H", "--header") and nxt:
            if ":" in nxt:
                key, val = nxt.split(":", 1)
                headers[key.strip()] = val.strip()
            i += 2
            continue
        if tok in ("-b", "--cookie") and nxt:
            if not nxt.startswith("@"):  # @file cookie jars aren't a paste we can read
                cookies = nxt
            i += 2
            continue
        if tok in ("-X", "--request", "-e", "--referer", "-A", "--user-agent") and nxt:
            if tok in ("-A", "--user-agent"):
                headers["User-Agent"] = nxt
            elif tok in ("-e", "--referer"):
                headers["Referer"] = nxt
            i += 2
            continue
        if tok in ("--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "-d") and nxt:
            i += 2  # body isn't needed (the tool generates its own inner request)
            continue
        if tok.startswith("-"):
            i += 1  # value-less flags: --compressed, -s, -k, -sk, --location, --insecure
            continue
        if not url and ("://" in tok or tok.startswith("http") or "." in tok):
            url = tok
        i += 1
    return url, headers, cookies


def parse_curl(text: str, cmd: bool = False) -> dict:
    """Parse a ``curl`` command copied from browser DevTools.

    ``cmd=False`` handles the bash form (Chrome 'Copy as cURL (bash)' / Firefox 'Copy as
    cURL'): ``\\``-newline continuations, single-quoted args. ``cmd=True`` handles the
    Windows form (Chrome 'Copy as cURL (cmd)'): ``^``-newline continuations and ``^`` escapes.
    """
    if cmd:
        text = re.sub(r"\^\r?\n\s*", " ", text)  # caret line-continuations
        text = re.sub(r"\^(.)", r"\1", text)      # strip remaining cmd caret-escapes
    else:
        text = re.sub(r"\\\r?\n\s*", " ", text)  # backslash line-continuations
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = shlex.split(text.replace("\\", "\\\\"), posix=True)
    url, headers, cookies = _walk_curl_tokens(tokens)
    return _finalize_parsed(url, headers, cookies)


def parse_curl_pwsh(text: str) -> dict:
    """Parse a PowerShell ``Invoke-WebRequest``/``Invoke-RestMethod`` snippet (Chrome/Firefox
    'Copy as PowerShell'). Handles ``-Uri``, ``-Headers @{...}``, ``-ContentType`` and
    Firefox's ``$session.Cookies.Add(New-Object System.Net.Cookie("name","value",...))``."""
    def _q(pattern: str) -> str:
        m = re.search(pattern, text, re.IGNORECASE)
        return m.group(1) if m else ""

    url = _q(r'-Uri\s+["\']([^"\']+)["\']')
    headers: dict[str, str] = {}
    ct = _q(r'-ContentType\s+["\']([^"\']+)["\']')
    if ct:
        headers["Content-Type"] = ct

    block = re.search(r'-Headers\s+@\{(.*?)\}', text, re.DOTALL | re.IGNORECASE)
    if block:
        for key, val in re.findall(r'["\']([^"\']+)["\']\s*=\s*["\']([^"\']*)["\']', block.group(1)):
            headers[key.strip()] = val.strip()

    # Firefox emits cookies as individual System.Net.Cookie objects on a WebSession.
    pairs = re.findall(r'System\.Net\.Cookie\(\s*["\']([^"\']*)["\']\s*,\s*["\']([^"\']*)["\']', text)
    cookies = "; ".join(f"{n}={v}" for n, v in pairs)
    return _finalize_parsed(url, headers, cookies)


def _balanced_brace(text: str, start: int) -> str:
    """Return the ``{...}`` substring (inclusive) beginning at the ``{`` at/after ``start``."""
    open_at = text.find("{", start)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_at:i + 1]
    return ""


def parse_fetch(text: str) -> dict:
    """Parse a ``fetch(url, {...})`` snippet (Chrome/Firefox 'Copy as fetch', 'Node.js fetch')."""
    m = re.search(r'fetch\(\s*["\']([^"\']+)["\']', text)
    url = m.group(1) if m else ""
    headers: dict[str, str] = {}
    hidx = re.search(r'["\']headers["\']\s*:', text)
    if hidx:
        block = _balanced_brace(text, hidx.end())
        parsed = False
        if block:
            try:
                obj = json.loads(block)
                headers = {str(k): str(v) for k, v in obj.items()}
                parsed = True
            except (ValueError, AttributeError):
                parsed = False
        if not parsed:
            for key, val in re.findall(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']*)["\']', block or ""):
                headers[key] = val
    return _finalize_parsed(url, headers)


def parse_xhr(text: str) -> dict:
    """Parse an ``XMLHttpRequest`` snippet: ``xhr.open(method,url)`` + ``setRequestHeader(k,v)``."""
    m = re.search(r'\.open\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']', text)
    url = m.group(2) if m else ""
    headers: dict[str, str] = {}
    for key, val in re.findall(r'setRequestHeader\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']*)["\']', text):
        headers[key] = val
    return _finalize_parsed(url, headers)


def detect_paste_format(text: str) -> str:
    """Best-effort sniff: name the paste format as a PASTE_FORMATS value, or "" if the box is
    empty or nothing recognisable is present. Used for the GUI's live "… detected" hint and by
    the ``"auto"`` path of :func:`parse_pasted_request`."""
    head = (text or "").lstrip()
    if not head:
        return ""
    low = head.lower()
    if low.startswith("curl ") or low.startswith("curl.exe") or low == "curl":
        # cmd form uses caret line-continuations / caret-escaped quotes; bash uses backslash + quotes.
        if "^\n" in text or "^\r\n" in text or '^"' in text:
            return "curl (cmd)"
        return "curl (bash)"
    if "invoke-webrequest" in low or "invoke-restmethod" in low or "new-object system.net.cookie" in low:
        return "curl (PowerShell)"
    if "xmlhttprequest" in low or ".setrequestheader(" in low:
        return "XHR (JS)"
    if re.search(r"\bfetch\(", head):
        return "fetch / JS"
    if re.match(r"^[A-Z]+\s+\S+\s+HTTP/\d", head):  # raw request line: METHOD /path HTTP/1.1
        return "Raw HTTP"
    return ""


def parse_pasted_request(text: str, fmt: str = "auto") -> dict:
    """Dispatch a pasted request to the parser named by ``fmt`` (a PASTE_FORMATS value, or
    ``"auto"`` to sniff). Every parser returns the same dict shape as parse_raw_request."""
    text = (text or "").strip()
    if not text:
        return {}
    low = fmt.lower() if fmt else "auto"
    if "auto" in low or not low:
        low = (detect_paste_format(text) or "raw http").lower()
    if "raw" in low:
        return parse_raw_request(text)
    if "powershell" in low or "pwsh" in low:
        return parse_curl_pwsh(text)
    if "curl" in low:
        return parse_curl(text, cmd="cmd" in low)
    if "xhr" in low:
        return parse_xhr(text)
    if "fetch" in low or "js" in low:
        return parse_fetch(text)
    return parse_raw_request(text)


def load_config_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def read_maybe_file(value: Optional[str]) -> Optional[str]:
    """If value looks like ``@path`` read the file, else return value as-is."""
    if value and value.startswith("@"):
        with open(value[1:], encoding="utf-8") as fh:
            return fh.read().strip()
    return value


def build_config(args: argparse.Namespace) -> Config:
    # Layer precedence (low -> high): raw-request paste, config file, explicit CLI flags.
    raw_cfg: dict = {}
    raw_text = read_maybe_file(getattr(args, "raw_request", None))
    if raw_text:
        raw_cfg = parse_pasted_request(raw_text, getattr(args, "paste_format", "auto"))
        for warn in raw_cfg.get("warnings", []):
            print(f"[warn] {warn}", file=sys.stderr)

    file_cfg_only: dict = {}
    if args.config:
        file_cfg_only = load_config_file(args.config)

    file_cfg = {**raw_cfg, **file_cfg_only}

    def pick(name, default=None):
        cli = getattr(args, name, None)
        if cli is not None:
            return cli
        return file_cfg.get(name, default)

    base_url = pick("base_url")
    if not base_url:
        sys.exit("base_url is required (via --base-url, --raw-request, or config file)")

    cookies = read_maybe_file(pick("cookies", "")) or ""
    headers = {**raw_cfg.get("headers", {}), **file_cfg_only.get("headers", {})}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    methods = [m.strip().lower() for m in (pick("methods", "get")).split(",") if m.strip()]

    proxies = None
    verify = not args.insecure
    if args.burp:
        proxies = {"http": DEFAULT_BURP_PROXY, "https": DEFAULT_BURP_PROXY}
        verify = False
    elif args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    param_filter = DEFAULT_PARAM_FILTER
    pf = pick("param_filter")
    if isinstance(pf, str):
        param_filter = [p.strip().lower() for p in pf.split(",") if p.strip()]
    elif isinstance(pf, list):
        param_filter = [str(p).lower() for p in pf]

    return Config(
        base_url=base_url,
        servlet_path=pick("servlet_path", DEFAULT_SERVLET_PATH),
        cookies=cookies,
        headers=headers,
        forbidden_id=pick("forbidden_id", "") or "",
        control_id=pick("control_id", "") or "",
        spoof_user=pick("spoof_user", "") or "",
        word_threshold=int(pick("word_threshold", DEFAULT_WORD_THRESHOLD)),
        min_length=int(pick("min_length", 1400)),
        param_filter=param_filter,
        methods=methods,
        proxies=proxies,
        verify=verify,
        timeout=float(pick("timeout", 30.0)),
        delay=float(pick("delay", 0.0)),
        run_noauth=not getattr(args, "no_noauth", False),
        run_negative=not getattr(args, "no_negative", False),
        negative_id=pick("negative_id") or Config.negative_id,
    )


def collect_explicit_ids(cfg: Config, args: argparse.Namespace) -> list[str]:
    """Gather resource ids the user supplied explicitly (forbidden id, --target-id, --ids-file)."""
    ids: list[str] = []
    if cfg.forbidden_id:
        ids.append(cfg.forbidden_id)
    ids.extend(getattr(args, "target_id", None) or [])
    ids_file = getattr(args, "ids_file", None)
    if ids_file:
        with open(ids_file, encoding="utf-8") as fh:
            ids.extend(l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#"))
    seen: set[str] = set()
    out: list[str] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Informatica EDC/LDM BOLA (IDOR) sweep tool - AUTHORIZED TESTING ONLY",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--config", help="JSON config file (see config.example.json)")
    p.add_argument("--swagger", help="OpenAPI/Swagger JSON path (default: the bundled official spec)")
    p.add_argument("--raw-request", dest="raw_request", help="Request paste, or @file (extracts url/cookies/headers). Format via --paste-format")
    p.add_argument("--paste-format", dest="paste_format", default="auto",
                   help="Format of --raw-request: auto (default) | 'Raw HTTP' | 'curl (bash)' | "
                        "'curl (cmd)' | 'curl (PowerShell)' | 'fetch / JS' | 'XHR (JS)'")
    p.add_argument("--base-url", dest="base_url", help="Target base URL, e.g. https://host:9085")
    p.add_argument("--servlet-path", dest="servlet_path", help="Proxy servlet path")
    p.add_argument("--cookies", help="Cookie header value, or @file to read from a file")
    p.add_argument("--header", "-H", action="append", help="Extra header 'Key: Value' (repeatable)")
    p.add_argument("--forbidden-id", dest="forbidden_id", help="Resource id you should NOT be able to read")
    p.add_argument("--target-id", dest="target_id", action="append", help="Resource id to test (repeatable)")
    p.add_argument("--ids-file", dest="ids_file", help="File with one resource id per line to test")
    p.add_argument("--enumerate", action="store_true", help="Discover ids via the catalog search endpoint and test them")
    p.add_argument("--max-ids", dest="max_ids", type=int, default=25, help="Max ids to pull when enumerating")
    p.add_argument("--search-query", dest="search_query", default="*", help="Query used for enumeration")
    p.add_argument("--no-noauth", dest="no_noauth", action="store_true", help="Skip the no-auth (C) differential leg")
    p.add_argument("--no-negative", dest="no_negative", action="store_true", help="Skip the negative-control (garbage-id) leg")
    p.add_argument("--negative-id", dest="negative_id", help="Garbage id used for the negative-control probe")
    p.add_argument("--no-session-check", dest="no_session_check", action="store_true", help="Skip the pre-flight session validity check")
    p.add_argument("--control-id", dest="control_id", help="Resource id you DO own (enables differential oracle)")
    p.add_argument("--spoof-user", dest="spoof_user", help="Identity to inject into userId insertion points")
    p.add_argument("--methods", help="Comma-separated HTTP methods to sweep (default get)")
    p.add_argument("--word-threshold", dest="word_threshold", type=int, help="Min words in inner data to call it access")
    p.add_argument("--min-length", dest="min_length", type=int, help="Response length (chars) at/above which it's real content (empty ~1200, content >=1500)")
    p.add_argument(
        "--insertion-mode",
        choices=["auto", "all", "interactive"],
        default="auto",
        help="How to pick injection points per endpoint",
    )
    p.add_argument("--use-userid", action="store_true", help="Include userId slots as insertion points")
    p.add_argument("--param-filter", dest="param_filter", help="Comma-separated param names to treat as insertion points")
    p.add_argument("--burp", action="store_true", help=f"Route through Burp at {DEFAULT_BURP_PROXY} (implies --insecure)")
    p.add_argument("--proxy", help="Custom upstream proxy URL")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    p.add_argument("--delay", type=float, help="Seconds to sleep between requests")
    p.add_argument("--timeout", type=float, help="Per-request timeout (seconds)")
    p.add_argument("--limit", type=int, help="Only sweep the first N matching endpoints")
    p.add_argument("--path-filter", help="Only sweep endpoints whose path contains this substring")
    p.add_argument("--include-multi-id", dest="include_multi_id", action="store_true",
                   help="Include endpoints needing multiple path ids (filled best-effort; usually meaningless)")
    p.add_argument("--all-endpoints", dest="all_endpoints", action="store_true",
                   help="Sweep all id-bearing endpoints (default: only catalog data-object endpoints)")
    p.add_argument("--out", help="Write full report to this .json or .csv file")
    p.add_argument("--dry-run", action="store_true", help="Print the envelopes that WOULD be sent; send nothing")
    p.add_argument(
        "--enable-write-methods",
        action="store_true",
        help="Allow PUT/POST/DELETE/PATCH in the sweep (DANGEROUS on production)",
    )
    p.add_argument("--yes", action="store_true", help="Skip the write-methods confirmation prompt")
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    cfg = build_config(args)

    # Safety gate for write methods.
    requested_writes = sorted(set(cfg.methods) & WRITE_METHODS)
    if requested_writes and not args.dry_run:
        if not args.enable_write_methods:
            sys.exit(
                f"Refusing to run write methods {requested_writes} without --enable-write-methods. "
                "This targets a production system."
            )
        if not args.yes:
            resp = input(
                f"About to send {', '.join(m.upper() for m in requested_writes)} requests that MAY MODIFY DATA. Type 'yes' to continue: "
            ).strip().lower()
            if resp != "yes":
                sys.exit("Aborted.")

    spec = load_swagger(args.swagger)
    endpoints = load_endpoints(spec, cfg)
    endpoints = [ep for ep in endpoints if ep.insertion_points]
    if not getattr(args, "all_endpoints", False):
        before = len(endpoints)
        endpoints = [ep for ep in endpoints if is_data_object_endpoint(ep)]
        print(f"Endpoint scope: {len(endpoints)} catalog data-object endpoints (of {before}); use --all-endpoints for the rest.")
    skipped_results: list[Result] = []
    if not getattr(args, "include_multi_id", False):
        skipped = [ep for ep in endpoints if not ep.scannable(cfg.path_values)]
        endpoints = [ep for ep in endpoints if ep.scannable(cfg.path_values)]
        for ep in skipped:
            needed = ep.uncovered_path_params(cfg.path_values)[1:]
            skipped_results.append(Result(
                endpoint=ep.path, method=ep.method.upper(), insertion="-", resource_id="-",
                verdict=SKIPPED, note="needs values for: " + ", ".join(needed),
                inner_status=None, word_count=0, rest_path=ep.path))
        if skipped:
            print(f"NOT-SCANNED: {len(skipped)} endpoints need real intermediate ids; use --include-multi-id to force.")
    if args.path_filter:
        endpoints = [ep for ep in endpoints if args.path_filter in ep.path]
    if args.limit:
        endpoints = endpoints[: args.limit]

    if not endpoints:
        sys.exit("No endpoints with insertion points matched the current filters.")

    # Assemble the resource ids to test (explicit first, then enumeration if needed).
    session = requests.Session()
    target_ids = collect_explicit_ids(cfg, args)
    want_enumerate = args.enumerate or (not target_ids and not args.dry_run)
    if want_enumerate and not args.dry_run:
        print(f"Enumerating ids via {SEARCH_PATH} (max {args.max_ids}, q={args.search_query!r}) ...")
        found = discover_ids(cfg, session, args.max_ids, args.search_query)
        print(f"  discovered {len(found)} id(s)")
        for rid in found:
            if rid not in target_ids:
                target_ids.append(rid)
    if not target_ids:
        target_ids = ["FORBIDDEN_ID_PLACEHOLDER"] if args.dry_run else []
    if not target_ids:
        sys.exit(
            "No resource ids to test. Provide --forbidden-id/--target-id/--ids-file, "
            "or let enumeration find them (needs a reachable target + valid cookies)."
        )

    mode = "differential" if cfg.control_id else ("no-auth heuristic" if cfg.run_noauth else "word-count heuristic")
    legs = "B" + ("+A" if cfg.control_id else "") + ("+C" if cfg.run_noauth else "") + ("+N" if cfg.run_negative else "")
    print(f"Target      : {cfg.base_url}{cfg.servlet_path}")
    print(f"Swagger     : {'bundled official spec' if not args.swagger else args.swagger}")
    print(f"Endpoints   : {len(endpoints)} (methods={','.join(cfg.methods)})")
    print(f"Resource ids: {len(target_ids)}")
    print(f"Oracle      : {mode}, min-length={cfg.min_length}, word-threshold={cfg.word_threshold}, legs={legs}")
    print(f"Insertion   : {args.insertion_mode}")
    if cfg.proxies:
        print(f"Proxy       : {cfg.proxies.get('https')}")
    if not cfg.control_id and not args.dry_run:
        print("NOTE: no --control-id; supply one for the strongest (differential) signal.")

    # Pre-flight: confirm the cookies still authenticate before a long sweep.
    if not args.dry_run and not getattr(args, "no_session_check", False):
        ok, detail = check_session(cfg, session)
        print(f"Session     : {detail}")
        if not ok:
            print("WARNING: pre-flight session check failed — results may be unreliable. "
                  "Refresh cookies or pass --no-session-check to proceed anyway.")
    print()

    results = run_sweep(cfg, endpoints, target_ids, args.insertion_mode, args.use_userid, args.dry_run)
    results = results + skipped_results  # include NOT-SCANNED entries in the report

    if not args.dry_run:
        print_summary(results)
    if args.out:
        write_report(results, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
