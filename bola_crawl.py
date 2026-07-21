#!/usr/bin/env python3
"""
Crawl → map → replay engine for the Informatica BOLA tool.

AUTHORIZED SECURITY TESTING ONLY.

Instead of synthesizing requests from the swagger, this drives the API the way the catalog
itself does: it fetches each object's detail as a "mapper" user, extracts the **real** links
the response hands back (object hrefs, additionalFacts/providerId URLs, related objects), and
builds a map of concrete GET URLs. Those URLs are then **replayed as every user** — so a low
user that can read a URL the mapper discovered is a definitive access finding.

Nothing is guessed: secondary ids (providerId, etc.) and encodings come straight from the
catalog's own responses. Works as any user (the mapper can be low or admin).
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

import bola_sweep as bs

# Only follow/keep links into the catalog data-object surface (not model/attribute metadata).
_DATA_URL_MARKERS = ("/catalog/data/objects", "/catalog/data/relationships",
                     "/catalog/data/objectsChildSummary")


@dataclass
class CrawledUrl:
    url: str          # concrete GET rest-path (e.g. /1/catalog/data/objects/<enc>/additionalFacts/x)
    kind: str         # object-detail | href
    object_id: str    # the base object this URL belongs to
    label: str = ""   # object name, if known


def _is_data_url(url: str) -> bool:
    return url.startswith("/") and any(m in url for m in _DATA_URL_MARKERS)


def _walk_hrefs(node, out: set) -> None:
    """Collect every `href` string (rooted path) anywhere in a parsed response."""
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "href" and isinstance(v, str) and v.startswith("/"):
                out.add(v)
            else:
                _walk_hrefs(v, out)
    elif isinstance(node, list):
        for x in node:
            _walk_hrefs(x, out)


def crawl_map(cfg, session, seed_ids, mapper, max_objects: int = 300,
              object_path: str = bs.DEFAULT_OBJECT_PATH, data_only: bool = True,
              on_progress=None, stop_check=None, pause_check=None) -> list:
    """Crawl as `mapper`: fetch each seed object's detail and follow the hrefs it returns.

    Returns a de-duplicated list of CrawledUrl (concrete GET URLs the catalog exposed to
    the mapper). One level of link-following per object. When `data_only` is True (default)
    only object-data hrefs are followed; set it False to follow EVERY href (e.g. the
    /models/attributes links) — the crawl equivalent of "All API endpoints".
    """
    urls: dict = {}

    def add(u: str, kind: str, oid: str, label: str = "") -> None:
        keep = _is_data_url(u) if data_only else u.startswith("/")
        if keep and u not in urls:
            urls[u] = CrawledUrl(url=u, kind=kind, object_id=oid, label=label)

    for i, oid in enumerate(seed_ids):
        if stop_check and stop_check():
            break
        if i >= max_objects:
            break
        bs._wait_if_paused(pause_check, stop_check)
        payload = bs.build_payload("id", cfg, oid)
        detail = f"{object_path}?id={urllib.parse.quote(payload, safe='')}"
        add(detail, "object-detail", oid)
        data = bs.fetch_inner(cfg, session, detail, user=mapper)
        label = ""
        if isinstance(data, dict):
            items = data.get("items") or []
            if items and isinstance(items[0], dict):
                label = bs._facts_map(items[0]).get("core.name", "") or ""
            found: set = set()
            _walk_hrefs(data, found)
            for h in found:
                add(h, "href", oid, label)
        if on_progress:
            on_progress(oid, len(urls))
        bs._sleep(cfg)
    return list(urls.values())


def replay_urls(cfg, session, crawled, users, mapper=None, on_result=None,
                stop_check=None, pause_check=None, on_reauth=None) -> list:
    """Replay each crawled URL as every user; classify read access (response-driven oracle).

    The `mapper` (the user that built the map) is skipped when there are other users to test —
    it already proved it can reach these URLs during the crawl, so re-testing it is duplication.
    With only the mapper present, it is kept (the result is an inventory of what it can reach).
    `on_reauth(user)` (optional) is called and BLOCKS when a user's session looks expired.
    """
    replay_users = [u for u in users if u is not mapper] or list(users)
    authfail: dict = {}
    results: list = []
    for c in crawled:
        if stop_check and stop_check():
            break
        for u in replay_users:
            bs._wait_if_paused(pause_check, stop_check)
            if stop_check and stop_check():
                return results
            probe = bs.send(cfg, session, c.url, "GET", user=u)
            if bs.looks_like_auth_failure(probe):
                authfail[u.label] = authfail.get(u.label, 0) + 1
                if authfail[u.label] >= bs.SESSION_FAIL_THRESHOLD and on_reauth and not (stop_check and stop_check()):
                    on_reauth(u)                       # BLOCKS for fresh creds
                    authfail[u.label] = 0
                    probe = bs.send(cfg, session, c.url, "GET", user=u)  # retry with new creds
            else:
                authfail[u.label] = 0
            access = probe.is_access(cfg.word_threshold, cfg.min_length)
            declared = u.owned_declared
            owned = (c.object_id in u.owned_ids) if declared else None
            ln = f"len={probe.resp_len}, inner={probe.inner_status}"
            if not probe.ok:
                verdict, note = bs.ERROR, probe.error or "request failed"
            elif not access:
                verdict, note = bs.DENIED, f"no access ({ln})"
            elif declared and owned:
                verdict, note = bs.OWNED, f"{u.label} owns this (declared scope, {ln})"
            elif declared:
                verdict, note = bs.VULNERABLE, f"{u.label} read a crawled URL OUTSIDE its declared scope ({ln})"
            else:
                verdict, note = bs.ACCESSIBLE, f"{u.label} can read this crawled URL; ownership undeclared ({ln})"
            res = bs.Result(
                endpoint=c.url.split("?")[0], method="GET", insertion=c.kind,
                resource_id=c.object_id, verdict=verdict, note=note,
                inner_status=probe.inner_status, word_count=probe.word_count, rest_path=c.url,
                user=u.label, owned=owned, resp_len=probe.resp_len,
                data_summary=bs.summarize_facts(probe.data_str)
                if verdict in (bs.VULNERABLE, bs.PUBLIC, bs.ACCESSIBLE, bs.OWNED) else "",
                curl=bs.build_curl(cfg, c.url, "GET", user=u),
                raw_request=bs.build_raw_request(cfg, c.url, "GET", user=u),
                response=(probe.raw_full or probe.data_str),
                is_file=probe.is_file, filename=probe.filename, file_ext=probe.file_ext,
            )
            results.append(res)
            bs._print_row(res)
            if on_result:
                on_result(res)
            bs._sleep(cfg)
    return results
