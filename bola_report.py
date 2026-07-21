#!/usr/bin/env python3
"""
Human-readable HTML report for the Informatica BOLA sweep.

Turns a list of bola_sweep.Result into a self-contained .html file: a summary, a
findings-first section with the actual data each leak exposed, and a copy-pasteable
curl + raw HTTP request to replay every finding in Burp.
"""

from __future__ import annotations

import html
import json
from typing import Iterable

# Verdict -> (label color, background) for the dark report theme.
VERDICT_STYLE = {
    "VULNERABLE": ("#ffffff", "#c0392b"),
    "PUBLIC(no-auth)": ("#ffffff", "#8e44ad"),
    "ACCESSIBLE?": ("#ffffff", "#b0568a"),
    "ENUM-LEAK": ("#3a2f05", "#e0932f"),
    "OWNED": ("#08313a", "#4dd0e1"),
    "DENIED": ("#0b3d1e", "#5fd67a"),
    "INCONCLUSIVE": ("#3a2f05", "#f0b429"),
    "NOT-SCANNED": ("#ffffff", "#3a6ea5"),
    "ERROR": ("#ffffff", "#7f8c8d"),
    "DRY-RUN": ("#ffffff", "#2471a3"),
}
FINDING_VERDICTS = ("VULNERABLE", "PUBLIC(no-auth)", "ACCESSIBLE?", "ENUM-LEAK")


def _esc(s) -> str:
    return html.escape("" if s is None else str(s))


def _badge(verdict: str) -> str:
    fg, bg = VERDICT_STYLE.get(verdict, ("#fff", "#555"))
    return f'<span class="badge" style="color:{fg};background:{bg}">{_esc(verdict)}</span>'


def _counts(results) -> dict:
    c: dict = {}
    for r in results:
        c[r.verdict] = c.get(r.verdict, 0) + 1
    return c


# Cell precedence in the access matrix: worst/most-interesting access wins.
_MATRIX_RANK = {
    "VULNERABLE": 6, "PUBLIC(no-auth)": 5, "ACCESSIBLE?": 4,
    "ENUM-LEAK": 3, "OWNED": 2, "DENIED": 1, "INCONCLUSIVE": 1, "ERROR": 0, "NOT-SCANNED": 0,
}


def build_matrix(results):
    """Pivot results into object (rows) x user (columns) -> access verdict.

    Gives admins a 'who can reach what' view: OWNED = legitimate, VULNERABLE/ACCESSIBLE?/
    ENUM-LEAK = review/block, DENIED = correctly blocked.
    """
    users = sorted({r.user for r in results if r.user})
    rows: dict = {}  # resource_id -> {"name":.., "type":.., "cells": {user: verdict}}
    for r in results:
        if r.verdict in ("NOT-SCANNED", "DRY-RUN") or not r.resource_id or r.resource_id == "-":
            continue
        row = rows.setdefault(r.resource_id, {"name": "", "type": "", "cells": {}})
        if getattr(r, "data_summary", ""):
            row["name"] = row["name"] or r.data_summary[:60]
        cur = row["cells"].get(r.user)
        if cur is None or _MATRIX_RANK.get(r.verdict, 0) > _MATRIX_RANK.get(cur, 0):
            row["cells"][r.user] = r.verdict
    return users, rows


def _matrix_html(results) -> str:
    users, rows = build_matrix(results)
    if not users or not rows:
        return ""
    head = "".join(f"<th>{_esc(u)}</th>" for u in users)
    body = []
    for rid, row in sorted(rows.items()):
        cells = "".join(
            f"<td>{_badge(row['cells'][u]) if u in row['cells'] else '<span class=dim>–</span>'}</td>"
            for u in users
        )
        body.append(f"<tr><td class='mono'>{_esc(rid)}</td>{cells}</tr>")
    return f"""
  <h2>Access matrix — who can reach what</h2>
  <p class="hint">OWNED = legitimate · VULNERABLE / ACCESSIBLE? / ENUM-LEAK = review &amp; block · DENIED = correctly blocked.</p>
  <div class="rtable"><table>
    <thead><tr><th>Resource id</th>{head}</tr></thead>
    <tbody>{''.join(body)}</tbody>
  </table></div>"""


def generate_html(results: list, meta: dict | None = None) -> str:
    meta = meta or {}
    counts = _counts(results)
    findings = [r for r in results if r.verdict in FINDING_VERDICTS]
    total = len(results)

    # Summary cards
    cards = []
    for v in ("VULNERABLE", "PUBLIC(no-auth)", "ACCESSIBLE?", "ENUM-LEAK", "OWNED", "DENIED", "INCONCLUSIVE", "NOT-SCANNED", "ERROR"):
        if counts.get(v):
            fg, bg = VERDICT_STYLE.get(v, ("#fff", "#555"))
            cards.append(
                f'<div class="card"><div class="dot" style="background:{bg}"></div>'
                f'<div class="num">{counts[v]}</div><div class="lbl">{_esc(v)}</div></div>'
            )
    cards_html = "".join(cards)

    meta_rows = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>"
        for k, v in meta.items()
    )

    # Findings section
    finding_blocks = []
    for i, r in enumerate(findings):
        who = f"<b>{_esc(r.user)}</b> &rarr; " if getattr(r, "user", "") else ""
        owned = ""
        if getattr(r, "owned", None) is False:
            owned = '<span class="tag">outside user\'s own set</span>'
        finding_blocks.append(f"""
        <div class="finding">
          <div class="fhead">
            {_badge(r.verdict)}
            <span class="fep">{who}{_esc(r.method)} {_esc(r.endpoint)}</span>
            {owned}
          </div>
          <table class="kv">
            <tr><th>Resource id</th><td class="mono">{_esc(r.resource_id)}</td></tr>
            <tr><th>Insertion</th><td>{_esc(r.insertion)}</td></tr>
            <tr><th>Actual path sent</th><td class="mono">{_esc(getattr(r, 'rest_path', ''))}</td></tr>
            <tr><th>Inner status / length</th><td>{_esc(r.inner_status)} &middot; {_esc(getattr(r, 'resp_len', ''))} chars</td></tr>
            <tr><th>Evidence</th><td>{_esc(getattr(r, 'data_summary', '') or r.note)}</td></tr>
            <tr><th>Reason</th><td>{_esc(r.note)}</td></tr>
          </table>
          <div class="repro">
            <button class="copy" data-target="curl-{i}">Copy curl</button>
            <button class="toggle" data-target="raw-{i}">Show raw request</button>
            <pre id="curl-{i}" class="mono block">{_esc(getattr(r, 'curl', ''))}</pre>
            <pre id="raw-{i}" class="mono block hidden">{_esc(getattr(r, 'raw_request', ''))}</pre>
          </div>
        </div>""")
    findings_html = "".join(finding_blocks) or '<p class="empty">No access leaks found. 🎉</p>'

    # Full results table
    rows = []
    for r in results:
        rows.append(
            "<tr>"
            f"<td>{_badge(r.verdict)}</td>"
            f"<td>{_esc(getattr(r, 'user', ''))}</td>"
            f"<td>{_esc(r.method)}</td>"
            f"<td>{_esc(r.inner_status)}</td>"
            f"<td>{_esc(getattr(r, 'resp_len', ''))}</td>"
            f"<td class='mono'>{_esc(r.endpoint)}</td>"
            f"<td>{_esc(r.insertion)}</td>"
            f"<td class='mono'>{_esc(r.resource_id)}</td>"
            "</tr>"
        )
    rows_html = "".join(rows)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BOLA Sweep Report</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:14px/1.5 "Segoe UI",system-ui,sans-serif; background:#1b1b1f; color:#e6e6ea; }}
  header {{ padding:20px 28px; background:#232329; border-bottom:1px solid #33333b; }}
  h1 {{ margin:0 0 4px; font-size:20px; }}
  .sub {{ color:#9aa0a6; }}
  .wrap {{ padding:20px 28px; max-width:1200px; margin:0 auto; }}
  h2 {{ font-size:16px; border-left:3px solid #4aa3ff; padding-left:8px; margin:26px 0 12px; }}
  .cards {{ display:flex; flex-wrap:wrap; gap:12px; }}
  .card {{ background:#232329; border:1px solid #33333b; border-radius:8px; padding:12px 16px; min-width:120px; }}
  .card .num {{ font-size:26px; font-weight:700; }}
  .card .lbl {{ color:#9aa0a6; font-size:12px; }}
  .card .dot {{ width:10px; height:10px; border-radius:50%; display:inline-block; margin-bottom:6px; }}
  table {{ border-collapse:collapse; width:100%; }}
  .meta th, .kv th {{ text-align:left; color:#9aa0a6; font-weight:600; padding:3px 12px 3px 0; white-space:nowrap; vertical-align:top; }}
  .badge {{ padding:2px 8px; border-radius:10px; font-size:12px; font-weight:700; white-space:nowrap; }}
  .finding {{ background:#232329; border:1px solid #33333b; border-left:4px solid #c0392b; border-radius:8px; padding:14px 16px; margin-bottom:14px; }}
  .fhead {{ display:flex; align-items:center; gap:10px; margin-bottom:8px; flex-wrap:wrap; }}
  .fep {{ font-weight:600; }}
  .tag {{ font-size:11px; color:#ffbcbc; background:#3a1f1f; border-radius:8px; padding:1px 8px; }}
  .kv td {{ padding:3px 0; }}
  .mono {{ font-family:Consolas,"Courier New",monospace; font-size:12px; word-break:break-all; }}
  .block {{ background:#141418; border:1px solid #33333b; border-radius:6px; padding:10px; overflow:auto; white-space:pre-wrap; margin:8px 0 0; }}
  .hidden {{ display:none; }}
  button {{ background:#2f6fb0; color:#fff; border:0; border-radius:6px; padding:5px 10px; font-size:12px; cursor:pointer; margin:8px 8px 0 0; }}
  button.toggle {{ background:#3a3a44; }}
  .rtable {{ overflow-x:auto; }}
  .rtable table {{ font-size:12px; }}
  .rtable td {{ border-top:1px solid #2a2a32; padding:5px 8px; }}
  .rtable th {{ position:sticky; top:0; background:#232329; text-align:left; padding:6px 8px; }}
  .empty {{ color:#5fd67a; font-size:16px; }}
  .dim {{ color:#5a5a66; }}
  .hint {{ color:#9aa0a6; margin:4px 0 10px; }}
  .filter {{ margin:8px 0; }}
  input[type=text] {{ background:#141418; border:1px solid #33333b; color:#e6e6ea; border-radius:6px; padding:6px 8px; width:280px; }}
</style></head>
<body>
<header>
  <h1>Informatica BOLA / IDOR Sweep — Report</h1>
  <div class="sub">Authorized testing only · {total} requests tested · {len(findings)} potential leak(s)</div>
</header>
<div class="wrap">
  <div class="cards">{cards_html}</div>

  <h2>Run details</h2>
  <table class="meta">{meta_rows}</table>

  <h2>Findings ({len(findings)})</h2>
  {findings_html}
  {_matrix_html(results)}

  <h2>All results ({total})</h2>
  <div class="filter"><input type="text" id="q" placeholder="filter table (endpoint, id, verdict, user)…"></div>
  <div class="rtable"><table id="all">
    <thead><tr><th>Verdict</th><th>User</th><th>Method</th><th>Inner</th><th>Len</th><th>Endpoint</th><th>Insertion</th><th>Resource id</th></tr></thead>
    <tbody>{rows_html}</tbody>
  </table></div>
</div>
<script>
  document.querySelectorAll('button.copy').forEach(b => b.onclick = () => {{
    const el = document.getElementById(b.dataset.target);
    navigator.clipboard.writeText(el.textContent).then(() => {{ b.textContent='Copied!'; setTimeout(()=>b.textContent='Copy curl',1200); }});
  }});
  document.querySelectorAll('button.toggle').forEach(b => b.onclick = () => {{
    const el = document.getElementById(b.dataset.target);
    el.classList.toggle('hidden');
    b.textContent = el.classList.contains('hidden') ? 'Show raw request' : 'Hide raw request';
  }});
  const q = document.getElementById('q');
  if (q) q.oninput = () => {{
    const t = q.value.toLowerCase();
    document.querySelectorAll('#all tbody tr').forEach(tr => {{
      tr.style.display = tr.textContent.toLowerCase().includes(t) ? '' : 'none';
    }});
  }};
</script>
</body></html>"""


def write_html_report(results: list, out_path: str, meta: dict | None = None) -> None:
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(generate_html(results, meta))
