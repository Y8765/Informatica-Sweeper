# Informatica BOLA/IDOR Tool — Session Summary & Handoff

**Purpose:** authorized BOLA/IDOR testing of an Informatica EDC/LDM catalog. All REST calls tunnel
through the proxy servlet `POST /ldmcatalog/ldmProxyServlet` with `{"path": "...", "method": "..."}`
in the body; the response is an envelope `{"status":..,"data":"<escaped json/str>","headers":{...}}`.

Two docs already exist and are current: **`README.md`** (technical) and **`USER_GUIDE.md`** (operator
"which button do I press"). This file is the high-level state + hard-won knowledge.

---

## Files

| File | What it is |
|---|---|
| `bola_gui.py` | The GUI (CustomTkinter dark shell, ttk fallback). Entry point. |
| `bola_sweep.py` | Engine: config, swagger parse, oracle, single- & multi-user sweeps, dump, direct download, reporting. |
| `bola_crawl.py` | Crawl → map → replay engine (response-driven). |
| `bola_report.py` | HTML report + access-matrix builder. |
| `swagger_data.py` | The official OpenAPI spec embedded (gzip+base64) — tool is self-contained. |
| `build.bat` | Compiles `dist\bola.exe` (CLI) + `dist\bola-gui.exe` (GUI) via PyInstaller. |
| `test_oracle.py` | 46 tests (dependency-free runner or pytest). All passing. |
| `config.example.json` | Optional config template. |
| `informatica_swagger.json` | Source spec (only needed to regenerate `swagger_data.py`). |
| `req.txt`, `res.txt`, `sample.txt` | Captured samples used as fixtures / for calibration. |

**Deps:** `requests` (required); `customtkinter` (premium GUI), `openpyxl` (Excel) optional.
**Build/run:** `build.bat` → `dist\bola-gui.exe`, or `python bola_gui.py`. Tests: `python test_oracle.py`.

---

## What the tool does

**Two scan methods** (both feed the same results grid/report):
- **Swagger sweep** (`▶`): tests each target id against a fixed endpoint list from the spec.
- **Crawl & map** (`🕷`): fetches each object's detail as the first user (the "mapper"), follows the
  REAL hrefs the responses return (no guessing), replays those URLs as the *other* users. Mapper is
  skipped on replay; single-user = inventory only.
- **★ AIO**: runs both, in full, over all endpoints.

**Multi-user model:** add N users (paste each one's request → auto-parses URL/cookies/headers). Each row
has a **format** dropdown — Raw HTTP (Burp) plus browser copies: curl (bash/cmd/PowerShell), fetch/JS, XHR
(for proxy-less environments). One dispatcher `bs.parse_pasted_request(text, fmt)` routes to per-format
parsers, all returning the same dict shape; `fmt="auto"` sniffs. fetch/XHR pastes usually lack the session
cookie (browser supplies it) → a ⚠ warning fires; prefer Copy-as-cURL. CLI: `--paste-format`.
Optionally declare each user's **owns ids** (authoritative legit scope). Verdicts:
- **VULNERABLE** — user read a resource outside its (declared) scope, or one it couldn't even enumerate.
- **OWNED** — read a resource in its declared scope (expected).
- **ACCESSIBLE?** — readable but ownership undeclared (review).
- **ENUM-LEAK** — object detail denied but search exposed it (info disclosure). Only fires on the
  object-detail endpoint and only on a clean denial (403 / empty-200), never on 404/400/5xx.
- **DENIED** / **INCONCLUSIVE** / **NOT-SCANNED** / **ERROR**.

**Enumeration:** paginated by server `totalCount`; multi-select object types (Resources/Tables/Columns/
Data Objects/Data Elements/Views/Schemas — none = all); "◀ from discovered" pushes selections into
owns/extra boxes; Clear resets discovery. Discovery tree = Scanner → Resource → Asset with Asset type
+ Resource type columns.

**Other actions:** Dump data (full object content per user → NDJSON), Download files (attachments),
Export (HTML / Excel / CSV / JSON), Refresh cookies (re-stamp stored curls with new session),
Pause/Resume, Stop, Leaks-only filter, Live request log (decoded, readable).

**Mid-scan re-auth:** if a user's session expires (~5 auth failures), the scan BLOCKS and pops a dialog
to paste a fresh request; updates that user's cookies live and resumes.

**Reports:** Excel has 3 sheets — **Findings** (only findings, with exposed data + curl/raw), **All
results**, **access-matrix** (object × user, color-coded "who can reach what" for admins). HTML mirrors
this. Every result stores the full untruncated response + a replay curl + raw HTTP request.

---

## Hard-won knowledge (from real responses — don't re-learn these)

- **Object id format:** full ids look like `RESOURCE://path/to/asset` (resources are doubled `X://X`).
  Use the FULL id verbatim; the tool does NOT re-double an id that already contains `://`. A bare id
  (no `://`) typed manually gets doubled as a convenience.
- **DO NOT collapse ids on `://`** — the left half is the resource prefix shared by all assets under it;
  splitting collapses hundreds of assets into their resource. (This was a real bug, fixed.)
- **Search vs objects response shapes differ:** `/data/search` items use `values:[{id,value}]`;
  `/data/objects` items use `facts:[{name,value}]`. `_facts_map` handles BOTH. (Real bug, fixed.)
- **Oracle:** `totalCount` is authoritative — `>=1` = access, `0` = empty/denied. Length/word-count are
  fallbacks only. Denials seen live: enveloped inner 404 (empty), enveloped inner 403 (HTML in `data`),
  raw outer 401 (HTML login page). All handled.
- **Endpoint id-spaces:** only the `/catalog/data/objects…` family (~24 endpoints) accepts a real
  catalog object id. Model/config `{id}` endpoints (e.g. `/models/lineageFilter/{id}`) are a DIFFERENT
  id space → 404 noise. Default endpoint scope = "Object API endpoints".
- **⚠ Binary downloads are corrupted by the proxy servlet.** It lossily UTF-8-decodes binary → every
  non-UTF-8 byte becomes U+FFFD (seen as `EF BF BD`). So zips/PDFs through `ldmProxyServlet` are
  unrecoverable; **text files (json/csv/xml) come through fine**.
  - **Fix = DIRECT download:** the real API base is **`/access`** (from the spec `servers` url, e.g.
    `https://host:9085/access`). Hit download endpoints DIRECTLY there (bypassing the servlet) for raw
    bytes. `bola_sweep.direct_get()` does this; "Download files…" tries DIRECT first, proxy fallback.
  - **Raw-file endpoints:** `/1/catalog/models/downloadModels` (octet-stream; matches `sample.txt`),
    `/1/catalog/data/downloadResources|downloadXdocs`, `/1/catalog/filestore/downloads`,
    `/2/catalog/jobs/{id}/logs/zip`, `/2/catalog/jobs/*Exports/{id}/result` (excel/csv),
    `/2/catalog/data/tdeExports/{id}/downloads`.
- **Infatoken:** kept on every normal request; only stripped in the intentional **no-auth leg**
  (`strip_auth=True`, via `AUTH_HEADER_KEYS`). Full pasted header set is forwarded (requests recomputes
  Content-Length, so a stale one is harmless).
- **Note:** during this session the target server was taken down for patching — the 401/"discovery
  broke" symptoms were external, not tool bugs.

---

## Open items / possible next steps

- **Verify DIRECT download works** against the live `/access` base (server was down at session end). If
  it returns HTML/redirect, the base path or auth for direct access may need adjustment.
- **Crawl link types:** currently follows object hrefs + additionalFacts. Could extend to follow
  relationships / comments / reviews responses if you send real samples of those.
- **`check_session` is strict** (flags outer≥400 / inner None / inner≥400). Offered to loosen it to
  only flag clear login/HTML 401s — not done. Do if patched-server flakiness causes false "invalid"
  warnings.
- **No-auth leg** shows `[no-auth] -> 401` lines in the live log (expected). Could hide them; untick
  "No-auth leg" to disable.
- Everything verified: **46/46 tests pass**, GUI renders, `dist\bola-gui.exe` + `dist\bola.exe` build
  and launch clean.

---

## Recommended first run (once server is back)

1. Add **admin** first (it's the crawl mapper), then **low**; paste each raw request, Parse.
2. Enumerate types = **Resources**; Test against = **Object API endpoints**.
3. Live request log + Dry run on → **▶ Swagger sweep** → confirm requests look right in the log.
4. Dry run off → **▶ Swagger sweep** (broad) and/or **🕷 Crawl & map** (precise).
5. **Leaks only** to review VULNERABLE/ENUM-LEAK; double-click a row for Request/Response tabs.
6. **Export → .xlsx** → hand the `access-matrix` + `Findings` sheets to admins.
7. **Download files…** for attachments (direct-download for intact binaries).
