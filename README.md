# Informatica EDC/LDM BOLA (IDOR) Sweep Tool

> **Authorized security testing only.** This tool sends requests to a target you must have
> written permission to test. Point it at production only with that permission and with the
> read-only defaults intact.

Given a **forbidden resource id** (an object you should *not* be able to read), the tool
sweeps the catalog REST API and reports which endpoints actually leak access to that object —
a Broken Object Level Authorization (BOLA / IDOR) check across the whole API surface instead of
one endpoint at a time in Burp.

The **official OpenAPI spec is embedded** (`swagger_data.py`), so you don't supply a swagger file.
Give it a URL + cookies and it runs on its own: if you don't name any resource ids it
**auto-enumerates** them from the catalog search endpoint and tests each. Supply a forbidden id
and/or a control id when you have them for a stronger signal — it degrades gracefully to whatever
you provide.

Two front-ends, same engine:
- **`bola_gui.py`** — desktop GUI (CustomTkinter, ttk fallback). Add users, Discover, Run.
- **`bola_sweep.py`** — CLI, for scripting / Burp pipelines.

## Multi-user mode (the definitive IDOR test)

Add two or more users (paste each one's raw request). The tool tests every resource against every
user. **Ownership ground-truth matters:** enumeration is *not* treated as proof of ownership —
a leaky search could list resources a user shouldn't have, which would otherwise mask the very leak
you're hunting.

**Declare each user's owned ids** (the "owns ids" box — the resources that user is *supposed* to
access, usually a short list). Then:

- **OWNED** — access to a resource in the user's **declared** scope (expected baseline).
- **VULNERABLE** — access to anything **outside** the declared scope (definitive IDOR).
- **DENIED** — no access.

If you **don't** declare ownership, the tool refuses to guess:

- **VULNERABLE** — the user read a resource it **couldn't even enumerate** (search hid it, detail
  leaked it — a strong signal).
- **ACCESSIBLE?** — the user can read it but ownership is undeclared; surfaced for review, **never**
  silently filed as OWNED. Declare the user's owned ids to turn these into a definitive verdict.

This is the "admin has 14 resources, low user has 1 — can the low user reach the other 13?" test:
enumerate the universe with admin, declare low's one real resource, run → any other access = leak.

## Discovery

**Discover** enumerates the catalog (paginated — pulls *all* resources, not one page) and shows a
**scanner → resource/asset** tree. Select single, multiple, or all to test; leave nothing selected to
test everything found. Per-user enumeration also builds each user's "owned" set for the verdicts above.

## Oracle / signals

- **Response length** is the primary signal (empty responses cluster low, real content is larger;
  default cutoff `min_length=1400`). Word count is the fallback.
- **Negative control** (a garbage id) filters endpoints that echo boilerplate for any id.
- **No-auth leg** catches resources readable with no login (PUBLIC).
- **HTML/redirect responses** are treated as *blocked/expired session* (401/403), not data; a
  pre-flight + mid-run watchdog warns when a session dies so late DENIEDs aren't false.

## Report

Export a **self-contained HTML report**: summary, findings-first, each finding showing the actual
data it exposed (parsed key facts) plus a **copy-paste curl and raw HTTP request** to replay in Burp.
JSON and CSV export are also available.

## How it works

Every REST call tunnels through the LDM proxy servlet, exactly like the UI:

```
POST /ldmcatalog/ldmProxyServlet
Content-Type: application/json

{"path":"/1/catalog/data/objects?id=<RESOURCE>","method":"GET"}
```

The response is an envelope:

```json
{"status":200,"data":"<escaped-json-string>","headers":{...}}
```

- **Access** → inner `status` 200 and `data` holds real content (`items`/`facts`, many words).
- **Denial** → non-200 inner status, empty `data`, `"totalCount":0`, or an error marker.

### The oracle

`data` word count (≥ `--word-threshold`, default 30) decides "did I get content". When you also
supply a `--control-id` (a resource you *do* own), each insertion point is tested with a
**3-request differential** so a friendly-but-empty 200 can't false-positive:

| Leg | Request | Expectation |
|-----|---------|-------------|
| A | control/owned id | ACCESS — defines what access looks like |
| B | forbidden id | the actual test |
| C | forbidden id, **auth stripped** | DENY — defines what denial looks like |

Verdicts for leg B:

- **VULNERABLE** — B looks like A (has data) and unlike C (no-auth denied). Real BOLA.
- **PUBLIC(no-auth)** — B *and* C both return data → broken auth, but not object-scoped.
- **DENIED** — B empty/denied.
- **INCONCLUSIVE** — control (A) itself failed, so no baseline to compare against.
- **ERROR** — transport failure.

Without `--control-id` the tool degrades to a word-count-only heuristic (prints a warning; more
false positives).

**Negative control (N):** per endpoint the tool also fires a **garbage id**. If a nonexistent id
already returns "access-looking" content of similar size, that endpoint hands back boilerplate for
*any* id — so the result is marked **INCONCLUSIVE** instead of a false VULNERABLE. Real access must
carry meaningfully more content than the garbage baseline. Disable with `--no-negative`.

**Session-expiry detection:** a pre-flight check confirms your cookies still authenticate before a
long sweep, and a watchdog warns if a streak of authenticated requests start coming back as
login-redirects/HTML — i.e. your session died mid-run and later DENIEDs are false. This is distinct
from a normal per-object denial (a valid JSON envelope with a 403/empty body).

### Injection ("insertion points", like Burp Intruder)

Candidate slots are auto-detected from the swagger: query params named
`id,resourceName,name,objectId,userId,q` (configurable via `--param-filter`) and `{path}` templates.
Encoding is smart per location:

- **Query** slots → doubled `<id>://<id>` form, percent-encoded (matches the real UI request).
- **Path** `{id}` templates → Informatica tilde encoding (`$`→`~24~`, `.`→`~2e~`, `:`→`~3a~`, `/`→`~2f~`).
- **userId** slots → your `--spoof-user` identity (only when `--use-userid` is set).

`--insertion-mode`:
- `auto` (default) — one best slot per endpoint.
- `all` — every candidate slot separately (sniper).
- `interactive` — it lists slots per endpoint and you pick.

## Safety

- **GET only by default.** PUT/POST/DELETE/PATCH are implemented but refused unless you pass
  `--enable-write-methods`, and then only after a typed `yes` confirmation (skip with `--yes`).
- `--dry-run` prints the exact envelopes it *would* send and sends nothing — use it first.
- `--delay` throttles between requests.

## Setup

```
pip install requests            # required
pip install customtkinter       # optional: premium dark GUI
```

`requests` is the only hard dependency; Tkinter ships with Python and the swagger is embedded.
The GUI uses **CustomTkinter** for a premium dark look when it is installed, and **automatically
falls back to a plain-ttk window** when it is not — so it still runs on a locked-down box.

## GUI (easiest)

```powershell
python bola_gui.py
```

Dark CustomTkinter shell with a fast, zebra-striped results grid (colored by verdict). The window
is resizable with a **draggable split**: a scrollable **Setup** panel on top, and a **Results + Log**
panel below that grows with the window. Drag the divider (or resize the window) to make the log
bigger. A **Leaks only** toggle hides everything except VULNERABLE/PUBLIC; double-click a row for
full request/response detail; the **Log** pane shows the session check, enumeration, and warnings.

1. Paste a raw request copied from Burp and click **Parse raw request** (fills URL + cookies +
   headers), *or* just type the **Base URL** and **Cookie header**.
2. Optionally paste **resource ids to test** (one per line) and a **control id**. Leave ids empty
   to auto-enumerate.
3. Tick **Route via Burp** if you want the requests to appear in Burp; **Dry run** to preview only.
4. **Run**. Results stream into the table, colored by verdict; double-click a row for the full
   request/response detail; **Export report** to JSON/CSV.

## CLI

Zero-config autorun — URL + cookies, everything else automatic (bundled swagger, enumerate ids):

```powershell
python bola_sweep.py --base-url https://host:9085 --cookies "@cookies.txt" --insecure --out report.json
```

From a raw request paste (extracts URL, cookies, Infatoken, headers):

```powershell
python bola_sweep.py --raw-request "@burp_request.txt" --enumerate --burp --out report.json
```

Strongest signal — you name the forbidden id and a control id you own:

```powershell
python bola_sweep.py --base-url https://host:9085 --cookies "@cookies.txt" `
  --forbidden-id "resource_2$$OracleScanner$$SYS.SYS" `
  --control-id  "resource_1$$OracleScanner$$SYS.SYS" `
  --insertion-mode all --insecure --out report.json
```

Dry run first to see exactly what would be sent:

```powershell
python bola_sweep.py --base-url https://host:9085 --forbidden-id "res$$x.y" --dry-run
```

### Key flags

| Flag | Purpose |
|------|---------|
| `--swagger` | OpenAPI/Swagger JSON (optional; defaults to the embedded official spec) |
| `--raw-request` | raw HTTP request paste or `@file`; extracts url/cookies/headers |
| `--config` | JSON config file (base_url, cookies, headers, ids, …) |
| `--forbidden-id` / `--target-id` / `--ids-file` | resource id(s) to test |
| `--enumerate` / `--max-ids` / `--search-query` | discover ids via catalog search |
| `--control-id` | resource id you DO own → enables the differential oracle |
| `--no-noauth` | skip the no-auth (C) leg (on by default) |
| `--no-negative` / `--negative-id` | skip / customize the garbage-id negative-control leg |
| `--no-session-check` | skip the pre-flight session-validity check |
| `--burp` | route via `http://127.0.0.1:8080`, TLS off |
| `--proxy` / `--insecure` | custom upstream proxy / disable TLS verify |
| `--methods` | comma list; default `get` |
| `--insertion-mode` | `auto` \| `all` \| `interactive` |
| `--use-userid` / `--spoof-user` | treat `userId` as an insertion point / value to inject |
| `--word-threshold` | min words in `data` to count as access (default 30) |
| `--path-filter` / `--limit` | restrict which endpoints run |
| `--out` | write full evidence to `.json` or `.csv` |
| `--dry-run` | print envelopes only, send nothing |

## Compile to a standalone binary

Ship it as an `.exe` (no Python needed on the target box) with the included build script:

```bat
build.bat                 :: builds dist\bola.exe (CLI) + dist\bola-gui.exe (GUI)
```

`build.bat` installs PyInstaller automatically if it is missing.
Options: `--gui-only`, `--cli-only`, `--onedir` (faster start, a folder), `--clean`, `--icon app.ico`.

The official swagger lives in `swagger_data.py` as plain Python, so it is compiled **into** the
binary — the `.exe` is fully self-contained. CustomTkinter's theme assets are bundled into
`bola-gui.exe` automatically. Result: `bola.exe` ~15 MB, `bola-gui.exe` ~18 MB. They are unsigned,
so Windows SmartScreen / AV may warn on first run.

```powershell
.\dist\bola.exe --base-url https://host:9085 --cookies "@cookies.txt" --insecure --out report.json
.\dist\bola-gui.exe
```

## Shell gotcha

- The resource id contains `$$`. In **PowerShell** and **cmd**, wrap ids in single quotes:
  `'resource_2$$Scanner$$SYS.SYS'`.
- Avoid **Git Bash / MSYS** for flags whose value starts with `/` (e.g. `--path-filter /1/...`):
  MSYS rewrites leading-slash arguments into Windows paths and the filter silently matches nothing.
  Use PowerShell, or prefix with `//`.

## Tests

```
python test_oracle.py           # dependency-free runner
python -m pytest test_oracle.py -q
```

The tests use the captured `req.txt` / `res.txt` as fixtures and assert that the generated
`id` envelope matches the real request byte-for-byte and that `res.txt` classifies as ACCESS.

## Files

- `bola_gui.py` — desktop GUI (multi-user, discovery, pause/resume, tooltips, HTML export)
- `bola_sweep.py` — CLI + engine (single- and multi-user sweeps)
- `bola_report.py` — HTML report generator
- `build.bat` — compile to standalone `.exe` (PyInstaller)
- `swagger_data.py` — the official OpenAPI spec, embedded (gzip+base64)
- `test_oracle.py` — unit tests
- `config.example.json` — optional config template
- `informatica_swagger.json` — source spec (only needed to regenerate `swagger_data.py`)
- `req.txt` / `res.txt` — captured sample request/response (test fixtures)
