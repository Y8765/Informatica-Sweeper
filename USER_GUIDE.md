# Informatica BOLA / IDOR Sweep — Operator's Guide

> **Authorized testing only.** Point this at a system you have written permission to test.
> Defaults are read‑only (GET). It talks to production the moment you press Run.

This guide is the "which button do I press" walkthrough. For internals see `README.md`.

---

## 1. What this tool does (in one minute)

Informatica EDC runs every REST call through one servlet
(`POST /ldmcatalog/ldmProxyServlet`, with the real path/verb inside the JSON body). This tool
speaks that language for you. Think of it like **sqlmap**:

- **Scan** = "does an access‑control flaw exist?" — it requests catalog objects **as each user**
  and classifies whether they can read things they shouldn't. There are **two scan methods**
  (see §4): **Swagger sweep** and **Crawl & map**.
- **Dump data** = "pull the whole DB" — it downloads the full content of every target object for a
  user, to show admins exactly what's exposed.

You give it **one or more users** (by pasting their raw request from Burp). With two users
(e.g. an admin and a low‑privilege user) it does the real IDOR test: *can the low user reach the
admin's objects?*

---

## 2. Launch

- **Easiest:** double‑click `dist\bola-gui.exe` (no Python needed).
- **From source:** `python bola_gui.py` (needs `pip install requests`; `customtkinter` for the dark
  UI and `openpyxl` for Excel export are optional).

The window is one long scrolling page: **Users → Discover → Options → Run/Export → Results → Log.**
Hover any label/checkbox for a tooltip explaining it.

---

## 3. Get a user's raw request from Burp (you'll do this for every user)

1. In Burp, find any request the app made to `…/ldmcatalog/ldmProxyServlet` (browse the catalog while
   proxying, then look in HTTP history).
2. Right‑click → **Copy to file** (or select the whole request in the Request pane and copy).
3. In the tool, paste it into that user's **"raw request"** box and click **Parse raw request** — it
   auto‑fills the URL, cookies, and headers (Infatoken etc.).

That's how the tool "becomes" that user. If a session expires, grab a fresh request and re‑paste.

### No Burp? Paste from the browser instead

When you can't run a proxy and only have the built‑in browser, use its **Network tab** (F12 →
Network), browse the catalog, right‑click any `ldmProxyServlet` (or `/access…`) request, and copy it.
Paste it into the user's box — the tool **auto‑detects the format** and shows a green
"✓ … detected" hint, auto‑selecting the **format** dropdown next to the label. It's usually right;
override the dropdown by hand if it ever guesses wrong (your pick then sticks). Recognised formats:

| Copied via | Set format to |
|---|---|
| Burp / raw HTTP text | **Raw HTTP** |
| Copy as cURL (bash) — Chrome/Firefox | **curl (bash)** |
| Copy as cURL (cmd) — Chrome on Windows | **curl (cmd)** |
| Copy as PowerShell | **curl (PowerShell)** |
| Copy as fetch / Node.js fetch | **fetch / JS** |
| Copy as XHR / XMLHttpRequest snippet | **XHR (JS)** |

**Prefer "Copy as cURL."** Chrome and Firefox strip the session `Cookie` out of *Copy as fetch* (the
real browser supplies it from its cookie jar), so a pasted `fetch` often has no session — the tool
logs a **⚠ No Cookie found** warning when that happens. cURL and PowerShell copies include the cookie.
The re‑auth dialog and CLI (`--paste-format`) auto‑detect the format, so you can paste any of these there.

---

## 4. Two scan methods (Swagger sweep vs Crawl & map)

Both press-and-go; both drop results into the same grid/report. Pick by how you want to reach the API.

| | **▶ Swagger sweep** | **🕷 Crawl & map** |
|---|---|---|
| How it finds endpoints | A **fixed list** from the bundled OpenAPI spec | **Follows the catalog's own `href`s** returned per object (no guessing) |
| Best for | Broad, predictable coverage across many endpoints | Precise, response‑driven testing (correct providerIds/sub‑resources) |
| Downside | May hit endpoints an object doesn't really have → DENIED/NOT‑SCANNED noise | Only tests what the mapper's responses reference |
| Ids | Injects your id into every id‑slot | Uses the real ids the responses contain |

**Crawl & map roles:** the **first user in the list is the "mapper"** — it crawls and builds the URL
map; the **other users replay** those URLs (mapper is skipped on replay — no duplicate self‑test).
So put **admin first**. With a **single user**, there's no one to compare against, so Crawl & map is
just an **inventory** of what that one user can reach (it says so in the log), not an IDOR test.

Rule of thumb: start with **Swagger sweep** for breadth; use **Crawl & map** when you want exact,
link‑accurate coverage (e.g. asset sub‑resources) or to inventory one user.

## 5. Which workflow to follow

### Case A — Two‑user privilege test (the main IDOR test) ⭐
*"The low user has 1 resource; can it reach the admin's others?"*

1. **Add user** → label it `admin` → paste admin's raw request. **(Put admin first — it's the mapper.)**
2. **Add user** → label it `low` → paste the low user's raw request.
3. Under **Enumerate types**, tick **Resources** (test at resource level; assets are "data" — dump
   those separately). Leave **Test against** on **Object API endpoints (/data/objects)**.
4. Click **🔍 Discover.** The tree fills with what each user can enumerate (admin sees more).
5. *(Optional but strongest signal)* In the **low** user's **owns ids** box, put the id(s) it is
   *supposed* to have (use **◀ from discovered** after selecting its legit resource in the tree). This
   makes every other access a **definitive** finding.
6. Press **▶ Swagger sweep** (broad) or **🕷 Crawl & map** (precise, link‑following).
7. Read the results: any **VULNERABLE** row where user = `low` is a real leak. Toggle **Leaks only** to
   hide the noise. **Export** an HTML/Excel report for the write‑up.

### Case B — Single‑user quick check / inventory
*"What can this one session reach?"*

1. **Add user** (just one) → paste its request.
2. **🔍 Discover**, then **▶ Swagger sweep** — findings are heuristic (no second user to compare), so
   treat **ACCESSIBLE?/ENUM‑LEAK** as "review"; declare **owns ids** for firm VULNERABLE calls.
   (**🕷 Crawl & map** with one user = an **inventory** of what it can reach, not a test.)

### Case C — Dump all the data
*"Show the admin everything a user can actually pull."*

1. Set up the user(s) as above (Discover first so there's a target list).
2. Click **Dump data…** → choose a folder → confirm.
3. You get `dump_<user>.ndjson` per user — one line per object with its **full** returned content.
   Open in any text/JSON tool. Great as evidence of exposure.

### Case D — Test specific ids only
- Paste them into **Extra target ids** (one per line), or select rows in the tree and they become the
  targets. Explicit tree selection overrides "test everything."

---

## 6. The screen, control by control

### Users
| Control | What it does |
|---|---|
| **+ Add user** | Add another identity to test as (repeat for admin, low, etc.) |
| **label** | A name for this user (shown in results) |
| **raw request** | Paste the Burp request; **Parse** fills URL/cookies/headers |
| **owns ids** | *(optional)* the ids this user is **legitimately** allowed — one per line. Anything else it reaches = definitive **VULNERABLE**. Leave blank to let the tool infer. |
| **◀ from discovered** | Fill this box from what you selected in the discovery tree (or all, if nothing selected) |
| **remove** | Delete this user row |

### Discovery
| Control | What it does |
|---|---|
| **🔍 Discover** | Enumerates the catalog **as each user** (paginated), fills the tree |
| **Clear** | Wipe the discovered tree/state so the next Discover/scan starts fresh |
| **Enumerate types** (checkboxes) | Which object classes to pull — tick any combo: Resources, Tables, Columns, Data Objects, Data Elements, Views, Schemas. **None ticked = all types.** Tick just **Resources** for the ~8–11 resource‑level targets |
| **Select all / Select none** | Pick which tree rows become targets (none selected = test everything found) |
| **the tree** | Scanner → Resource → Asset, with **Asset type** and **Resource type** columns |
| **Extra target ids** | Ids to test even if enumeration didn't find them (one per line) |
| **Param values** | Real values for non‑id params the tool can't guess, e.g. `reviewId=42`, `DomainName=PROD` (one per line). Used to fill extra `{path}` ids / required query params — **never** the resource id |

### Options
| Control | What it does |
|---|---|
| **Methods** | Which HTTP verbs to send. **GET** is safe. PUT/POST/DELETE need "Enable writes". |
| **Insertion** | `auto` = one best id slot per endpoint; `all` = every candidate slot (like Burp Intruder) |
| **Min length** | Response length (chars) at/above which it's "real content" (empty ≈1200, content ≥1500 → ~1400) |
| **Word thr.** | Fallback content signal (min words) when length isn't available |
| **Max ids** | Cap on how many objects to pull when enumerating |
| **Search q** | Enumeration query (`*` = everything) |
| **Test against** | `Object API endpoints (/data/objects)` = only the ~24 endpoints that accept a real catalog object id (recommended); `All API endpoints` = also model/config `{id}` endpoints (different id space → mostly noise). *This is the /data/objects REST family, NOT the "Data Object" type.* |
| **userId value** | The identity to inject into `userId` params if you enable "userId slots" — the tool does **not** guess this |

### Global flags (apply to Discover **and** the scan)
| Flag | Meaning |
|---|---|
| **Route via Burp** | Send everything through Burp at 127.0.0.1:8080 (to watch/replay). Implies insecure TLS. |
| **Insecure TLS** | Skip cert validation (needed for self‑signed prod / Burp) |
| **Live request log** | Log every request (method, **decoded** path, status, length) to the Log pane |
| **Force enumerate** | Re‑enumerate even if you already discovered |
| **userId slots** | Also inject into `userId` params (needs a "userId value") |
| **No‑auth leg** | Also try each request with **no** cookies, to catch public leaks |
| **Negative ctrl** | Also send a garbage id, so endpoints that echo junk for any id don't false‑positive |
| **Dry run** | Build and show the requests it *would* send — sends nothing (sanity check first) |
| **Enable writes** | Allow PUT/POST/DELETE (dangerous on prod; confirmation required) |
| **Incl. multi‑id endpoints** | Also test endpoints needing several ids (e.g. `/objects/{id}/comments/{commentId}`); off by default because the extra ids can't be guessed |

### Actions
| Button | What it does |
|---|---|
| **▶ Swagger sweep** | Scan method 1 — test targets against the fixed endpoint list from the spec |
| **🕷 Crawl & map** | Scan method 2 — crawl each object as the first user, follow its real hrefs, replay as the other users (see §4) |
| **⏸ Pause / ▶ Resume** | Hold and continue the scan |
| **■ Stop** | Abort the scan |
| **Export…** | Save the report — **.html** (readable, with access matrix + curl/raw), **.xlsx** (findings + access‑matrix sheets), **.csv**, or **.json** |
| **Dump data…** | Download the full content of every target object per user → `dump_<user>.ndjson` |
| **Save log** | Save the Log pane to a file (logs are **not** kept between launches) |
| **Leaks only** | Show only findings (VULNERABLE / PUBLIC / ACCESSIBLE? / ENUM‑LEAK) |

### Results & Log
- Each result row: **Verdict · User · Method · Inner status · Length · Endpoint · Insertion · Id.**
- **Double‑click a row** → detail window with the exact request, the returned data, and **Copy curl /
  Copy raw request** to replay in Burp.
- The final Log line shows the full tally, e.g.
  `Done. 1600 tested — VULNERABLE=3  ACCESSIBLE?=5  ENUM‑LEAK=21  OWNED=40  DENIED=1531`.

---

## 7. How to read the verdicts

| Verdict | Meaning | Action |
|---|---|---|
| **VULNERABLE** | The user **read** an object outside its scope (real IDOR) | **Fix / block** |
| **PUBLIC(no‑auth)** | Readable even with **no** login | **Fix / block** (worse) |
| **ACCESSIBLE?** | User can read it, but its legitimate scope isn't declared | **Review** (declare owns to confirm) |
| **ENUM‑LEAK** | Detail was denied, **but search exposed** the object's existence/metadata to the user | **Review** — search over‑exposure |
| **OWNED** | User read an object in its **declared** scope | Expected — ignore |
| **DENIED** | No access | Correctly blocked |
| **INCONCLUSIVE** | Endpoint returns content even for a garbage id → can't judge | Investigate manually |
| **NOT‑SCANNED** | Endpoint needs extra ids the tool doesn't have | Fill **Param values** or test manually |
| **ERROR** | Network/transport failure | Check connection/session |

For admins deciding what to lock down, open the **Export → Excel → `access-matrix` sheet** (or the
HTML "Access matrix" section): one row per object, one column per user, color‑coded. **OWNED** = leave
it; **VULNERABLE/ACCESSIBLE?/ENUM‑LEAK** = candidates to block; **DENIED** = already fine.

---

## 8. Troubleshooting

- **"session OK" then 0 enumerated / 401s** → that user's pasted request is expired. Grab a fresh one
  from Burp and re‑paste. The tool pops a warning when a session is invalid.
- **Discover finds fewer objects than the catalog UI** → turn on **Live request log** and read the
  `totalCount=` line. If it's low, that session's *search* is genuinely limited — raise **Max ids** or
  use **Extra target ids** to test ids the search didn't return.
- **Everything comes back DENIED** → either access is correctly enforced (good), or the session died
  mid‑run (watch for the session warning), or you're hitting the wrong endpoints (keep **Test against**
  on *Object API endpoints*).
- **Lots of NOT‑SCANNED** → those endpoints need extra ids (e.g. a `commentId`). Add them under
  **Param values**, or ignore — they're not the core object surface.
- **Windows SmartScreen / AV warns on the .exe** → it's unsigned; expected for an internal tool.

---

## 9. Recommended first run (copy/paste checklist)

1. Add **admin** first, then **low** (paste each raw request, **Parse**). *(First user = crawl mapper.)*
2. **Enumerate types** = tick **Resources** · **Test against** = *Object API endpoints (/data/objects)*.
3. Turn on **Live request log** and **Dry run**. Press **▶ Swagger sweep**, read the log to confirm the
   requests look right.
4. Turn **Dry run** off. Press **▶ Swagger sweep** for real (or **🕷 Crawl & map** for link‑accurate).
5. Toggle **Leaks only**, review VULNERABLE/ENUM‑LEAK rows, double‑click to inspect.
6. **Export…** → `.xlsx` and hand the `access-matrix` sheet to the admins.
7. If they want the exposed data itself: **Dump data…** → a folder.
