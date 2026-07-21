#!/usr/bin/env python3
"""
Desktop GUI for the Informatica EDC/LDM BOLA (IDOR) sweep tool.

AUTHORIZED SECURITY TESTING ONLY.

Add one or more users (paste each user's raw request), Discover the catalog's
scanners/resources/assets, pick what to test, and run. In multi-user mode the tool
enumerates what each user can see for itself, then flags any resource a user can reach
that lies outside its own set — a definitive IDOR.

Premium CustomTkinter dark shell with a fast ttk.Treeview; falls back to plain ttk when
CustomTkinter is not installed.

    python bola_gui.py
"""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import bola_sweep as bs
import bola_crawl

try:
    import customtkinter as ctk

    HAVE_CTK = True
except Exception:  # pragma: no cover
    ctk = None
    HAVE_CTK = False

PALETTE = {
    bs.VULNERABLE: "#ff5c5c",
    bs.PUBLIC: "#c58cff",
    bs.ACCESSIBLE: "#ff9ecb",
    bs.ENUM_LEAK: "#e0932f",
    bs.OWNED: "#4dd0e1",
    bs.DENIED: "#5fd67a",
    bs.INCONCLUSIVE: "#f0b429",
    bs.SKIPPED: "#6ea8e0",
    bs.ERROR: "#9aa0a6",
    "DRY-RUN": "#4aa3ff",
}
ROW_DARK = ("#242424", "#2b2b2b")

METHOD_CHOICES = ["get", "post", "put", "delete"]

# Object types you can enumerate (label -> Solr core.classType). None checked = all types.
TYPE_CHOICES = [
    ("Resources", "core.Resource"),
    ("Tables", "com.infa.ldm.relational.Table"),
    ("Columns", "com.infa.ldm.relational.Column"),
    ("Data Objects", "core.DataSet"),
    ("Data Elements", "core.DataElement"),
    ("Views", "com.infa.ldm.relational.View"),
    ("Schemas", "com.infa.ldm.relational.DatabaseSchema"),
]

TIP = {
    "discover": "Enumerate the catalog (paginated) and list scanners -> resources/assets. "
                "Pick single, multiple, or all to test. Leaving nothing selected tests everything found.",
    "users": "Each user is a session you test as. Paste that user's raw request (from Burp) — the tool "
             "reads its cookies/headers/URL. Optionally DECLARE the ids this user legitimately owns "
             "(comma/space separated): then access to anything else = definitive leak. Enumeration is "
             "NOT treated as ownership (search can be leaky too), so declaring is the way to confirm.",
    "owned": "Resource ids this user is SUPPOSED to access (its real scope). Leave blank if unknown — "
             "the tool then flags accessible-but-undeclared resources as ACCESSIBLE? for you to review, "
             "and anything reachable that the user couldn't even enumerate as VULNERABLE.",
    "methods": "Which HTTP verbs to sweep. GET is safe/read-only. PUT/POST/DELETE can MODIFY data — off "
               "by default and gated behind 'Enable writes'.",
    "insertion": "Where the resource id is injected. auto = the single best slot per endpoint. "
                 "all = every candidate slot separately (like Burp Intruder sniper).",
    "word_threshold": "Fallback signal: min words in the response body to count as real content, used only "
                      "when response length isn't available.",
    "min_length": "Primary signal: response body length (chars) at/above which it's treated as real content. "
                  "Empty responses cluster ~1200; real content is >=1500, so ~1400 separates them.",
    "max_ids": "Maximum resources to pull when enumerating (paginated).",
    "search_query": "Query used for enumeration. '*' = everything.",
    "opt_enumerate": "Force a fresh enumeration even if you already discovered/selected resources.",
    "opt_burp": "Route every request through Burp at 127.0.0.1:8080 so you can inspect/replay them. Implies insecure TLS.",
    "opt_insecure": "Disable TLS certificate verification (needed for self-signed prod certs / Burp).",
    "opt_userid": "Also inject into a 'userId' parameter (identity spoofing). Requires a 'userId value' "
                  "below — the identity to impersonate. Ignored if that value is empty.",
    "userid_value": "The identity to put in userId parameters when 'userId slots' is on (e.g. another "
                    "user's id like PT\\\\otheruser). The tool does NOT guess this — you set it. "
                    "Leave blank to skip userId injection entirely.",
    "opt_noauth": "Also send each request with auth stripped, to catch resources readable with NO login (public leak).",
    "opt_negative": "Also send a garbage/nonexistent id so the tool learns what 'not found / boilerplate' looks like "
                    "and doesn't falsely flag endpoints that echo junk for any id.",
    "opt_dryrun": "Build and show the requests it WOULD send, but send nothing. Use to sanity-check before hitting prod.",
    "opt_writes": "Allow PUT/POST/DELETE in the sweep. DANGEROUS on production — can modify/delete objects.",
    "opt_verbose": "Log every HTTP request live (method, path, status, response length) to the Log pane — "
                   "for both Discover and Run. Lets you watch requests hit Burp. Chatty; turn off for speed.",
    "opt_multipath": "Include endpoints whose URL needs SEVERAL ids (e.g. /objects/{id}/comments/{commentId}/"
                     "replies/{replyId}). OFF by default: the tool can't know real intermediate ids, so it would "
                     "fill them with the same id (garbage) — meaningless. On = test them anyway (best-effort).",
    "opt_enumleak": "Report ENUM-LEAK: when object detail is DENIED but the search endpoint had exposed that "
                    "object to the user (existence/metadata disclosure). This fires on small/denied responses "
                    "by design, so the Content-length threshold does NOT suppress it. Untick to treat those as "
                    "plain DENIED instead.",
    "endpoint_scope": "Which APIs to test. Swagger sweep: 'Object API endpoints (/data/objects)' (~24) are the "
                      "endpoints that accept a real catalog object id; 'All API endpoints' also hits model/config/{id} "
                      "endpoints (different id space → mostly noise). Crawl & map: 'Object API endpoints' follows only "
                      "object-data hrefs; 'All API endpoints' follows EVERY href the responses contain (incl. "
                      "/models/attributes). (NOT the 'Data Object' type — it's the /data/objects REST family.)",
    "type_filter": "Check which object types to ENUMERATE (what becomes a target). None checked = all types. "
                   "e.g. tick 'Resources' for just the ~11 resources; add 'Tables'/'Columns' to include those "
                   "assets. Each type is pulled via a Solr class-type filter.",
    "param_values": "Supply real values for non-id parameters the tool can't guess, e.g.\n"
                    "  commentId=1234\n  DomainName=PROD\n  type=Oracle\n"
                    "Used to fill extra {path} ids and required query params (never the resource id). "
                    "Endpoints still missing a required id are reported as NOT-SCANNED.",
    "leaks": "Show only rows that need attention — VULNERABLE, PUBLIC, and ACCESSIBLE? — hiding "
             "DENIED/OWNED/INCONCLUSIVE noise. Non-destructive; toggle anytime.",
    "control": "LEGACY single-user knob: a resource you legitimately own, used as a 'what success looks like' baseline. "
               "Not needed in multi-user mode — each user's own resources are the baseline automatically.",
}


class Tooltip:
    def __init__(self, widget, text):
        self.widget, self.text, self.tip = widget, text, None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _e):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 16
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", bg="#0f0f12", fg="#e6e6ea",
                 relief="solid", borderwidth=1, wraplength=520, font=("Segoe UI", 11),
                 padx=10, pady=8).pack()

    def _hide(self, _e):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class BolaGUI:
    def __init__(self, root):
        self.root = root
        self.queue: "queue.Queue" = queue.Queue()
        self.stop_flag = threading.Event()
        self.pause_flag = threading.Event()
        self.reauth_event = threading.Event()
        self._active_cfg = None
        self._active_users = []
        self.worker = None
        self.results: list[bs.Result] = []
        self.counts: dict[str, int] = {}
        self.user_rows: list[dict] = []
        self.discovered: dict[str, bs.ResourceInfo] = {}
        self.enum_by_label: dict[str, set] = {}
        self.item_to_id: dict[str, str] = {}

        self.base_url = tk.StringVar()
        self.insertion_mode = tk.StringVar(value="auto")
        self.word_threshold = tk.IntVar(value=bs.DEFAULT_WORD_THRESHOLD)
        self.min_length = tk.IntVar(value=1400)
        self.max_ids = tk.IntVar(value=500)
        self.search_query = tk.StringVar(value="*")
        self.type_vars = {label: tk.BooleanVar(value=False) for label, _ct in TYPE_CHOICES}
        self.endpoint_scope = tk.StringVar(value="Object API endpoints (/data/objects)")
        self.userid_value = tk.StringVar()
        self.status = tk.StringVar(value="Idle.")
        self.filter_leaks = tk.BooleanVar(value=False)
        self.method_vars = {m: tk.BooleanVar(value=(m == "get")) for m in METHOD_CHOICES}
        for attr, default in [
            ("opt_enumerate", False), ("opt_burp", False), ("opt_insecure", True),
            ("opt_userid", False), ("opt_noauth", True), ("opt_negative", True),
            ("opt_dryrun", False), ("opt_writes", False), ("opt_verbose", True),
            ("opt_multipath", False), ("opt_enumleak", True),
        ]:
            setattr(self, attr, tk.BooleanVar(value=default))
        self.extra_ids_box = None
        self.param_values_box = None

        self.log_box = None
        self._build()
        self._init_tree_style()
        self.add_user_row()
        self.log("Ready. Add user(s), Discover resources, then Run.")

    # ---------------------------------------------------------------- widget factory
    def F(self, parent, **kw):
        return (ctk.CTkFrame(parent, **kw) if HAVE_CTK else ttk.Frame(parent))

    def L(self, parent, text, **kw):
        return ctk.CTkLabel(parent, text=text, **kw) if HAVE_CTK else ttk.Label(parent, text=text)

    def B(self, parent, text, cmd, **kw):
        return ctk.CTkButton(parent, text=text, command=cmd, **kw) if HAVE_CTK else ttk.Button(parent, text=text, command=cmd)

    def E(self, parent, var, width=200):
        return ctk.CTkEntry(parent, textvariable=var, width=width) if HAVE_CTK else ttk.Entry(parent, textvariable=var, width=max(12, width // 8))

    def C(self, parent, text, var, cmd=None):
        if HAVE_CTK:
            return ctk.CTkCheckBox(parent, text=text, variable=var, command=cmd)
        return ttk.Checkbutton(parent, text=text, variable=var, command=cmd)

    def T(self, parent, height_px=70):
        if HAVE_CTK:
            return ctk.CTkTextbox(parent, height=height_px)
        return tk.Text(parent, height=max(3, height_px // 18), wrap="none")

    # ---------------------------------------------------------------- build UI
    def _build(self):
        r = self.root
        r.title("Informatica BOLA Sweep — authorized testing only")
        if HAVE_CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
        # Open at ~a quarter of the screen (resizable), centered — not full-screen.
        sw, sh = r.winfo_screenwidth(), r.winfo_screenheight()
        w, h = max(880, sw // 2), max(600, int(sh * 0.55))
        x, y = (sw - w) // 2, max(0, (sh - h) // 3)
        r.geometry(f"{w}x{h}+{x}+{y}")
        r.minsize(820, 560)

        head = self.F(r, fg_color="transparent") if HAVE_CTK else self.F(r)
        head.pack(fill="x", padx=12, pady=(8, 2))
        title = self.L(head, "Informatica BOLA / IDOR Sweep")
        if HAVE_CTK:
            title.configure(font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(side="left")

        # ONE long scrolling page holding everything (no split panes). Run/Pause/Stop sit
        # inline right after the options/global-flags, in natural flow — not a cramped top bar.
        if HAVE_CTK:
            body = ctk.CTkScrollableFrame(r)
        else:
            body = self._scroll_frame(r)
        body.pack(fill="both", expand=True, padx=10, pady=(4, 10))

        self._build_users(body)
        self._build_discovery(body)
        self._build_options(body)
        self._build_actions(body)
        self._build_results(body)
        self._build_log(body)

    def _scroll_frame(self, parent):
        canvas = tk.Canvas(parent, highlightthickness=0)
        sb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win, width=e.width))
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return inner

    def _build_users(self, parent):
        bar = self.F(parent, fg_color="transparent") if HAVE_CTK else self.F(parent)
        bar.pack(fill="x", padx=6, pady=(6, 0))
        lbl = self.L(bar, "Users  (paste each user's raw request)")
        lbl.pack(side="left")
        Tooltip(lbl, TIP["users"])
        self.B(bar, "+ Add user", self.add_user_row, width=100).pack(side="left", padx=8)
        self.users_container = self.F(parent, fg_color="transparent") if HAVE_CTK else self.F(parent)
        self.users_container.pack(fill="x", padx=6, pady=2)

    def add_user_row(self):
        row = self.F(self.users_container)
        row.pack(fill="x", pady=3)
        label_var = tk.StringVar(value=f"user{len(self.user_rows) + 1}")
        top = self.F(row, fg_color="transparent") if HAVE_CTK else self.F(row)
        top.pack(fill="x")
        self.L(top, "label").pack(side="left")
        self.E(top, label_var, width=120).pack(side="left", padx=6)
        self.B(top, "remove", lambda: self._remove_user(entry), width=70).pack(side="right")

        # format dropdown; state["user_set"] flips once the operator picks a format by hand,
        # after which live auto-detection stops overriding their choice.
        state = {"user_set": False}
        fmt_var = tk.StringVar(value=bs.PASTE_FORMATS[0])
        if HAVE_CTK:
            ctk.CTkOptionMenu(top, variable=fmt_var, values=bs.PASTE_FORMATS, width=150,
                              command=lambda _v: _on_fmt_pick()).pack(side="left", padx=(12, 0))
        else:
            cb = ttk.Combobox(top, textvariable=fmt_var, values=bs.PASTE_FORMATS, width=18, state="readonly")
            cb.pack(side="left", padx=(12, 0))
            cb.bind("<<ComboboxSelected>>", lambda _e: _on_fmt_pick())
        flbl = self.L(top, "format")
        flbl.pack(side="right", padx=(0, 4))
        Tooltip(flbl, "How this request was copied. Burp/proxy = Raw HTTP. From a browser's Network tab: "
                      "right-click a request → Copy as cURL / fetch. Note: 'Copy as fetch' usually omits "
                      "the session cookie — prefer 'Copy as cURL' when only the browser is available.")
        det_lbl = self.L(top, "")  # live "… detected" hint
        det_lbl.pack(side="left", padx=8)

        def _color(widget, color):
            try:
                widget.configure(text_color=color) if HAVE_CTK else widget.configure(foreground=color)
            except Exception:
                pass

        def _refresh_det(*_):
            det = bs.detect_paste_format(txt.get("1.0", "end"))
            if not det:
                det_lbl.configure(text="")
                return
            disp = "Raw HTTP / Burp request" if det == "Raw HTTP" else det
            if not state["user_set"] and fmt_var.get() != det:
                fmt_var.set(det)  # auto-fill the dropdown until the operator overrides it
            if fmt_var.get() == det:
                det_lbl.configure(text=f"✓ {disp} detected")
                _color(det_lbl, "#2ecc71")
            else:
                det_lbl.configure(text=f"⚠ {disp} detected — using {fmt_var.get()}")
                _color(det_lbl, "#f0b429")

        def _on_fmt_pick():
            state["user_set"] = True
            _refresh_det()

        txt = self.T(row, height_px=120)
        try:
            txt.bind("<KeyRelease>", _refresh_det)
            # paste fires before the text lands, so re-check just after
            txt.bind("<<Paste>>", lambda _e: txt.after(15, _refresh_det))
        except Exception:
            pass

        self.L(row, "request paste — Raw HTTP / curl / fetch / XHR (auto-detected; dropdown overrides)").pack(
            anchor="w", padx=2, pady=(4, 0))
        txt.pack(fill="x", pady=(0, 0))

        orow = self.F(row, fg_color="transparent") if HAVE_CTK else self.F(row)
        orow.pack(fill="x", pady=(4, 0))
        olbl = self.L(orow, "owns ids — one per line (optional; comma/space also ok)")
        olbl.pack(side="left", padx=2)
        Tooltip(olbl, TIP["owned"])
        owned_txt = self.T(row, height_px=64)
        self.B(orow, "◀ from discovered", lambda: self._load_selected_into(owned_txt), width=150).pack(side="left", padx=8)
        owned_txt.pack(fill="x")
        Tooltip(owned_txt, TIP["owned"])

        entry = {"frame": row, "label": label_var, "owned": owned_txt, "text": txt, "fmt": fmt_var}
        self.user_rows.append(entry)

    def _remove_user(self, entry):
        if len(self.user_rows) <= 1:
            return
        entry["frame"].destroy()
        self.user_rows.remove(entry)

    def _build_discovery(self, parent):
        bar = self.F(parent, fg_color="transparent") if HAVE_CTK else self.F(parent)
        bar.pack(fill="x", padx=6, pady=(8, 0))
        self.discover_btn = self.B(bar, "🔍 Discover", self.on_discover, width=110)
        self.discover_btn.pack(side="left")
        Tooltip(self.discover_btn, TIP["discover"])
        self.B(bar, "Clear", self.on_clear_discovery, width=70).pack(side="left", padx=6)
        self.B(bar, "Select all", lambda: self.tree_sel(True), width=90).pack(side="left")
        self.B(bar, "Select none", lambda: self.tree_sel(False), width=90).pack(side="left", padx=6)

        # Multi-select object types to enumerate (none checked = all types).
        trow = self.F(parent, fg_color="transparent") if HAVE_CTK else self.F(parent)
        trow.pack(fill="x", padx=6, pady=(2, 0))
        tlbl = self.L(trow, "Enumerate types (none = all):")
        tlbl.pack(side="left", padx=(2, 6))
        Tooltip(tlbl, TIP["type_filter"])
        for label, _ct in TYPE_CHOICES:
            self.C(trow, label, self.type_vars[label]).pack(side="left", padx=4)

        holder = self.F(parent)
        holder.pack(fill="x", padx=6, pady=4)
        self.disc_tree = ttk.Treeview(holder, columns=("type", "restype", "id"), show="tree headings",
                                      height=6, selectmode="extended")
        self.disc_tree.heading("#0", text="Scanner / Resource / Asset")
        self.disc_tree.heading("type", text="Asset type")
        self.disc_tree.heading("restype", text="Resource type")
        self.disc_tree.heading("id", text="Id")
        self.disc_tree.column("#0", width=260)
        self.disc_tree.column("type", width=170)
        self.disc_tree.column("restype", width=120)
        self.disc_tree.column("id", width=340)
        self.disc_tree.configure(height=9)
        dsb = ttk.Scrollbar(holder, orient="vertical", command=self.disc_tree.yview)
        self.disc_tree.configure(yscrollcommand=dsb.set)
        self.disc_tree.pack(side="left", fill="x", expand=True)
        dsb.pack(side="right", fill="y")

        erow = self.F(parent, fg_color="transparent") if HAVE_CTK else self.F(parent)
        erow.pack(fill="x", padx=6, pady=(4, 0))
        elbl = self.L(erow, "Extra target ids — one per line (optional; test even if not enumerated)")
        elbl.pack(side="left")
        Tooltip(elbl, "Paste resource ids to test directly, one per line (comma/space also ok). Useful when a "
                      "low-priv user can't enumerate them via search but you still want to try accessing them by id.")
        self.extra_ids_box = self.T(parent, height_px=64)
        self.B(erow, "◀ from discovered", lambda: self._load_selected_into(self.extra_ids_box), width=150).pack(side="left", padx=8)
        self.extra_ids_box.pack(fill="x", padx=6, pady=(0, 2))

        plbl = self.L(parent, "Param values — name=value, one per line (for extra path ids or required query params)")
        plbl.pack(anchor="w", padx=6, pady=(4, 0))
        Tooltip(plbl, TIP["param_values"])
        self.param_values_box = self.T(parent, height_px=64)
        self.param_values_box.pack(fill="x", padx=6, pady=(0, 2))

    def _build_options(self, parent):
        opt = self.F(parent)
        opt.pack(fill="x", padx=6, pady=(8, 4))

        mrow = self.F(opt, fg_color="transparent") if HAVE_CTK else self.F(opt)
        mrow.pack(fill="x", pady=2)
        mlbl = self.L(mrow, "Methods:")
        mlbl.pack(side="left")
        Tooltip(mlbl, TIP["methods"])
        for m in METHOD_CHOICES:
            self.C(mrow, m.upper(), self.method_vars[m]).pack(side="left", padx=4)

        srow = self.F(opt, fg_color="transparent") if HAVE_CTK else self.F(opt)
        srow.pack(fill="x", pady=2)
        self._labeled(srow, "Insertion", None, "insertion",
                      widget=(ctk.CTkOptionMenu(srow, variable=self.insertion_mode, values=["auto", "all"], width=90)
                              if HAVE_CTK else ttk.Combobox(srow, textvariable=self.insertion_mode,
                                                            values=["auto", "all"], width=8, state="readonly")))
        self._labeled(srow, "Min length", self.min_length, "min_length")
        self._labeled(srow, "Word thr.", self.word_threshold, "word_threshold")
        self._labeled(srow, "Max ids", self.max_ids, "max_ids")
        self._labeled(srow, "Search q", self.search_query, "search_query")

        eprow = self.F(opt, fg_color="transparent") if HAVE_CTK else self.F(opt)
        eprow.pack(fill="x", pady=2)
        eplbl = self.L(eprow, "Test against (which APIs):")
        eplbl.pack(side="left", padx=(4, 4))
        Tooltip(eplbl, TIP["endpoint_scope"])
        ep_opts = ["Object API endpoints (/data/objects)", "All API endpoints"]
        if HAVE_CTK:
            ctk.CTkOptionMenu(eprow, variable=self.endpoint_scope, values=ep_opts, width=280).pack(side="left")
        else:
            ttk.Combobox(eprow, textvariable=self.endpoint_scope, values=ep_opts, width=32, state="readonly").pack(side="left")

        urow = self.F(opt, fg_color="transparent") if HAVE_CTK else self.F(opt)
        urow.pack(fill="x", pady=2)
        ulbl = self.L(urow, "userId value (for userId slots):")
        ulbl.pack(side="left", padx=(4, 4))
        Tooltip(ulbl, TIP["userid_value"])
        ue = self.E(urow, self.userid_value, width=280)
        ue.pack(side="left")
        Tooltip(ue, TIP["userid_value"])

        glbl = self.L(opt, "Global flags — apply to both Discover and Run:")
        glbl.pack(anchor="w", padx=4, pady=(6, 0))
        crow = self.F(opt, fg_color="transparent") if HAVE_CTK else self.F(opt)
        crow.pack(fill="x", pady=4)
        checks = [
            ("Route via Burp", self.opt_burp, "opt_burp"),
            ("Insecure TLS", self.opt_insecure, "opt_insecure"),
            ("Live request log", self.opt_verbose, "opt_verbose"),
            ("Force enumerate", self.opt_enumerate, "opt_enumerate"),
            ("userId slots", self.opt_userid, "opt_userid"),
            ("No-auth leg", self.opt_noauth, "opt_noauth"),
            ("Negative ctrl", self.opt_negative, "opt_negative"),
            ("Dry run", self.opt_dryrun, "opt_dryrun"),
            ("Enable writes", self.opt_writes, "opt_writes"),
            ("Incl. multi-id endpoints", self.opt_multipath, "opt_multipath"),
            ("Enum-leak finding", self.opt_enumleak, "opt_enumleak"),
        ]
        for i, (text, var, key) in enumerate(checks):
            cb = self.C(crow, text, var)
            cb.grid(row=i // 5, column=i % 5, sticky="w", padx=6, pady=3)
            Tooltip(cb, TIP[key])

    def _labeled(self, parent, text, var, tipkey, widget=None):
        lbl = self.L(parent, text)
        lbl.pack(side="left", padx=(12, 4))
        Tooltip(lbl, TIP[tipkey])
        w = widget if widget is not None else self.E(parent, var, width=70)
        w.pack(side="left")
        Tooltip(w, TIP[tipkey])

    def _build_actions(self, parent):
        wrap = self.F(parent)
        wrap.pack(fill="x", padx=6, pady=(8, 4))
        # Row 1: SCAN controls.
        act = self.F(wrap, fg_color="transparent") if HAVE_CTK else self.F(wrap)
        act.pack(fill="x", pady=(4, 2))
        # Row 2: OUTPUT / tools (built below, populated as `act2`).
        act2 = self.F(wrap, fg_color="transparent") if HAVE_CTK else self.F(wrap)
        self.run_btn = self.B(act, "▶  Swagger sweep", self.on_run, width=130)
        self.run_btn.pack(side="left", padx=(6, 0))
        Tooltip(self.run_btn,
                "METHOD 1 — swagger-based. Tries a fixed LIST of endpoints (from the bundled OpenAPI) "
                "against each target id, injecting the id into every id-slot. Broad, predictable coverage; "
                "may hit endpoints an object doesn't really have (→ DENIED/NOT-SCANNED). Good default.")
        self.crawl_btn = self.B(act, "🕷 Crawl & map", self.on_crawl, width=120)
        self.crawl_btn.pack(side="left", padx=6)
        Tooltip(self.crawl_btn,
                "METHOD 2 — crawling-based. Fetches each object's detail as the first user and FOLLOWS the "
                "real hrefs the catalog returns (providerIds, related objects — no guessing), then replays "
                "those exact URLs as the OTHER users. Precise, response-driven; the mapper is skipped on "
                "replay (single user = inventory only).")
        self.aio_btn = self.B(act, "★ AIO", self.on_aio, width=70)
        self.aio_btn.pack(side="left", padx=6)
        Tooltip(self.aio_btn, "All-In-One: run BOTH methods in full — Swagger sweep over ALL API endpoints, then "
                              "Crawl & map following ALL hrefs — and detect file/attachment responses. The most "
                              "thorough (and slowest) option.")
        self.pause_btn = self.B(act, "⏸  Pause", self.on_pause, width=90)
        self.pause_btn.pack(side="left", padx=6)
        self.stop_btn = self.B(act, "■  Stop", self.on_stop, width=80)
        self.stop_btn.pack(side="left")
        if HAVE_CTK:
            self.progress = ctk.CTkProgressBar(act, mode="indeterminate", width=150)
            self.progress.set(0)
        else:
            self.progress = ttk.Progressbar(act, mode="indeterminate", length=150)
        self.progress.pack(side="left", padx=10)

        # ---- Row 2: output / tools ----
        act2.pack(fill="x", pady=(2, 2))
        self.B(act2, "Export…", self.on_export, width=90).pack(side="left", padx=(6, 0))
        dumpb = self.B(act2, "Dump data…", self.on_dump, width=100)
        dumpb.pack(side="left", padx=6)
        Tooltip(dumpb, "Fetch the FULL detail of every target object (per user) and stream it to disk "
                       "as NDJSON — the complete data each user can pull. For admins to review what's exposed.")
        filesb = self.B(act2, "Download files…", self.on_download_files, width=120)
        filesb.pack(side="left")
        Tooltip(filesb, "Save the file/attachment responses found in the results to disk (zip/pdf/csv/…). "
                        "Tries the DIRECT (non-proxy) endpoint for raw bytes; falls back to the proxy copy "
                        "(binary may be corrupt, text is fine).")
        refb = self.B(act2, "Refresh cookies", self.on_refresh_cookies, width=120)
        refb.pack(side="left", padx=6)
        Tooltip(refb, "Re-paste each user's FRESH request into their box above, then click this to rebuild "
                      "every stored result's curl / raw request with the new cookies (per user). Use it before "
                      "copying/exporting requests when the original session has expired (e.g. a day later).")
        self.B(act2, "Save log", self.on_save_log, width=80).pack(side="left")
        leaks = self.C(act2, "Leaks only", self.filter_leaks, self.on_filter_toggle)
        leaks.pack(side="left", padx=10)
        Tooltip(leaks, TIP["leaks"])
        # Row 3: status on its own full-width line so it never gets cut off.
        srow = self.F(wrap, fg_color="transparent") if HAVE_CTK else self.F(wrap)
        srow.pack(fill="x")
        lbl = self.L(srow, "")
        lbl.configure(textvariable=self.status)
        if HAVE_CTK:
            lbl.configure(anchor="w")
        lbl.pack(side="left", fill="x", expand=True, padx=6)
        self._set_running(False)

    def _build_results(self, parent):
        self.L(parent, "Results  (double-click a row for the request / curl)").pack(anchor="w", padx=6, pady=(8, 0))
        res = self.F(parent)
        res.pack(fill="x", padx=6, pady=(0, 6))
        cols = ("verdict", "user", "method", "inner", "len", "endpoint", "insertion", "id")
        widths = (110, 90, 55, 50, 50, 300, 130, 220)
        # Fixed visible height inside the single scrolling page; its own scrollbars for overflow.
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=16)
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w", stretch=(c == "endpoint"))
        vsb = ttk.Scrollbar(res, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(res, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        res.columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self.show_detail)

    def _build_log(self, parent):
        self.L(parent, "Log").pack(anchor="w", padx=6)
        self.log_box = self.T(parent, height_px=170)
        self.log_box.pack(fill="x", padx=6, pady=(0, 10))

    def _init_tree_style(self):
        if HAVE_CTK:
            style = ttk.Style()
            style.theme_use("clam")
            style.configure("Treeview", background="#2b2b2b", fieldbackground="#2b2b2b",
                            foreground="#dce4ee", rowheight=23, borderwidth=0)
            style.configure("Treeview.Heading", background="#1f6aa5", foreground="white", relief="flat")
            style.map("Treeview", background=[("selected", "#144870")], foreground=[("selected", "#fff")])
        for verdict, color in PALETTE.items():
            self.tree.tag_configure(verdict, foreground=color)
        self.tree.tag_configure("odd", background=ROW_DARK[0])
        self.tree.tag_configure("even", background=ROW_DARK[1])

    # ---------------------------------------------------------------- helpers
    def log(self, msg, status=True):
        if status:
            self.status.set(msg)
        if self.log_box is not None:
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")

    def on_save_log(self):
        if self.log_box is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".log",
                                            filetypes=[("Log", "*.log"), ("Text", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.log_box.get("1.0", "end"))
            self.log(f"Log saved to {path}")

    def collect_users(self):
        users, base, servlet = [], "", bs.DEFAULT_SERVLET_PATH
        for row in self.user_rows:
            raw = row["text"].get("1.0", "end").strip()
            if not raw:
                continue
            fmt = row["fmt"].get() if row.get("fmt") else "auto"
            pc = bs.parse_pasted_request(raw, fmt)
            base = base or pc.get("base_url", "")
            if pc.get("servlet_path"):
                servlet = pc["servlet_path"]
            label = row["label"].get().strip() or f"user{len(users) + 1}"
            detected = bs.detect_paste_format(raw)
            note = f" (auto-detected: {detected})" if detected and detected == fmt else ""
            self.log(f"✓ {label}: parsed as {fmt}{note}")
            for warn in pc.get("warnings", []):
                self.log(f"⚠ {label} ({fmt}): {warn}")
            u = bs.User(label=label, cookies=pc.get("cookies", ""), headers=pc.get("headers", {}),
                        base_url=pc.get("base_url", ""))
            # Declared scope is AUTHORITATIVE; enumeration is only a candidate set.
            # Accept one id per line, and/or comma/space separated.
            declared = [t for t in row["owned"].get("1.0", "end").replace(",", " ").split() if t]
            u.owned_ids = set(declared)
            u.enum_ids = set(self.enum_by_label.get(label, set()))
            users.append(u)
        return users, base, servlet

    def _parse_param_values(self):
        vals = {}
        if self.param_values_box is not None:
            for line in self.param_values_box.get("1.0", "end").splitlines():
                line = line.strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    vals[k.strip()] = v.strip()
        return vals

    def build_cfg(self, base, servlet):
        proxies = None
        verify = not self.opt_insecure.get()
        if self.opt_burp.get():
            proxies = {"http": bs.DEFAULT_BURP_PROXY, "https": bs.DEFAULT_BURP_PROXY}
            verify = False
        methods = [m for m in METHOD_CHOICES if self.method_vars[m].get()] or ["get"]
        return bs.Config(
            base_url=self.base_url.get().strip() or base,
            servlet_path=servlet,
            word_threshold=int(self.word_threshold.get()),
            min_length=int(self.min_length.get()),
            methods=methods,
            proxies=proxies,
            verify=verify,
            run_noauth=self.opt_noauth.get(),
            run_negative=self.opt_negative.get(),
            enum_leak=self.opt_enumleak.get(),
            spoof_user=self.userid_value.get().strip(),
            path_values=self._parse_param_values(),
        )

    def _use_userid(self):
        """userId injection only when the box is ticked AND a value is supplied."""
        return self.opt_userid.get() and bool(self.userid_value.get().strip())

    def _selected_class_types(self):
        """Checked object types as Solr class-type strings; [] means 'all types'."""
        return [ct for label, ct in TYPE_CHOICES if self.type_vars[label].get()]

    def _enumerate_user(self, cfg, session, user):
        """Enumerate one user across the selected types (or all if none checked); merged, deduped."""
        types = self._selected_class_types() or [""]
        seen = {}
        for ct in types:
            for r in bs.discover_resources(cfg, session, max_ids=int(self.max_ids.get()),
                                           query=self.search_query.get() or "*", user=user, class_type=ct):
                seen.setdefault(r.id, r)
        return list(seen.values())

    def on_clear_discovery(self):
        """Reset discovery so the next run/Discover starts fresh."""
        self.discovered = {}
        self.enum_by_label = {}
        self.item_to_id = {}
        self.disc_tree.delete(*self.disc_tree.get_children())
        self.log("Discovery cleared.")

    def tree_sel(self, select_all):
        items = []
        for parent in self.disc_tree.get_children():
            items.append(parent)
            items.extend(self.disc_tree.get_children(parent))
        if select_all:
            self.disc_tree.selection_set(items)
        else:
            self.disc_tree.selection_remove(items)

    def _extra_ids(self):
        if self.extra_ids_box is None:
            return []
        return [t for t in self.extra_ids_box.get("1.0", "end").replace(",", " ").split() if t]

    def _assemble_targets(self, users):
        """Resource ids to test. Explicit tree selection wins; otherwise EVERYTHING we know:
        every user's declared owns + enumerated ids + all discovered + extra ids. This is why
        declaring 'pt2 owns 8' makes those 8 get tested against pt3 without pasting them manually."""
        extra = set(self._extra_ids())
        selected = set(self._tree_selected_ids())
        if selected:
            return list(selected | extra)
        ids = set(extra)
        ids |= set(self.discovered.keys())
        for u in users:
            ids |= set(u.owned_ids)
            ids |= set(u.enum_ids)
        return list(ids)

    def _tree_selected_ids(self):
        """Resource ids currently selected in the discovery tree (empty if none selected)."""
        ids = []
        for item in self.disc_tree.selection():
            rid = self.item_to_id.get(item)
            if rid:
                ids.append(rid)
            else:  # a scanner node -> all its children
                for ch in self.disc_tree.get_children(item):
                    cid = self.item_to_id.get(ch)
                    if cid:
                        ids.append(cid)
        return ids

    def _load_selected_into(self, textwidget):
        """Append discovered ids into a text box: selected ones, or ALL if none selected."""
        if not self.discovered:
            messagebox.showinfo("Nothing discovered", "Click 'Discover resources' first.")
            return
        ids = self._tree_selected_ids() or list(self.item_to_id.values())
        existing = set(textwidget.get("1.0", "end").split())
        added = 0
        for i in ids:
            if i not in existing:
                textwidget.insert("end", i + "\n")
                existing.add(i)
                added += 1
        self.log(f"Loaded {added} discovered id(s) ({'selected' if self._tree_selected_ids() else 'all'}).", status=False)

    def selected_ids(self):
        ids = set(self._extra_ids())  # manual ids always included
        for item in self.disc_tree.selection():
            rid = self.item_to_id.get(item)
            if rid:
                ids.add(rid)
            else:
                for ch in self.disc_tree.get_children(item):
                    cid = self.item_to_id.get(ch)
                    if cid:
                        ids.add(cid)
        if not self.disc_tree.selection():  # nothing picked -> all discovered + extras
            ids |= set(self.item_to_id.values())
        return list(ids)

    # ---------------------------------------------------------------- discovery
    def on_discover(self):
        if self.worker and self.worker.is_alive():
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Add at least one user with a pasted raw request.")
            return
        if base and not self.base_url.get().strip():
            self.base_url.set(base)
        cfg = self.build_cfg(base, servlet)
        self.discover_btn.configure(state="disabled")
        self.progress.start()
        self.log("Discovering resources per user … (live requests below)")
        # Track the discovery thread in self.worker so the queue-drain keeps polling until it
        # delivers the 'discovered' result (otherwise the tree updates only on the next click).
        self.worker = threading.Thread(target=self._discover_worker, args=(cfg, users), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _conn_desc(self, cfg):
        proxy = cfg.proxies.get("https") if cfg.proxies else None
        return (f"Connection: {cfg.base_url}{cfg.servlet_path} · "
                f"{'via Burp ' + proxy if proxy else 'direct'} · TLS verify {'off' if not cfg.verify else 'on'}")

    def _set_logger(self):
        bs.REQUEST_LOGGER = (lambda m: self.queue.put(("reqlog", m))) if self.opt_verbose.get() else None

    def _discover_worker(self, cfg, users):
        self._set_logger()
        try:
            import requests
            session = requests.Session()
            self.queue.put(("status", self._conn_desc(cfg)))
            merged: dict[str, bs.ResourceInfo] = {}
            enum: dict[str, set] = {}
            for u in users:
                ok, detail = bs.check_session(cfg, session, user=u)
                self.queue.put(("status", detail))
                if not ok:
                    self.queue.put(("warn", f"{detail}\n\nEnumeration for '{u.label}' will likely be empty. "
                                            f"Re-paste a fresh raw request for this user."))
                res = self._enumerate_user(cfg, session, u)
                enum[u.label] = {r.id for r in res}
                for r in res:
                    if r.id in merged:
                        merged[r.id].seen_by.add(u.label)
                    else:
                        r.seen_by.add(u.label)
                        merged[r.id] = r
                self.queue.put(("status", f"[{u.label}] enumerated {len(res)} resource(s)."))
            self.queue.put(("discovered", (merged, enum)))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    def _populate_tree(self, merged, enum):
        self.discovered = merged
        self.enum_by_label = enum
        self.disc_tree.delete(*self.disc_tree.get_children())
        self.item_to_id = {}
        groups = bs.group_by_scanner(list(merged.values()))
        for scanner, items in sorted(groups.items()):
            parent = self.disc_tree.insert("", "end", text=f"{scanner}  ({len(items)})", values=("", "", ""))
            for r in items:
                node = self.disc_tree.insert(parent, "end", text=r.name or r.id,
                                             values=(r.kind or "-", r.res_type or "-", r.id))
                self.item_to_id[node] = r.id
        self.log(f"Discovered {len(merged)} object(s) across {len(groups)} resource(s). "
                 f"Enumerated (NOT proof of ownership): "
                 + ", ".join(f"{k}={len(v)}" for k, v in enum.items()))

    # ---------------------------------------------------------------- run
    def _set_running(self, running):
        self.run_btn.configure(state="disabled" if running else "normal")
        self.crawl_btn.configure(state="disabled" if running else "normal")
        self.aio_btn.configure(state="disabled" if running else "normal")
        self.pause_btn.configure(state="normal" if running else "disabled")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def on_run(self):
        if self.worker and self.worker.is_alive():
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Add at least one user with a pasted raw request.")
            return
        cfg = self.build_cfg(base, servlet)
        if not cfg.base_url:
            messagebox.showerror("No target", "Could not determine base URL from the raw request(s).")
            return
        writes = sorted(set(cfg.methods) & bs.WRITE_METHODS)
        if writes and not self.opt_dryrun.get():
            if not self.opt_writes.get():
                messagebox.showerror("Blocked", f"{writes} need 'Enable writes' checked (dangerous on prod).")
                return
            if not messagebox.askyesno("Confirm write methods", f"Send {writes} that MAY MODIFY DATA?"):
                return

        self.tree.delete(*self.tree.get_children())
        self.results, self.counts = [], {}
        self.stop_flag.clear()
        self.pause_flag.clear()
        self.pause_btn.configure(text="⏸  Pause")
        self._set_running(True)
        self.progress.start()
        self.log("Running …")
        self.worker = threading.Thread(target=self._run_worker, args=(cfg, users), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _run_worker(self, cfg, users):
        self._set_logger()
        self._active_cfg, self._active_users = cfg, users
        try:
            import requests
            spec = bs.load_swagger(None)
            endpoints = [e for e in bs.load_endpoints(spec, cfg) if e.insertion_points]
            # Scope to the endpoints that actually accept a catalog object id (default), or all.
            if self.endpoint_scope.get().startswith("Object"):
                before = len(endpoints)
                endpoints = [e for e in endpoints if bs.is_data_object_endpoint(e)]
                self.queue.put(("status",
                                f"Endpoint scope: {len(endpoints)} catalog data-object endpoint(s) "
                                f"(of {before} id-bearing) — the surface that accepts a catalog object id."))
            # Endpoints needing real intermediate ids we don't have (and can't fill from Param
            # values) are reported as NOT-SCANNED rather than fired with garbage — unless opted in.
            if not self.opt_multipath.get():
                skipped = [e for e in endpoints if not e.scannable(cfg.path_values)]
                endpoints = [e for e in endpoints if e.scannable(cfg.path_values)]
                for e in skipped:
                    needed = e.uncovered_path_params(cfg.path_values)[1:]  # all but the id slot
                    self.queue.put(("row", bs.Result(
                        endpoint=e.path, method=e.method.upper(), insertion="-", resource_id="-",
                        verdict=bs.SKIPPED,
                        note="needs values for: " + ", ".join(needed) + " — add to 'Param values' or test manually",
                        inner_status=None, word_count=0, rest_path=e.path)))
                if skipped:
                    self.queue.put(("status",
                                    f"{len(skipped)} endpoint(s) NOT scanned (need intermediate ids) — listed as "
                                    f"NOT-SCANNED rows. Fill 'Param values' or tick 'Incl. multi-id endpoints'."))
            session = requests.Session()
            dry = self.opt_dryrun.get()
            self.queue.put(("status", self._conn_desc(cfg)))

            # Ensure per-user ENUMERATION sets + a target list exist (enumerate if needed).
            # Enumeration only builds candidate sets; it never sets declared ownership.
            need_disc = self.opt_enumerate.get() or not self.discovered
            if need_disc and not dry:
                merged, enum = {}, {}
                for u in users:
                    res = self._enumerate_user(cfg, session, u)
                    enum[u.label] = {r.id for r in res}
                    for r in res:
                        merged.setdefault(r.id, r).seen_by.add(u.label)
                    self.queue.put(("status", f"[{u.label}] enumerated {len(res)}"))
                self.enum_by_label = enum
                self.discovered = merged
                for u in users:
                    u.enum_ids = set(enum.get(u.label, set()))
                self.queue.put(("discovered", (merged, enum)))  # also populate the tree

            targets = ["FORBIDDEN_ID_PLACEHOLDER"] if dry else self._assemble_targets(users)
            if not targets:
                self.queue.put(("error",
                                "No resources to test. Declare each user's 'owns ids', add 'Extra target ids', "
                                "or click Discover."))
                return
            self.queue.put(("status", f"Target universe: {len(targets)} resource id(s)."))

            if not any(u.owned_declared for u in users):
                self.queue.put(("status",
                                "No 'owns ids' declared — accessible-but-undeclared resources are flagged "
                                "ACCESSIBLE? for review; declare each user's owned ids for definitive VULNERABLE."))
            use_userid = self._use_userid()
            if self.opt_userid.get() and not use_userid:
                self.queue.put(("status", "userId slots enabled but no 'userId value' set — skipping userId injection."))
            multiuser = len(users) > 1 or any(u.enum_ids or u.owned_ids for u in users)
            cb = dict(on_result=lambda r: self.queue.put(("row", r)),
                      stop_check=self.stop_flag.is_set,
                      pause_check=self.pause_flag.is_set,
                      on_warning=lambda m: self.queue.put(("warn", m)),
                      on_reauth=self._reauth)
            self.queue.put(("status",
                            f"Testing {len(targets)} resource(s) as {len(users)} user(s) "
                            f"over {len(endpoints)} endpoints — {'multi-user IDOR' if multiuser else 'single-user'} mode."))
            if multiuser and not dry:
                bs.run_multiuser_sweep(cfg, endpoints, users, targets,
                                       self.insertion_mode.get(), use_userid, **cb)
            else:
                cfg.cookies = users[0].cookies
                cfg.headers = users[0].headers
                bs.run_sweep(cfg, endpoints, targets, self.insertion_mode.get(),
                             use_userid, dry, **cb)
            self.queue.put(("done", None))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    # ---------------------------------------------------------------- queue drain
    def _drain(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "row":
                    self._add_row(payload)
                elif kind == "status":
                    self.log(payload)
                elif kind == "reqlog":
                    self.log(payload, status=False)
                elif kind == "discovered":
                    self._populate_tree(*payload)
                    self.progress.stop()
                    self.discover_btn.configure(state="normal")
                elif kind == "warn":
                    self.log("⚠ " + payload)
                    messagebox.showwarning("Warning", payload)
                elif kind == "info":
                    self.log(payload)
                    messagebox.showinfo("Done", payload)
                elif kind == "reauth":
                    self._reauth_dialog(payload)
                elif kind == "done":
                    self._finish("Done.")
                    return
                elif kind == "error":
                    self.log("ERROR: " + payload)
                    self._finish("Error.")
                    messagebox.showerror("Error", payload)
                    return
        except queue.Empty:
            pass
        if (self.worker and self.worker.is_alive()) or not self.queue.empty():
            self.root.after(120, self._drain)

    def _add_row(self, r: bs.Result):
        self.results.append(r)
        self.counts[r.verdict] = self.counts.get(r.verdict, 0) + 1
        if not (self.filter_leaks.get() and not r.is_finding):
            self._insert_row(r, len(self.tree.get_children()) + 1)
        tally = "  ".join(f"{v}={n}" for v, n in self.counts.items())
        self.status.set(f"{len(self.results)} tested — {tally}")

    def _insert_row(self, r, i):
        iid = self.tree.insert(
            "", "end",
            values=(r.verdict, r.user, r.method, r.inner_status, r.resp_len, r.endpoint, r.insertion, r.resource_id),
            tags=(r.verdict, "odd" if i % 2 else "even"),
        )
        self.tree.see(iid)

    def _finish(self, msg):
        self.progress.stop()
        self._set_running(False)
        self.discover_btn.configure(state="normal")
        order = [bs.VULNERABLE, bs.PUBLIC, bs.ACCESSIBLE, bs.ENUM_LEAK, bs.OWNED,
                 bs.DENIED, bs.INCONCLUSIVE, bs.SKIPPED, bs.ERROR, "DRY-RUN"]
        tally = "  ".join(f"{v}={self.counts[v]}" for v in order if self.counts.get(v))
        review = sum(self.counts.get(v, 0) for v in (bs.VULNERABLE, bs.PUBLIC, bs.ACCESSIBLE, bs.ENUM_LEAK))
        self.log(f"{msg} {len(self.results)} tested — {tally or 'no results'}")
        self.log(f"{review} finding(s) to review (VULNERABLE/PUBLIC/ACCESSIBLE?/ENUM-LEAK) — "
                 f"toggle 'Leaks only' to focus, or Export for the full report.", status=False)

    def on_pause(self):
        if self.pause_flag.is_set():
            self.pause_flag.clear()
            self.pause_btn.configure(text="⏸  Pause")
            self.log("Resumed.")
        else:
            self.pause_flag.set()
            self.pause_btn.configure(text="▶  Resume")
            self.log("Paused — press Resume to continue.")

    def on_stop(self):
        self.stop_flag.set()
        self.pause_flag.clear()
        self.reauth_event.set()   # unblock any pending re-auth wait
        self.log("Stopping…")

    def _reauth(self, user):
        """Called from the worker thread when a session expired. BLOCKS until the GUI provides
        fresh creds (or the user stops). `user` is the User to refresh, or None for single-user."""
        self.reauth_event.clear()
        self.queue.put(("reauth", user))
        self.reauth_event.wait()   # hold the scan here until the dialog is answered

    def _reauth_dialog(self, user):
        label = user.label if user is not None else (
            self._active_users[0].label if self._active_users else "user")
        win = tk.Toplevel(self.root)
        win.title(f"Session expired — refresh '{label}'")
        win.geometry("820x460")
        win.configure(bg="#1b1b1f")
        win.transient(self.root)
        try:
            win.grab_set()
        except Exception:
            pass
        tk.Label(win, bg="#1b1b1f", fg="#f0b429", font=("Segoe UI", 12, "bold"),
                 text=f"The session for '{label}' looks expired. The scan is PAUSED.").pack(
            anchor="w", padx=10, pady=(10, 2))
        tk.Label(win, bg="#1b1b1f", fg="#e6e6ea", justify="left", font=("Segoe UI", 10),
                 text="Grab a fresh request for this user (Burp, or browser Network tab → Copy as "
                      "cURL/fetch) and paste it below, then 'Apply & resume'. Format is auto-detected; "
                      "only cookies/headers are updated.").pack(anchor="w", padx=10)
        txt = tk.Text(win, height=16, wrap="none", bg="#141418", fg="#e6e6ea",
                      insertbackground="#fff", font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=10, pady=8)

        def apply_():
            raw = txt.get("1.0", "end").strip()
            if not raw:
                messagebox.showerror("Empty", "Paste a raw request first.", parent=win)
                return
            pc = bs.parse_pasted_request(raw, "auto")
            cookies = pc.get("cookies", "")
            headers = pc.get("headers", {})
            for warn in pc.get("warnings", []):
                self.log(f"⚠ {label}: {warn}")
            if user is not None:
                if cookies:
                    user.cookies = cookies
                user.headers = {**user.headers, **headers}
            if user is None or (self._active_users and user is self._active_users[0]):
                if self._active_cfg is not None and cookies:
                    self._active_cfg.cookies = cookies
                    self._active_cfg.headers = {**self._active_cfg.headers, **headers}
            win.destroy()
            self.reauth_event.set()
            self.log(f"Refreshed '{label}' — resuming scan.")

        def stop_():
            self.stop_flag.set()
            win.destroy()
            self.reauth_event.set()
            self.log("Stopped at re-auth.")

        btns = tk.Frame(win, bg="#1b1b1f")
        btns.pack(fill="x", padx=10, pady=(0, 10))
        tk.Button(btns, text="Apply & resume", font=("Segoe UI", 11), command=apply_).pack(side="left")
        tk.Button(btns, text="Stop scan", font=("Segoe UI", 11), command=stop_).pack(side="left", padx=8)
        win.protocol("WM_DELETE_WINDOW", stop_)

    def on_filter_toggle(self):
        self.tree.delete(*self.tree.get_children())
        i = 0
        for r in self.results:
            if not self.filter_leaks.get() or r.is_finding:
                i += 1
                self._insert_row(r, i)

    def on_refresh_cookies(self):
        """Rebuild the stored curl/raw request on every result using the CURRENT user cookies
        (re-parsed from the boxes), so copied/exported requests use a fresh, valid session."""
        if not self.results:
            messagebox.showinfo("Nothing to refresh", "Run a scan first.")
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Paste each user's fresh raw request first.")
            return
        cfg = self.build_cfg(base, servlet)
        by_label = {u.label: u for u in users}
        n = 0
        for r in self.results:
            if not r.rest_path or r.verdict in ("NOT-SCANNED", "DRY-RUN"):
                continue
            u = by_label.get(r.user) or (users[0] if len(users) == 1 else None)
            if u is None:
                continue
            method = r.method or "GET"
            r.curl = bs.build_curl(cfg, r.rest_path, method, user=u)
            r.raw_request = bs.build_raw_request(cfg, r.rest_path, method, user=u)
            n += 1
        self.log(f"Rebuilt {n} request(s) with current cookies — Copy/Export now use the fresh session.")
        messagebox.showinfo("Cookies refreshed",
                            f"Updated {n} stored request(s) to the current cookies.\n"
                            f"Copy-curl / Copy-raw and Export now use the fresh session.")

    def on_export(self):
        if not self.results:
            messagebox.showinfo("Nothing to export", "Run a sweep first.")
            return
        # Explicit format chooser (so Excel is one obvious click, not a hidden dialog dropdown).
        win = tk.Toplevel(self.root)
        win.title("Export report — choose format")
        win.configure(bg="#1b1b1f")
        win.transient(self.root)
        try:
            win.grab_set()
        except Exception:
            pass
        tk.Label(win, bg="#1b1b1f", fg="#e6e6ea", font=("Segoe UI", 12, "bold"),
                 text="Export report as:").pack(anchor="w", padx=14, pady=(12, 6))

        def do(ext, label, filt):
            win.destroy()
            path = filedialog.asksaveasfilename(defaultextension=ext,
                                                filetypes=[(label, filt), ("All files", "*.*")])
            if not path:
                return
            meta = {
                "Target": self.base_url.get(),
                "Users": ", ".join(sorted(self.enum_by_label)) or "-",
                "Endpoints tested": len({r.endpoint for r in self.results}),
                "Resources tested": len({r.resource_id for r in self.results}),
            }
            try:
                bs.write_report(self.results, path, meta)
                self.log(f"Report written to {path}")
                messagebox.showinfo("Exported", f"Saved:\n{path}")
            except Exception as exc:
                messagebox.showerror("Export failed", str(exc))

        row = tk.Frame(win, bg="#1b1b1f")
        row.pack(padx=14, pady=(0, 8))
        tk.Button(row, text="📊  Excel (.xlsx)", font=("Segoe UI", 11), width=18,
                  command=lambda: do(".xlsx", "Excel", "*.xlsx")).grid(row=0, column=0, padx=4, pady=4)
        tk.Button(row, text="🌐  HTML report", font=("Segoe UI", 11), width=18,
                  command=lambda: do(".html", "HTML", "*.html")).grid(row=0, column=1, padx=4, pady=4)
        tk.Button(row, text="CSV", font=("Segoe UI", 11), width=18,
                  command=lambda: do(".csv", "CSV", "*.csv")).grid(row=1, column=0, padx=4, pady=4)
        tk.Button(row, text="JSON", font=("Segoe UI", 11), width=18,
                  command=lambda: do(".json", "JSON", "*.json")).grid(row=1, column=1, padx=4, pady=4)
        tk.Label(win, bg="#1b1b1f", fg="#9aa0a6", font=("Segoe UI", 9),
                 text="Excel = 3 sheets: Findings · All results · access-matrix.").pack(padx=14, pady=(0, 10))

    def on_aio(self):
        if self.worker and self.worker.is_alive():
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Add at least one user with a pasted raw request.")
            return
        cfg = self.build_cfg(base, servlet)
        if not cfg.base_url:
            messagebox.showerror("No target", "Could not determine base URL from the raw request(s).")
            return
        if not messagebox.askyesno("All-In-One",
                                   "Run BOTH methods in full (Swagger sweep over ALL endpoints + Crawl & map "
                                   "following ALL hrefs)? This is the most thorough and slowest option."):
            return
        self.tree.delete(*self.tree.get_children())
        self.results, self.counts = [], {}
        self.stop_flag.clear(); self.pause_flag.clear()
        self.pause_btn.configure(text="⏸  Pause")
        self._set_running(True); self.progress.start()
        self.log("AIO: Swagger sweep (all endpoints) + Crawl & map (all hrefs) …")
        self.worker = threading.Thread(target=self._aio_worker, args=(cfg, users), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _aio_worker(self, cfg, users):
        self._set_logger()
        self._active_cfg, self._active_users = cfg, users
        try:
            import requests
            session = requests.Session()
            self.queue.put(("status", self._conn_desc(cfg)))
            spec = bs.load_swagger(None)
            endpoints = [e for e in bs.load_endpoints(spec, cfg)
                         if e.insertion_points and e.scannable(cfg.path_values)]  # ALL id-bearing, scannable

            # Enumerate per user (owned/enum sets + seeds).
            merged = {}
            for u in users:
                ok, detail = bs.check_session(cfg, session, user=u)
                self.queue.put(("status", detail))
                if not ok:
                    self.queue.put(("warn", f"{detail}\nEnumeration for '{u.label}' may be empty."))
                res = self._enumerate_user(cfg, session, u)
                u.enum_ids = {r.id for r in res}
                for r in res:
                    merged.setdefault(r.id, r).seen_by.add(u.label)
            self.discovered = merged
            self.enum_by_label = {u.label: set(u.enum_ids) for u in users}
            self.queue.put(("discovered", (merged, self.enum_by_label)))
            targets = self._assemble_targets(users)
            if not targets:
                self.queue.put(("error", "Nothing to test — enumeration returned no objects."))
                return

            use_userid = self._use_userid()
            cb = dict(on_result=lambda r: self.queue.put(("row", r)),
                      stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set,
                      on_warning=lambda m: self.queue.put(("warn", m)), on_reauth=self._reauth)

            # Phase 1 — Swagger sweep over ALL endpoints.
            self.queue.put(("status", f"[AIO 1/2] Swagger sweep: {len(targets)} target(s) × {len(endpoints)} endpoints…"))
            bs.run_multiuser_sweep(cfg, endpoints, users, targets,
                                   self.insertion_mode.get(), use_userid, **cb)

            # Phase 2 — Crawl & map (all hrefs) + replay.
            if not (self.stop_flag.is_set()):
                mapper = users[0]
                self.queue.put(("status", f"[AIO 2/2] Crawl & map as '{mapper.label}' (all hrefs)…"))
                crawled = bola_crawl.crawl_map(cfg, session, targets, mapper,
                                               max_objects=int(self.max_ids.get()), data_only=False,
                                               on_progress=lambda oid, n: self.queue.put(("status", f"mapped {n} URL(s)…")),
                                               stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set)
                self.queue.put(("status", f"[AIO 2/2] Replaying {len(crawled)} mapped URL(s)…"))
                bola_crawl.replay_urls(cfg, session, crawled, users, mapper=mapper,
                                       on_result=lambda r: self.queue.put(("row", r)),
                                       stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set,
                                       on_reauth=self._reauth)
            files = sum(1 for r in self.results if r.is_file)
            self.queue.put(("status", f"AIO complete. {files} file/attachment response(s) detected "
                                      f"(use 'Download files…')."))
            self.queue.put(("done", None))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    def on_download_files(self):
        if self.worker and self.worker.is_alive():
            return
        files = [r for r in self.results if r.is_file]
        if not files:
            messagebox.showinfo("No files", "No file/attachment responses were detected in the results.")
            return
        folder = filedialog.askdirectory(title="Save detected files into")
        if not folder:
            return
        users, base, servlet = self.collect_users()
        cfg = self._active_cfg or self.build_cfg(base, servlet)
        by_label = {u.label: u for u in (users or self._active_users or [])}
        self._set_logger()
        self.log(f"Downloading {len(files)} file(s) — trying DIRECT (raw) first, proxy fallback …")
        self.worker = threading.Thread(target=self._download_files_worker,
                                       args=(cfg, files, by_label, folder), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _download_files_worker(self, cfg, files, by_label, folder):
        import os
        import requests
        try:
            session = requests.Session()
            direct = proxy = 0
            for i, r in enumerate(files):
                if self.stop_flag.is_set():
                    break
                user = by_label.get(r.user) or (self._active_users[0] if self._active_users else None)
                name = r.filename or f"{(r.resource_id or 'file')}_{i}.{r.file_ext or 'bin'}"
                name = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in name)[:120] or f"file_{i}"
                path = os.path.join(folder, name)

                # 1) DIRECT (bypass proxy) → raw bytes, no corruption.
                wrote = False
                resp = bs.direct_get(cfg, session, r.rest_path, user=user)
                if resp is not None and resp.status_code == 200 and resp.content and b"<html" not in resp.content[:200].lower():
                    with open(path, "wb") as fh:
                        fh.write(resp.content)
                    direct += 1
                    wrote = True
                    self.queue.put(("status", f"direct ✓ {name} ({len(resp.content)} bytes)"))
                if not wrote:
                    # 2) Fallback: proxy-extracted data (text OK; binary may be corrupt).
                    data = r.response
                    try:
                        d = json.loads(r.response).get("data")
                        if isinstance(d, str):
                            data = d
                        elif d is not None:
                            data = json.dumps(d)
                    except Exception:
                        pass
                    with open(path, "wb") as fh:
                        fh.write(data.encode("utf-8", errors="replace"))
                    proxy += 1
                    tag = " (⚠ may be corrupt)" if "�" in data else ""
                    self.queue.put(("status", f"proxy fallback {name}{tag}"))
            self.queue.put(("info", f"Saved {direct + proxy} file(s) to {folder}.\n"
                                    f"{direct} via DIRECT endpoint (raw, intact), {proxy} via proxy fallback "
                                    f"(binary may be corrupt — text is fine)."))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    def on_crawl(self):
        if self.worker and self.worker.is_alive():
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Add at least one user with a pasted raw request.")
            return
        cfg = self.build_cfg(base, servlet)
        if not cfg.base_url:
            messagebox.showerror("No target", "Could not determine base URL from the raw request(s).")
            return
        self.tree.delete(*self.tree.get_children())
        self.results, self.counts = [], {}
        self.stop_flag.clear()
        self.pause_flag.clear()
        self.pause_btn.configure(text="⏸  Pause")
        self._set_running(True)
        self.progress.start()
        self.log("Crawl & Map …")
        self.worker = threading.Thread(target=self._crawl_worker, args=(cfg, users), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _crawl_worker(self, cfg, users):
        self._set_logger()
        self._active_cfg, self._active_users = cfg, users
        try:
            import requests
            session = requests.Session()
            self.queue.put(("status", self._conn_desc(cfg)))

            # Enumerate per user to get seeds + owned/enum sets (search-based).
            merged = {}
            for u in users:
                ok, detail = bs.check_session(cfg, session, user=u)
                self.queue.put(("status", detail))
                res = self._enumerate_user(cfg, session, u)
                u.enum_ids = {r.id for r in res}
                for r in res:
                    merged.setdefault(r.id, r).seen_by.add(u.label)
            self.discovered = merged
            self.enum_by_label = {u.label: set(u.enum_ids) for u in users}
            self.queue.put(("discovered", (merged, self.enum_by_label)))

            seeds = self._assemble_targets(users)
            if not seeds:
                self.queue.put(("error", "Nothing to crawl — enumeration returned no objects."))
                return

            mapper = users[0]
            data_only = self.endpoint_scope.get().startswith("Object")
            scope_desc = "object-data hrefs only" if data_only else "ALL hrefs (all API endpoints)"
            self.queue.put(("status", f"Mapping as '{mapper.label}': crawling {len(seeds)} object(s), "
                                      f"following {scope_desc} …"))
            crawled = bola_crawl.crawl_map(
                cfg, session, seeds, mapper, max_objects=int(self.max_ids.get()), data_only=data_only,
                on_progress=lambda oid, n: self.queue.put(("status", f"mapped {n} URL(s)…")),
                stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set)
            if not crawled:
                self.queue.put(("error", "Crawl found no catalog data URLs (mapper may lack access)."))
                return
            replay_n = max(1, len(users) - 1) if len(users) > 1 else 1
            if len(users) == 1:
                self.queue.put(("status", f"Mapped {len(crawled)} URL(s). Single user — this is an "
                                          f"INVENTORY of what '{mapper.label}' can reach (no cross-user test)."))
            else:
                self.queue.put(("status", f"Mapped {len(crawled)} URL(s) as '{mapper.label}'. Replaying as the "
                                          f"other {replay_n} user(s) — mapper skipped (already proven)."))

            bola_crawl.replay_urls(
                cfg, session, crawled, users, mapper=mapper,
                on_result=lambda r: self.queue.put(("row", r)),
                stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set,
                on_reauth=self._reauth)
            self.queue.put(("done", None))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    def on_dump(self):
        if self.worker and self.worker.is_alive():
            return
        users, base, servlet = self.collect_users()
        if not users:
            messagebox.showerror("No users", "Add at least one user with a pasted raw request.")
            return
        cfg = self.build_cfg(base, servlet)
        if not cfg.base_url:
            messagebox.showerror("No target", "Could not determine base URL.")
            return
        folder = filedialog.askdirectory(title="Choose a folder to dump all object data into")
        if not folder:
            return
        if not messagebox.askyesno("Confirm data dump",
                                   "This downloads the FULL content of every target object for each user "
                                   "and writes it to disk. Proceed?"):
            return
        self.stop_flag.clear()
        self.pause_flag.clear()
        self._set_running(True)
        self.progress.start()
        self.log(f"Dumping object data to {folder} …")
        self.worker = threading.Thread(target=self._dump_worker, args=(cfg, users, folder), daemon=True)
        self.worker.start()
        self.root.after(120, self._drain)

    def _dump_worker(self, cfg, users, folder):
        self._set_logger()
        try:
            import os
            import requests
            session = requests.Session()

            # Ensure we have a target list (enumerate if nothing discovered yet).
            if not self.discovered and not self.opt_enumerate.get():
                for u in users:
                    res = self._enumerate_user(cfg, session, u)
                    for r in res:
                        self.discovered.setdefault(r.id, r).seen_by.add(u.label)
                    u.enum_ids = {r.id for r in res}
            targets = self._assemble_targets(users)
            self.queue.put(("status", f"Dumping {len(targets)} object(s) per user into {folder}"))

            total_bytes = 0
            for u in users:
                ok, detail = bs.check_session(cfg, session, user=u)
                self.queue.put(("status", detail))
                if not ok:
                    self.queue.put(("warn", f"{detail}\nSkipping dump for '{u.label}'."))
                    continue
                safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in u.label) or "user"
                path = os.path.join(folder, f"dump_{safe}.ndjson")
                count = {"n": 0, "bytes": 0}

                def _write(item, _p=path, _c=count):
                    line = json.dumps(item, ensure_ascii=False)
                    with open(_p, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                    _c["n"] += 1
                    _c["bytes"] += len(line)
                    if _c["n"] % 25 == 0:
                        self.queue.put(("status", f"[{u.label}] dumped {_c['n']} object(s)…"))

                open(path, "w", encoding="utf-8").close()  # truncate/create
                bs.dump_objects(cfg, session, targets, user=u, on_item=_write,
                                stop_check=self.stop_flag.is_set, pause_check=self.pause_flag.is_set)
                total_bytes += count["bytes"]
                self.queue.put(("status", f"[{u.label}] wrote {count['n']} object(s) -> {path} "
                                          f"({count['bytes'] // 1024} KB)"))
            self.queue.put(("status", f"Dump complete. ~{total_bytes // 1024} KB across {len(users)} user(s)."))
            self.queue.put(("done", None))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
        finally:
            bs.REQUEST_LOGGER = None

    def show_detail(self, _e=None):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        r = next((x for x in self.results
                  if x.endpoint == vals[5] and x.insertion == vals[6] and x.resource_id == vals[7]
                  and x.user == vals[1]), None)
        if r is None:
            return
        self._detail_window(r)

    @staticmethod
    def _prettify_response(text):
        """Pretty-print the envelope: expand the escaped inner `data` JSON and indent everything."""
        if not text:
            return "-"
        try:
            env = json.loads(text)
        except Exception:
            return text  # not JSON (e.g. an HTML denial page) — show as-is
        if isinstance(env, dict) and isinstance(env.get("data"), str):
            try:
                env["data"] = json.loads(env["data"])   # unescape inner data so it's readable
            except Exception:
                pass
        try:
            return json.dumps(env, indent=2, ensure_ascii=False)
        except Exception:
            return text

    def _detail_window(self, r):
        win = tk.Toplevel(self.root)
        win.title(f"{r.verdict} — {r.endpoint}")
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        w, h = min(1100, int(sw * 0.8)), min(820, int(sh * 0.85))
        win.geometry(f"{w}x{h}+{(sw - w) // 2}+{max(0, (sh - h) // 3)}")
        win.minsize(760, 480)
        win.configure(bg="#1b1b1f")

        summary = (f"{r.verdict}    user: {r.user}    owned: {r.owned}    "
                   f"inner status: {r.inner_status}    length: {r.resp_len}\n"
                   f"{r.method} {r.endpoint}    [{r.insertion}]\nresource id: {r.resource_id}\n"
                   f"evidence: {r.data_summary or '-'}\nreason: {r.note}")
        tk.Label(win, bg="#1b1b1f", fg="#e6e6ea", justify="left", font=("Consolas", 10),
                 text=summary).pack(anchor="w", padx=10, pady=(8, 4))

        # Buttons FIRST, pinned to the bottom, so they can never be pushed off-screen.
        btns = tk.Frame(win, bg="#1b1b1f")
        btns.pack(side="bottom", fill="x", padx=8, pady=8)
        tk.Button(btns, text="Copy curl", font=("Segoe UI", 11),
                  command=lambda: self._clip(r.curl)).pack(side="left")
        tk.Button(btns, text="Copy raw request", font=("Segoe UI", 11),
                  command=lambda: self._clip(r.raw_request)).pack(side="left", padx=6)
        tk.Button(btns, text="Copy response", font=("Segoe UI", 11),
                  command=lambda: self._clip(r.response)).pack(side="left")
        tk.Button(btns, text="Close", font=("Segoe UI", 11), command=win.destroy).pack(side="right")

        nb = ttk.Notebook(win)
        nb.pack(side="top", fill="both", expand=True, padx=8, pady=4)

        def _tab(title, content, wrap="none"):
            frame = tk.Frame(nb, bg="#141418")
            t = tk.Text(frame, wrap=wrap, bg="#141418", fg="#e6e6ea", insertbackground="#fff",
                        borderwidth=0, font=("Consolas", 11), padx=10, pady=8)
            ysb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
            xsb = ttk.Scrollbar(frame, orient="horizontal", command=t.xview)
            t.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
            t.grid(row=0, column=0, sticky="nsew"); ysb.grid(row=0, column=1, sticky="ns")
            xsb.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
            t.insert("end", content or "-")
            t.configure(state="disabled")
            nb.add(frame, text=title)

        _tab("Response (pretty)", self._prettify_response(r.response), wrap="word")
        _tab("Request (curl)", r.curl, wrap="word")
        _tab("Request (raw HTTP)", r.raw_request)
        _tab("Response (raw)", r.response)

    def _clip(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text or "")
        self.log("Copied to clipboard.")


def main():
    root = ctk.CTk() if HAVE_CTK else tk.Tk()
    BolaGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
