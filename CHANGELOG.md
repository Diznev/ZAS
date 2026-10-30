# Changelog

All notable changes to ZAS. The project is under active development — read
[Status and known limitations](README.md#status-and-known-limitations) alongside this file.

---

## Unreleased

### Added — 6 modules sourced from three public PoC indexes

Candidates were taken from `0xMarcio/pocindex`, `trickest/cve` 2026 and
`nomi-sec/PoC-in-GitHub` 2026, filtered to web products with an explicit
code-execution mechanic and a public PoC, then implemented against the
upstream PoC source itself.

| CVE | Module | Product | Chain |
|---|---|---|---|
| CVE-2025-3248 | `_lf_3248_validate_code` (via `other_langflow_rce`) | Langflow < 1.3.0 | unauthenticated `validate/code` `@exec()` |
| CVE-2025-68613 | `other_n8n_expression_rce` | n8n 0.211.0-1.120.3 / 1.121.0 | authenticated Set-node expression → `child_process` |
| CVE-2026-60004 | `other_gitea_diffpatch_rce` | Gitea 1.17-1.27.0 | `diffpatch` double-send → `-3` fallback → git hook |
| CVE-2026-58138 | `other_conductor_inline_rce` | Conductor 3.21.21-3.30.1 | unauthenticated INLINE javascript → `Runtime.exec` |
| CVE-2026-47668 | `other_dbgate_runners_rce` | DBGate <= 7.1.8 | unauthenticated `runners/start` assign-command → `child_process` |
| CVE-2026-6279 | `wp_avada_builder_rce` | Avada Builder <= 3.15.2 | unauthenticated `call_user_func()` via `render_logics` |

CVE-2025-3248 is the unauthenticated predecessor of the Langflow
`validate/code` chains already in the collection; it is the missing lower
half of that version range and is dispatched by `other_langflow_rce` like
the other twelve. The Langflow facade now covers thirteen CVEs.

CVE-2025-3248 and CVE-2026-58138 both read back a response that can echo
the submitted code or workflow definition. The execution marker is
assembled at runtime from two fragments in those modules, so a reply that
only reflects the request cannot satisfy the verification check.

`other_gitea_diffpatch_rce` does not follow the upstream PoC's reverse
shell: this collection only reports `ok=True` against real command output.
The hook instead posts the output to Gitea's own contents API and the
module verifies against that file. Where no `curl`/`wget` is available in
the hook environment the command runs but the module reports `ok=False`
naming that reason.

---

## ZAS v5.2 — 2026-10-29

Major cleanup of the module collection: every module now has to be backed by a real,
publicly disclosed PoC. Modules that only looked like exploits were either rebuilt
against the real source or removed.

### Added — reverse-shell support

The largest capability gap found while building advanced modules was the lack of any
way to receive a callback. NetScaler waits up to 24 hours for an agent to connect;
TeamCity and Langflow have shell-based targets that were impossible to complete.

- `lib/zas_revshell.py` — 19 payload languages (bash/sh/dash, python/python3, perl,
  ruby, php, node, lua, awk/gawk, nc/ncat/socat/telnet/openssl, powershell, jsp),
  an auto-probe chain that runs whatever the target has, staged `chunked()` delivery
  for interfaces that length-limit input, and `java_source()` for servlet targets.
- `lib/zas_listener.py` — threaded TCP catcher, multi-client, broadcast or single
  target, clean shutdown.
- `core/revshell_tab.py` + a **Listener** panel in the GUI.

### Added — custom request headers

Replaces the unused "Request Signing" toggle. Several modules need a specific header
to reach the vulnerable path at all (an app routing header, a nonce, a session
cookie). The field feeds `zas_core.set_custom_headers()`, which is applied to every
session — no per-module changes required. **Global: clear it between engagements.**

### Added — PDF export

The PDF generator in `lib/zas_pdf_report.py` existed but nothing called it. Wired to
an **PDF** button in the Output panel, with an HTML fallback when `reportlab` is
missing. `reportlab` added to `requirements.txt`.

### Fixed — credentials never reached authenticated modules

The GUI collected `User` / `Pass` but sent them only as `username` / `password`,
while modules read `user`, `email`, `USERNAME`, `pass`, `PASSWORD`. Authenticated
modules (Ghost, five Langflow modules, n8n, FunnelKit) could not see the values the
operator typed. Now passed under every variant.

Also: the pseudo-shell re-exploit path dropped `extra_args` entirely, so an
authenticated module could not log in when a shell command was re-run from the
Shells tab.

### Removed

- **Domain Fronting** toggle — every major CDN disabled the technique after 2021-22,
  so the checkbox implied a capability that does not work. Keep it as a per-engagement
  note if a niche CDN in scope still allows it.
- Dead code: `fingerprint_favicon`, `generate_waf_evasion_headers`, `run_async_scan`,
  `CollapsibleFrame`, three `registry.py` helpers, and 111 unused imports project-wide.
- `zas_recon` trimmed to `ShodanAPI` — the Censys and FOFA clients were never called.

### Added — 19 modules

**From validated public PoCs (5):**

| CVE | Product | Vulnerability |
|---|---|---|
| CVE-2026-88771 | Citrix NetScaler | pre-auth command injection |
| CVE-2026-9198 | Langflow | auto_login SUPERUSER token + `exec()` |
| CVE-2026-93616 | Check Point Management | unauthenticated traversal → upload and execute |
| CVE-2026-75650 | Adobe Commerce | StyleSmuggler template injection (CISA KEV) |
| CVE-2026-104935 | Ivanti Connect Secure | `X-DSCGI-PATH` auth bypass → RCE |

**Ported from Metasploit (14):**

| CVE | Product | Vulnerability |
|---|---|---|
| CVE-2025-48827 / 48828 | vBulletin | `replaceAdTemplate` via Reflection dispatch |
| CVE-2013-2251 | Struts 2 | DefaultActionMapper OGNL (S2-016) |
| CVE-2026-75604 | Next.js | cache traversal RCE |
| CVE-2026-29053 | Ghost CMS | authenticated theme RCE |
| CVE-2026-63077 | JetBrains TeamCity | pre-auth agent-polling XML deserialization |
| CVE-2026-86218 | N-able N-central | unauthenticated Struts race → CGI |
| CVE-2026-0768 / 0769 / 0770 / 10134 | Langflow | unauthenticated RCE, four vectors |
| CVE-2026-18729 / 19295 / 7873 / 93674 | Langflow | authenticated RCE / command injection |

Langflow now spans 12 modules in the collection. Two of the newly added CVEs predate
2026 and are labelled as such: Struts is 2013, vBulletin is 2025 — both entered
Metasploit in 2026.

### Earlier in v5.2

- 10 modules with verified CVEs added (WPvivid, Forminator, Elementor D&D, WPForms Pro,
  WordPress Core LFI, Langflow ×2, n8n, Next.js/sharp).
- 16 modules rebuilt against real public PoCs.
- Detect and Audit modes removed — Exploit is the only mode; `detect()` stripped from
  every module.
- 12 modules removed for lacking any public research.
- Fixed: the shell never echoed the session token (so verification could not pass in
  any module); 9 modules crashed with `NameError` at the moment of success; 4
  late-binding closure bugs in `core/shell_tabs.py`; 25 dead-code gates that made
  `exploit()` return early on a stub.

### Honesty rule

`exploit()` returns `ok=True` **only** when execution is positively verified via
`validate_shell_response()`. HTTP status codes are never proof. Where a working chain
cannot be derived from the public source, the module returns `ok=False` with a precise
reason instead of inventing a request shape.

---

## Known gaps

Carried forward deliberately so nobody mistakes a clean load for a working exploit.

1. **Almost nothing is proven end-to-end.** Two modules have run against a genuinely
   vulnerable target (mock). The other 94 are verified only for the absence of false
   positives. Run anything you intend to trust in a lab first.
2. **Two modules can never report success** — `other_netscaler_preauth_rce` (no
   synchronous verification channel upstream) and `other_langflow_93674_cmdinj`
   (blind). Both say so in `info()`.
3. **Several chains are partial** and return `ok=False` naming the missing stage:
   `wp2shell_sqli` (SQLi only), `avideo_clone_rce` (needs a hostile clone server),
   `wp_travel_engine_deser` and `wp_wpforo_deser` (object injection, no RCE gadget).
4. **Cleanup is not ported** in modules where upstream had it — `other_nable_ncentral_rce`
   leaves a mutated servlet holder, `wp_dbbackup_fileread` is destructive by design.
5. **Custom headers are global**, not per-target.
6. **The reverse-shell listener accepts from anyone** on its bound address.
7. **CVE attribution can lag the research** — some public PoCs predate their CVE.

---

## Testing (local only)

A pytest suite covering the shared helpers, the module contract and the
reverse-shell listener is kept alongside the source but is **not shipped
in this repository**. \	ests/\ is gitignored on purpose.

The defects listed below were found by running it; the fixes are in the
code regardless of where the tests live.

## Langflow consolidated into one module

Thirteen Langflow CVEs meant thirteen GUI rows for one product. They are now one
module, `other_langflow_rce`, which reads the target version and runs only
the chains whose affected range includes it, unauthenticated ones first.

The chain implementations were not touched — they live in `_lf_*` siblings
that the GUI loader skips, so the code that was verified stays verified.
`info()` lists every CVE, and the result's `method` field names the chain
that fired, so the audit trail still identifies the specific vulnerability.

---

## Removed

- **`lib/zas_stealth.py`** — 15.9 KB entirely dead. None of its five classes
  (`DomainFronting`, `RequestSigner`, `AdaptiveDelays`, `ProxyRotator`,
  `StealthSession`) were referenced outside the file, and `AdaptiveDelays` /
  `ProxyRotator` duplicated `zas_core`.
- **`core/registry.py`** — stale duplicate of `exploits/registry.py` (see
  the shadowing bug above).

### Packaging

- Local config, caches and editor/agent state are excluded from git.
- `zas_config.example.json` added as the tracked template.
