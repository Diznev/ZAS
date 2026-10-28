# Changelog

## ZAS v5.2 — 2026-10-29

Major cleanup of the module collection: every module now has to be backed by a real,
publicly disclosed PoC. Modules that only looked like exploits were either rebuilt
against the real source or removed.

### Added — 9 new modules

| Module | CVE | Vulnerability |
|---|---|---|
| `wp_wpvivid_sendtosite_rce` | CVE-2026-1357 | WPvivid Backup — crypto fail-open → path-traversal write |
| `wp_forminator_upload_rce` | CVE-2026-15748 | Forminator — forged field config + blocklist bypass |
| `wp_elementor_ddfileupload_rce` | CVE-2026-18351 | Elementor D&D Upload — MIME allowlist regex bypass |
| `wp_wpforms_chunkupload_rce` | CVE-2026-10818 | WPForms Pro — chunked upload written before validation |
| `wp_core_pagetemplate_lfi_rce` | CVE-2026-87902 | WordPress Core — page-template LFI → RCE |
| `other_langflow_buildpublic_rce` | CVE-2026-33017 | Langflow — `exec()` via public flow build |
| `other_langflow_mcp_rce` | CVE-2026-105697 | Langflow — MCP stdio `command`/`args` injection |
| `other_n8n_expr_rce` | CVE-2026-1470 | n8n — Expression sandbox escape (authenticated) |
| `other_nextjs_imageopt_rce` | CVE-2026-96889 | Next.js / sharp — librsvg UAF via `/_next/image` |

### Rebuilt against real public PoCs

Mechanics were invented or only partly ported; each was re-derived from the upstream
source (PoC repo, advisory, or vulnerable-vs-patched plugin diff):

- `other_magento_rce` → CVE-2026-48356 (APSB25-94 PolyShell, guest-cart upload, CISA KEV)
- `joomla_acymailing_upload_rce` (was `joomla_media_upload`) → CVE-2026-94132 (POP3 MIME write)
- `wp_simple_file_list_rce` → CVE-2020-36847 (upload + rename chain, EDB-48979)
- `wp_gravityforms_rce` → CVE-2025-13407 (chunked `?gf_page=upload` name confusion)
- `wp_starter_templates_rce` → CVE-2025-13065 (WXR double-extension upload, Author+)
- `wp_mdtf_lfi` → CVE-2026-54845 (`shortcode_txt` → `mdf_ajax_content_redraw`)
- `wp_ninja_forms_upload_rce` → CVE-2026-0740 (upload + destination override)
- `joomla_jce_rce` → CVE-2026-48907 (two-stage: rogue profile import → browser upload)
- `joomla_rsfiles_rce` → CVE-2026-57827 (`task=rsfiles.upload`)
- `langflow_rce` → CVE-2026-27966 (CSV Agent `python_repl_ast`)
- `wp_easyinvoice_rce` → CVE-2026-48836 (`payment_proof` MIME-only check)
- `wp_hunk_companion_rce` → CVE-2024-11972 (REST `permission_callback` bypass)
- `wp_dbbackup_fileread` → CVE-2026-4030 (`wp_db_temp_dir` + `backup` file read)
- `avideo_clone_rce` → CVE-2026-33478 (key leak + DB dump; RCE needs a hostile clone server)
- `wp2shell_sqli` → CVE-2026-63030 (blind SQLi kept; RCE stage not ported)

### CVE labels corrected

- `wp_blocksy_fonts_rce` CVE-2026-12430 → **CVE-2026-58480 / 15158** (12430 is Stored XSS)
- `wp_royal_elementor_rce` CVE-2024-33829 → **CVE-2023-5360** (33829 is idccms CSRF)
- `wp_simple_file_list_rce` CVE-2024-22988 → **CVE-2020-36847** (22988 is ZKteco)

### Removed

- Detect and Audit modes — Exploit is the only mode. `detect()` removed from every module.
- 12 modules that could not be backed by any public research: `wp_aioseo_rce`,
  `other_gitlab_rce`, `other_prestashop_rce`, `wp_tagdiv_rce`, `wp_cf7hubspot_deser`,
  `other_adminer_rce`, `other_confluence_rce`, `other_jenkins_rce`, `other_laravel_rce`,
  `other_roundcube_rce`, `other_vbulletin_rce`, `joomla_jdownloads_upload_rce`.
- 7 of those carried CVE IDs belonging to entirely different products.

### Fixed

- `zas_core.get_shell_content()` never emitted the session token, so
  `validate_shell_response()` could not pass in any module. It now echoes the token.
- 9 modules crashed with `NameError` at the moment of success (`"version": ver` with
  `ver` undefined, `marker` vs `verify_marker`, unimported `get_shell_content`).
- 4 late-binding closure bugs in `core/shell_tabs.py` — Tk error callbacks raised
  `NameError` after the `except` block exited.
- 25 modules had a dead-code gate: `exploit()` consulted a `detect()` stub that always
  returned `vulnerable: False`, so the exploit path could never run.
- 3 modules claimed success on an HTTP status code alone.
- `zas_config.json` module toggles were out of sync (12 stale, 9 missing).
- Version string was inconsistent (`v5.1` / `v5.0` / `v4.0`); unified to **5.2**.

### Honesty rule

`exploit()` returns `ok=True` **only** when execution is positively verified via
`validate_shell_response()`. HTTP status codes are never proof. Where a working chain
cannot be derived from the public source, the module returns `ok=False` with a precise
reason instead of inventing a request shape.

### Packaging

- `.mimocode/`, `zas_config.json`, `__pycache__`, editor and agent state excluded from git.
- `zas_config.example.json` added as the tracked template.
