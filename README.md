# ZAS — Distribution Package

**ZAS** is a desktop application for **authorized** vulnerability research and exploitation (internal red team, lab ranges, engagements with written scope).

This package is the **runtime distribution**: GUI, exploit modules, and helper libraries. No marketplace or online module store — everything runs locally.

> **Only test systems you are authorized to assess.** Unauthorized access is illegal.

---

## Contents

```
ZAS/
├── zas_gui.py           # Main GUI
├── zas_config.json      # Saved settings (mode, modules, TLS, scan options)
├── requirements.txt     # Python dependencies
├── README.md
├── core/                # Theme, export (TXT/JSON/CSV/HTML/SARIF), shells UI, audit log
├── exploits/            # Exploit modules (WordPress / Joomla / other) + zas_core
└── lib/                 # Fingerprint, WAF, recon, creds, pivot, stealth, notifications
```

**Included:** ~80 exploit modules, shell session manager, reporting, optional advanced features (fingerprint, WAF, notifications).

---

## Requirements

| | |
|--|--|
| OS | Windows 10/11 (primary) |
| Python | **3.11 or newer** (with tkinter) |
| Network | Outbound HTTPS to targets you are allowed to test |

### Install

```bat
cd ZAS
python -m pip install -r requirements.txt
```

If Python is not installed: [python.org](https://www.python.org/downloads/) → check **“Add Python to PATH”**.

---

## Start

```bat
python zas_gui.py
```

---

## Quick start

1. **Target** — type a URL and press **＋**, or **📁** to load a `.txt` list (one URL per line).
2. **Mode** — use **Exploit** for full exploitation (Detect/Audit are limited in this build).
3. **Modules** — search or filter (CRIT / HIGH / WordPress / Joomla / Other), tick modules in the table.
4. Optional: Threads / Timeout / Jitter / Delay, **Skip validation**, **Ignore SSL** (for lab / self-signed certs).
5. **▶ START** — progress in **Output** (right panel).
6. **Shells** — left menu; successful exploits open sessions (badge count appears there).
7. Export from Output: **HTML / CSV / SARIF / Save**.

**Hotkeys:** `F5` start · `F6` pause · `F7` stop · `Ctrl+S` save log · `Ctrl+O` open targets.

---

## UI overview

| Zone | Purpose |
|------|---------|
| **Top bar** | Target, mode (Detect / Exploit / Audit), START / PAUSE / STOP, scan settings |
| **Left menu** | Modules, Exploit, Advanced, Shodan, Notify, **Shells** |
| **Main** | Module table (search, filters, severity badges, `?` details) |
| **Right** | Output log + export buttons |

---

## Notes

- **Exploit mode is the main path.** Many modules do not perform full passive detection (`detect` may say `not_checked`).
- **`zas_config.json` and `reports/`** can contain credentials and scan data — treat as sensitive.
- **Ignore SSL** is for lab targets with invalid certificates; leave it on only if you understand the risk.
- Cleanup button removes tracked shells/users/templates where possible.

---

## Troubleshooting

| Problem | What to try |
|---------|-------------|
| `python` not found | Reinstall Python and enable “Add to PATH” |
| `ModuleNotFoundError: requests` | `python -m pip install -r requirements.txt` |
| Window won’t open / black screen | Update GPU drivers; try Python 3.11 x64 |
| Target never times out | Lower **Timeout**, enable **Skip validation** for bulk lists |
| SSL errors on HTTPS | Enable **Ignore SSL** (lab only) |

---

## Disclaimer

For defensive security testing, education, and **authorized** red-team use only. You are responsible for compliance with local law and engagement rules.

---

## Contact

**Telegram:** [@vaalzevul](https://t.me/vaalzevul)
