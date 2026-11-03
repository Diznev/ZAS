import os
import sys
import json


COLORS = {
    "bg": "#0a0d0b",
    "bg2": "#101511",
    "bg3": "#131a14",
    "bg4": "#0d1110",
    "fg": "#c9d1d9",
    "fg2": "#8b9489",
    "fg3": "#6a736a",
    "green": "#3fb950",
    "red": "#f85149",
    "yellow": "#d29922",
    "blue": "#58a6ff",
    "purple": "#bc8cff",
    "cyan": "#39d353",
    "border": "#1e2b1b",
    "accent": "#c9ff45",
    "accent2": "#a8e036",
    "orange": "#f0883e",
    "pink": "#f778ba",
    "lime": "#c9ff45",
    "teal": "#39d353",
    "primary": "#c9ff45",
    "primaryFg": "#111609",
    "card": "#101511",
    "muted": "#161b17",
    "mutedFg": "#8b9489",
}


def configure_input_styles(root, style):
    """Keep normal, readonly, selected and popup input text legible in clam."""
    for name in ("TEntry", "TCombobox"):
        style.configure(name, foreground=COLORS["fg"], fieldbackground=COLORS["bg2"],
                        background=COLORS["bg3"], bordercolor=COLORS["border"],
                        insertcolor=COLORS["fg"], selectbackground=COLORS["accent"],
                        selectforeground=COLORS["primaryFg"], padding=(6, 4))
        style.map(name,
                  foreground=[("disabled", COLORS["fg3"]), ("!disabled", COLORS["fg"])],
                  fieldbackground=[("disabled", COLORS["bg4"]), ("readonly", COLORS["bg2"])],
                  selectbackground=[("disabled", COLORS["bg4"]), ("!disabled", COLORS["accent"])],
                  selectforeground=[("disabled", COLORS["fg3"]), ("!disabled", COLORS["primaryFg"])],
                  bordercolor=[("focus", COLORS["accent"]), ("!focus", COLORS["border"])])
    style.configure("TCombobox", arrowcolor=COLORS["accent"], arrowsize=14)
    style.map("TCombobox",
              background=[("disabled", COLORS["bg4"]), ("!disabled", COLORS["bg3"])],
              arrowcolor=[("disabled", COLORS["fg3"]), ("!disabled", COLORS["accent"])])
    # The expanded list is a Tk Listbox, not part of the ttk field style.
    for option, value in {
        "background": COLORS["bg2"], "foreground": COLORS["fg"],
        "selectBackground": COLORS["accent"], "selectForeground": COLORS["primaryFg"],
        "selectBorderWidth": 0, "font": ("Segoe UI", 10), "activeStyle": "none",
    }.items():
        root.option_add("*TCombobox*Listbox." + option, value)
    style.map("TButton", background=[("disabled", COLORS["bg4"]),
                                      ("pressed", COLORS["accent2"]),
                                      ("active", COLORS["accent"])],
              foreground=[("disabled", COLORS["fg3"]),
                                      ("pressed", COLORS["primaryFg"]),
                                      ("active", COLORS["primaryFg"])])
    style.configure("Treeview", background=COLORS["bg2"], fieldbackground=COLORS["bg2"], foreground=COLORS["fg"])
    style.map("Treeview", background=[("disabled", COLORS["bg4"]), ("selected", COLORS["accent"])],
              foreground=[("disabled", COLORS["fg3"]), ("selected", COLORS["primaryFg"])])
    style.configure("Treeview.Heading", background=COLORS["bg3"], foreground=COLORS["fg"])
    style.map("Treeview.Heading", background=[("active", COLORS["bg3"]), ("pressed", COLORS["bg3"])],
              foreground=[("active", COLORS["fg"]), ("pressed", COLORS["fg"])])


def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    # Return project root (parent of core/)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_config_path():
    return os.path.join(get_base_dir(), "zas_config.json")


def load_config():
    path = get_config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(cfg):
    try:
        with open(get_config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        return True
    except OSError:
        return False


def classify_exp(exp):
    """Classify exploit module by plugin name. Uses unified registry."""
    try:
        from registry import classify
        return classify(exp.get("plugin", ""))
    except ImportError:
        p = exp.get("plugin", "").lower()
        if p.startswith("com_") or p.startswith("mod_"):
            return "joomla"
        wp_keys = ["wp-", "wordpress", "login-with-azure", "branda", "breeze",
                    "loginpress", "import-users", "duplicator", "all-in-one-seo",
                    "flavor", "tagdiv", "wp-maps", "file-manager", "gravityforms",
                    "fusion-builder", "acf-extended", "easy-invoice", "host-google-fonts",
                    "wp-meta-data", "dokan", "wp-travel", "cf7-hubspot", "wpforo",
                    "database-backup", "divi", "blocksy", "piotnetforms", "advanced-form",
                    "ninja-forms", "instant-appointment"]
        if any(k in p for k in wp_keys):
            return "wordpress"
        return "other"
