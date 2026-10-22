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
