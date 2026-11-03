"""Local research metadata only: no downloads, code execution or module loading."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
import uuid


STATUSES = {
    "new": "New",
    "reviewing": "Under review",
    "needs_lab": "Awaiting lab",
    "deferred": "Deferred",
    "rejected": "Rejected",
}
CATALOG_NOTE = (
    "Research catalog: CVE IDs are recorded as claims and require verification "
    "against NVD/GHSA. Status indicates workflow progress, not confirmed exploitation. "
    "Catalog entries neither install modules nor execute PoCs."
)
MAX_BYTES = 4 * 1024 * 1024
MAX_CANDIDATES = 2000
TEXT_LIMITS = {
    "cve": 40, "product": 200, "versions": 1000, "preconditions": 5000,
    "poc_url": 2000, "advisory_url": 2000, "revision": 200, "notes": 10_000,
}
FIELDS = set(TEXT_LIMITS) | {"id", "status", "created_at", "updated_at"}


class CatalogConflict(ValueError):
    """The catalog was modified since the caller loaded it, or is being saved."""


def validate_source_url(value, required=False):
    """Allow browser links only; never interpret a local path or script URI."""
    if not value:
        if required:
            raise ValueError("Provide a URL for the public PoC or research")
        return ""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or any(char.isspace() or ord(char) < 32 for char in value)):
            raise ValueError()
        parsed.port
    except ValueError as exc:
        raise ValueError("Source must be an HTTP(S) URL without a username or password") from exc
    return value


def validate_candidate(record):
    if not isinstance(record, dict) or set(record) - FIELDS:
        raise ValueError("Invalid candidate fields")
    result = {}
    for field, limit in TEXT_LIMITS.items():
        value = record.get(field, "")
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f"Field {field}: enter text no longer than {limit} characters")
        result[field] = value.strip()
    result["cve"] = result["cve"].upper()
    if not re.fullmatch(r"CVE-(?:\d{4}-\d{4,}|UNVERIFIED)", result["cve"]):
        raise ValueError("Enter CVE-YYYY-NNNN or CVE-UNVERIFIED; the ID requires independent verification")
    if not result["product"]:
        raise ValueError("Specify a product")
    validate_source_url(result["poc_url"], required=True)
    validate_source_url(result["advisory_url"])
    status = record.get("status", "new")
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("Unknown candidate status")
    if status == "needs_lab" and not all(result[key] for key in ("versions", "preconditions", "advisory_url")):
        raise ValueError("Before lab review, specify affected versions, prerequisites and an advisory URL")
    if status in ("rejected", "deferred") and not result["notes"]:
        raise ValueError("Provide a reason for rejection or deferral in the notes")
    result["status"] = status
    try:
        result["id"] = str(uuid.UUID(record["id"]))
        for field in ("created_at", "updated_at"):
            value = record[field]
            if not isinstance(value, str) or len(value) > 40:
                raise ValueError()
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError()
            result[field] = parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        if result["updated_at"] < result["created_at"]:
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid entry ID or date with timezone") from exc
    return result


def make_candidate(fields, original=None):
    """Create/edit metadata, preserving stable identity and creation date."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    previous = validate_candidate(original) if original is not None else None
    record = {key: fields.get(key, "") for key in TEXT_LIMITS}
    record.update(status=fields.get("status", "new"),
                  id=previous["id"] if previous else str(uuid.uuid4()),
                  created_at=previous["created_at"] if previous else now,
                  updated_at=max(now, previous["updated_at"]) if previous else now)
    return validate_candidate(record)


def _identity(record):
    product = " ".join(record["product"].casefold().split())
    if record["cve"] == "CVE-UNVERIFIED":
        return record["cve"], product, record["poc_url"].rstrip("/")
    return record["cve"], product


def candidate_identity(record):
    """Shared duplicate key for local entries and advisory previews."""
    return _identity(record)


def validate_candidates(records):
    if not isinstance(records, list) or len(records) > MAX_CANDIDATES:
        raise ValueError(f"Catalog must contain no more than {MAX_CANDIDATES} entries")
    validated = [validate_candidate(record) for record in records]
    ids, identities = set(), set()
    for record in validated:
        if record["id"] in ids or _identity(record) in identities:
            raise ValueError("Duplicate candidate: the ID or CVE/product combination already exists")
        ids.add(record["id"])
        identities.add(_identity(record))
    return validated


def _read_bytes(path):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(raw) > MAX_BYTES:
        raise ValueError("Catalog exceeds the 4 MiB size limit")
    return raw


def load_catalog(path):
    raw = _read_bytes(path)
    if raw is None:
        return {"candidates": [], "revision": None}
    try:
        document = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Catalog is invalid: expected UTF-8 JSON; the original file was not changed") from exc
    if (not isinstance(document, dict) or set(document) != {"schema_version", "candidates"}
            or type(document["schema_version"]) is not int or document["schema_version"] != 1):
        raise ValueError("Unsupported candidate catalog format")
    return {"candidates": validate_candidates(document["candidates"]),
            "revision": hashlib.sha256(raw).hexdigest()}


def catalog_document(records):
    document = {"schema_version": 1, "candidates": validate_candidates(records)}
    raw = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("Catalog exceeds the 4 MiB size limit")
    return raw


def save_catalog(path, records, expected_revision):
    """Atomic write with optimistic concurrency and a short exclusive lock.

    A pre-existing lock is never removed automatically. Failed writes preserve
    the prior catalog and remove only this operation's temporary files.
    """
    normalized = validate_candidates(records)
    raw = catalog_document(normalized)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = path.with_name(path.name + ".lock")
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise CatalogConflict("Another save is in progress. Try again later; the existing lock file was preserved.") from exc
    temporary = None
    try:
        os.close(descriptor)
        current = load_catalog(path)
        if current["revision"] != expected_revision:
            raise CatalogConflict("Another window changed the catalog. Close the editor, reload the catalog and retry.")
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".candidates-", suffix=".tmp",
                                         dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        return {"candidates": normalized, "revision": hashlib.sha256(raw).hexdigest()}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        lock.unlink(missing_ok=True)


def merge_candidates(existing, incoming):
    """Import new identities only; never overwrite existing research notes."""
    existing, incoming = validate_candidates(existing), validate_candidates(incoming)
    by_identity = {_identity(record): record for record in existing}
    by_id = {record["id"]: record for record in existing}
    merged = list(existing)
    skipped = 0
    for record in incoming:
        match = by_identity.get(_identity(record)) or by_id.get(record["id"])
        if match is not None:
            comparable = set(FIELDS) - {"id", "created_at", "updated_at"}
            if any(record[key] != match[key] for key in comparable):
                raise CatalogConflict("Import contains a conflicting duplicate. Edit the existing entry; nothing was overwritten.")
            skipped += 1
            continue
        merged.append(record)
        by_identity[_identity(record)] = record
        by_id[record["id"]] = record
    return {"candidates": validate_candidates(merged), "added": len(merged) - len(existing), "skipped": skipped}
