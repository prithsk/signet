"""Append-only transparency log of sealed root hashes.

Each line: canonical JSON {seq, ts, envelope_id, root_hash, key_id, prev, hash}
hash = sha256(prev + canonical(line without prev/hash)). Publish this file somewhere
you cannot quietly rewrite (a public git repo, an object store with versioning). A
document whose root_hash is absent from the log at the claimed time is suspect.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from .core import ZERO_HASH, canonical, now_iso, sha256

_lock = threading.Lock()


def _last(path: Path) -> dict | None:
    if not path.exists():
        return None
    last = None
    with path.open("rb") as f:
        for line in f:
            if line.strip():
                last = json.loads(line)
    return last


def append(path: Path, envelope_id: str, root_hash: str, key_id: str) -> dict:
    with _lock:
        prev_entry = _last(path)
        prev = prev_entry["hash"] if prev_entry else ZERO_HASH
        body = {
            "seq": (prev_entry["seq"] + 1) if prev_entry else 0,
            "ts": now_iso(),
            "envelope_id": envelope_id,
            "root_hash": root_hash,
            "key_id": key_id,
        }
        entry = {**body, "prev": prev, "hash": sha256(prev.encode() + canonical(body))}
        with path.open("ab") as f:
            f.write(canonical(entry) + b"\n")
        return entry


def verify_log(text: str) -> str | None:
    """Return None if the log is an intact chain, else a reason."""
    prev = ZERO_HASH
    for i, line in enumerate(l for l in text.splitlines() if l.strip()):
        e = json.loads(line)
        body = {k: e[k] for k in ("seq", "ts", "envelope_id", "root_hash", "key_id")}
        if e["seq"] != i or e["prev"] != prev or e["hash"] != sha256(prev.encode() + canonical(body)):
            return f"log broken at line {i}"
        prev = e["hash"]
    return None


def contains(text: str, root_hash: str) -> bool:
    return any(json.loads(l)["root_hash"] == root_hash for l in text.splitlines() if l.strip())
