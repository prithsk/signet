"""Maintenance jobs. Run from cron: `python -m signet.jobs expire`."""
from __future__ import annotations

import json
import sys

from . import core
from .app import db, now


def expire() -> int:
    """Mark pending envelopes past expires_at as expired and append the event. Returns count."""
    n = 0
    with db() as c:
        rows = c.execute("select * from envelopes where status='pending' and expires_at < ?", (now().isoformat(),)).fetchall()
        for env in rows:
            chain = core.AuditChain(json.loads(env["chain_json"]))
            chain.append("expired", "signet", {})
            c.execute("update envelopes set status='expired', chain_json=? where id=?", (json.dumps(chain.events), env["id"]))
            n += 1
    return n


def prune_otps() -> int:
    """Clear stale OTP hashes so they never linger in the database."""
    with db() as c:
        cur = c.execute("update signers set otp_hash=null where otp_hash is not null and otp_expires < ?", (now().isoformat(),))
        return cur.rowcount


def backup() -> str:
    """Tar the database and keys into SIGNET_BACKUP_DIR (default data/backups). Returns path."""
    import os
    import tarfile
    from pathlib import Path

    from .app import DATA, KEYS_DIR, DB_PATH, TLOG

    out_dir = Path(os.environ.get("SIGNET_BACKUP_DIR", DATA / "backups"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"signet-{now().strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
    with tarfile.open(out, "w:gz") as t:
        t.add(DB_PATH, arcname="signet.db")
        t.add(KEYS_DIR, arcname="keys")
        if TLOG.exists():
            t.add(TLOG, arcname="transparency.log")
    return str(out)


def check_transparency() -> str:
    """Verify the local transparency log chain. Exit non-zero from cron if broken."""
    from .app import TLOG
    from .transparency import verify_log

    reason = verify_log(TLOG.read_text()) if TLOG.exists() else None
    if reason:
        sys.exit(reason)
    return "ok"


if __name__ == "__main__":
    job = sys.argv[1] if len(sys.argv) > 1 else "expire"
    print({"expire": expire, "prune_otps": prune_otps, "backup": backup, "check_transparency": check_transparency}[job]())
