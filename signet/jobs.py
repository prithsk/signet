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


if __name__ == "__main__":
    job = sys.argv[1] if len(sys.argv) > 1 else "expire"
    print({"expire": expire, "prune_otps": prune_otps}[job]())
