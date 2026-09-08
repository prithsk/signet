"""Signet HTTP API v2. One file, SQLite, no ORM.

Env:
  SIGNET_DATA        directory for db and keys (default ./data)
  SIGNET_APIKEY      api key for sender endpoints (default: dev)
  SIGNET_MAIL        memory | log | smtp (default log)
  SIGNET_OTP_TTL     seconds an OTP stays valid (default 600)
  SIGNET_LINK_TTL    seconds a signing link stays valid (default 30 days)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import BackgroundTasks, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response

from . import core, transparency
from .outbox import Mail, make_outbox
from .pages import OTP_HTML, SIGN_HTML
from .ratelimit import RateLimiter

DATA = Path(os.environ.get("SIGNET_DATA", "data"))
API_KEY = os.environ.get("SIGNET_APIKEY", "")
DEV = os.environ.get("SIGNET_DEV") == "1"
OTP_TTL = int(os.environ.get("SIGNET_OTP_TTL", "600"))
LINK_TTL = int(os.environ.get("SIGNET_LINK_TTL", str(30 * 86400)))
MAX_UPLOAD = int(os.environ.get("SIGNET_MAX_UPLOAD", str(20 * 1024 * 1024)))
PUBLIC_URL = os.environ.get("SIGNET_PUBLIC_URL")  # e.g. https://sign.example.com
ALLOW_PRIVATE_WEBHOOKS = os.environ.get("SIGNET_ALLOW_PRIVATE_WEBHOOKS") == "1"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

if not API_KEY or API_KEY in ("dev", "changeme", "test"):
    if DEV:
        API_KEY = API_KEY or "dev"
        print("[signet] DEV MODE with weak api key; never expose this to a network", file=sys.stderr)
    else:
        sys.exit("SIGNET_APIKEY must be set to a strong secret (or set SIGNET_DEV=1 for local dev)")
DATA.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA / "signet.db"
KEYS_DIR = DATA / "keys"
KEYS_DIR.mkdir(exist_ok=True)


def load_keyring() -> core.KeyRing:
    keys = {}
    for pem in sorted(KEYS_DIR.glob("*.pem")):
        k = core.key_from_pem(pem.read_bytes())
        keys[core.key_id(k)] = k
    active_file = KEYS_DIR / "ACTIVE"
    if not keys:
        k = core.generate_key()
        kid = core.key_id(k)
        (KEYS_DIR / f"{kid}.pem").write_bytes(core.key_to_pem(k))
        active_file.write_text(kid)
        keys[kid] = k
    active = active_file.read_text().strip() if active_file.exists() else next(iter(keys))
    return core.KeyRing(keys, active)


def rotate_key() -> str:
    """Generate a new key, make it active, keep old ones for verification."""
    kid = KEYRING.rotate()
    (KEYS_DIR / f"{kid}.pem").write_bytes(core.key_to_pem(KEYRING.active))
    (KEYS_DIR / "ACTIVE").write_text(kid)
    return kid


KEYRING = load_keyring()
OUTBOX = make_outbox()
LIMITER = RateLimiter()
TLOG = DATA / "transparency.log"
RATE_ENVELOPES = int(os.environ.get("SIGNET_RATE_ENVELOPES", "120"))  # per api key per minute
RATE_OTP = int(os.environ.get("SIGNET_RATE_OTP", "20"))  # per ip per minute
RATE_VERIFY = int(os.environ.get("SIGNET_RATE_VERIFY", "60"))  # per ip per minute

SCHEMA = """
create table if not exists envelopes (
  id text primary key, status text, original blob, chain_json text,
  created_at text, expires_at text, webhook_url text, webhook_secret text, title text
);
create table if not exists signers (
  envelope_id text, idx integer, email text, token text unique,
  placements_json text, image blob, signed_at text,
  identity_verified_at text, otp_hash text, otp_expires text, otp_attempts integer default 0,
  primary key (envelope_id, idx)
);
create table if not exists completed (envelope_id text primary key, pdf blob);
create table if not exists mail_log (id integer primary key, ts text, to_addr text, subject text);
create table if not exists webhook_deliveries (
  id integer primary key, envelope_id text, ts text, status integer, attempt integer, error text
);
"""


def db() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    return c


def now() -> datetime:
    return datetime.now(timezone.utc)


def send_mail(c, to: str, subject: str, body: str) -> None:
    OUTBOX.send(Mail(to, subject, body))
    c.execute("insert into mail_log (ts,to_addr,subject) values (?,?,?)", (core.now_iso(), to, subject))


app = FastAPI(title="Signet")


def require_key(x_api_key: str | None):
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(401, "bad api key")


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.get("/health")
def health():
    with db() as c:
        c.execute("select 1")
    return {"ok": True, "active_key_id": KEYRING.active_id, "transparency_entries": sum(1 for _ in TLOG.open()) if TLOG.exists() else 0}


def webhook_url_problem(url: str) -> str | None:
    """Reject anything that could reach private or link-local networks (SSRF)."""
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        return "webhook_url must be http(s) with a host"
    if u.username or u.password:
        return "webhook_url must not contain credentials"
    if ALLOW_PRIVATE_WEBHOOKS:
        return None
    if u.scheme != "https":
        return "webhook_url must be https"
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return "webhook_url host does not resolve"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return "webhook_url must not point at a private, loopback, or link-local address"
    return None


def placement_problem(placements: list, page_count: int) -> str | None:
    for p in placements:
        if not isinstance(p, dict) or set(p) != {"page", "x", "y", "w", "h"}:
            return "each placement needs exactly page, x, y, w, h"
        if not isinstance(p["page"], int) or not 0 <= p["page"] < page_count:
            return f"placement page must be an integer in [0, {page_count - 1}]"
        for k in ("x", "y", "w", "h"):
            if not isinstance(p[k], (int, float)) or not 0 <= p[k] <= 1:
                return f"placement {k} must be a number in [0, 1]"
        if p["w"] <= 0 or p["h"] <= 0 or p["x"] + p["w"] > 1 or p["y"] + p["h"] > 1:
            return "placement box must have positive size and stay inside the page"
    return None


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    if resp.headers.get("content-type", "").startswith("text/html"):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; img-src data:; frame-ancestors 'none'; form-action 'none'"
        )
    return resp


def load_chain(row) -> core.AuditChain:
    return core.AuditChain(json.loads(row["chain_json"]))


def save_chain(c, env_id, chain: core.AuditChain):
    c.execute("update envelopes set chain_json=? where id=?", (json.dumps(chain.events), env_id))


def envelope_open(env) -> str | None:
    """Return a reason the envelope cannot be signed, or None."""
    if env["status"] == "completed":
        return "completed"
    if env["status"] == "voided":
        return "voided"
    if env["expires_at"] and datetime.fromisoformat(env["expires_at"]) < now():
        return "expired"
    return None


# ------------------------------------------------------------ sender API


@app.post("/envelopes")
async def create_envelope(
    request: Request,
    file: UploadFile = File(...),
    signers: str = Form(...),
    title: str = Form("Document"),
    webhook_url: str | None = Form(None),
    send_emails: bool = Form(True),
    x_api_key: str | None = Header(None),
):
    """signers: JSON list of {email, placements:[{page,x,y,w,h}]}."""
    require_key(x_api_key)
    LIMITER.check("envelopes:" + core.sha256(x_api_key.encode())[:16], RATE_ENVELOPES, 60)
    try:
        signer_list = json.loads(signers)
        assert isinstance(signer_list, list) and 0 < len(signer_list) <= 50
        for s in signer_list:
            assert isinstance(s.get("email"), str) and EMAIL_RE.match(s["email"]) and len(s["email"]) <= 254
            assert isinstance(s["placements"], list)
    except Exception:
        raise HTTPException(422, "signers must be a JSON list (1-50) of {email, placements} with valid emails")
    if len({s["email"].lower() for s in signer_list}) != len(signer_list):
        raise HTTPException(422, "signer emails must be unique")
    title = title.strip()[:200] or "Document"
    original = await file.read(MAX_UPLOAD + 1)
    if len(original) > MAX_UPLOAD:
        raise HTTPException(413, f"file exceeds {MAX_UPLOAD} bytes")
    try:
        page_count = len(core.PdfReader(core.io.BytesIO(original)).pages)
        assert page_count > 0
    except Exception:
        raise HTTPException(422, "file is not a readable PDF")
    for s in signer_list:
        why = placement_problem(s["placements"], page_count)
        if why:
            raise HTTPException(422, why)
    if webhook_url:
        why = webhook_url_problem(webhook_url)
        if why:
            raise HTTPException(422, why)

    env_id = "env_" + secrets.token_urlsafe(8)
    expires = (now() + timedelta(seconds=LINK_TTL)).isoformat()
    webhook_secret = secrets.token_urlsafe(32) if webhook_url else None
    chain = core.AuditChain()
    chain.append(
        "created",
        "api",
        {"signers": [s["email"] for s in signer_list], "original_sha256": core.sha256(original), "expires_at": expires},
    )
    links = []
    with db() as c:
        c.execute(
            "insert into envelopes (id,status,original,chain_json,created_at,expires_at,webhook_url,webhook_secret,title)"
            " values (?,?,?,?,?,?,?,?,?)",
            (env_id, "pending", original, json.dumps(chain.events), core.now_iso(), expires, webhook_url, webhook_secret, title),
        )
        for i, s in enumerate(signer_list):
            token = secrets.token_urlsafe(24)
            c.execute(
                "insert into signers (envelope_id, idx, email, token, placements_json) values (?,?,?,?,?)",
                (env_id, i, s["email"], token, json.dumps(s["placements"])),
            )
            base = (PUBLIC_URL.rstrip("/") + "/") if PUBLIC_URL else str(request.base_url)
            url = base + f"sign/{token}"
            links.append({"email": s["email"], "url": url})
            if send_emails:
                send_mail(c, s["email"], f"Please sign: {title}", f"Open this link to review and sign.\n\n{url}\n\nThe link expires {expires[:10]}.")
    out = {"envelope_id": env_id, "status": "pending", "expires_at": expires, "signing_links": links}
    if webhook_secret:
        out["webhook_secret"] = webhook_secret
    return out


@app.get("/envelopes/{env_id}")
def get_envelope(env_id: str, x_api_key: str | None = Header(None)):
    require_key(x_api_key)
    with db() as c:
        row = c.execute("select * from envelopes where id=?", (env_id,)).fetchone()
        if not row:
            raise HTTPException(404)
        signers = c.execute(
            "select idx,email,identity_verified_at,signed_at from signers where envelope_id=? order by idx", (env_id,)
        ).fetchall()
        hooks = c.execute("select ts,status,attempt,error from webhook_deliveries where envelope_id=? order by id", (env_id,)).fetchall()
    return {
        "envelope_id": env_id,
        "title": row["title"],
        "status": row["status"],
        "expires_at": row["expires_at"],
        "signers": [dict(s) for s in signers],
        "events": json.loads(row["chain_json"]),
        "webhook_deliveries": [dict(h) for h in hooks],
    }


@app.post("/envelopes/{env_id}/void")
def void_envelope(env_id: str, x_api_key: str | None = Header(None)):
    require_key(x_api_key)
    with db() as c:
        row = c.execute("select * from envelopes where id=?", (env_id,)).fetchone()
        if not row:
            raise HTTPException(404)
        if row["status"] != "pending":
            raise HTTPException(409, f"envelope is {row['status']}")
        chain = load_chain(row)
        chain.append("voided", "api", {})
        c.execute("update envelopes set status='voided' where id=?", (env_id,))
        save_chain(c, env_id, chain)
    return {"envelope_id": env_id, "status": "voided"}


@app.get("/envelopes/{env_id}/completed.pdf")
def completed_pdf(env_id: str, x_api_key: str | None = Header(None)):
    require_key(x_api_key)
    with db() as c:
        row = c.execute("select pdf from completed where envelope_id=?", (env_id,)).fetchone()
    if not row:
        raise HTTPException(404, "not completed yet")
    return Response(row["pdf"], media_type="application/pdf")


@app.post("/keys/rotate")
def keys_rotate(x_api_key: str | None = Header(None)):
    require_key(x_api_key)
    kid = rotate_key()
    return {"active_key_id": kid}


# ------------------------------------------------------------ webhooks


def deliver_webhook(env_id: str) -> None:
    with db() as c:
        env = c.execute("select * from envelopes where id=?", (env_id,)).fetchone()
        if not env or not env["webhook_url"]:
            return
        payload = json.dumps(
            {"event": "envelope.completed", "envelope_id": env_id, "title": env["title"], "root_hash": json.loads(env["chain_json"])[-1]["hash"]},
            separators=(",", ":"),
        ).encode()
        sig = hmac.new(env["webhook_secret"].encode(), payload, hashlib.sha256).hexdigest()
        for attempt in range(1, 4):
            status, err = None, None
            try:
                r = httpx.post(env["webhook_url"], content=payload, headers={"content-type": "application/json", "x-signet-signature": f"sha256={sig}"}, timeout=10)
                status = r.status_code
            except Exception as e:  # noqa: BLE001
                err = str(e)[:200]
            c.execute(
                "insert into webhook_deliveries (envelope_id,ts,status,attempt,error) values (?,?,?,?,?)",
                (env_id, core.now_iso(), status, attempt, err),
            )
            c.commit()
            if status and 200 <= status < 300:
                return


# ------------------------------------------------------------ signer flow


def _signer_and_env(c, token: str):
    s = c.execute("select * from signers where token=?", (token,)).fetchone()
    if not s:
        raise HTTPException(404)
    env = c.execute("select * from envelopes where id=?", (s["envelope_id"],)).fetchone()
    return s, env


@app.get("/sign/{token}", response_class=HTMLResponse)
def sign_page(token: str, request: Request):
    with db() as c:
        s, env = _signer_and_env(c, token)
        if s["signed_at"]:
            return HTMLResponse("<p style='font:16px system-ui;margin:40px'>Already signed. Thank you.</p>")
        why = envelope_open(env)
        if why:
            return HTMLResponse(f"<p style='font:16px system-ui;margin:40px'>This document is {why} and can no longer be signed.</p>", status_code=410)
        chain = load_chain(env)
        chain.append("viewed", s["email"], {"ip": request.client.host if request.client else None})
        save_chain(c, env["id"], chain)
        if not s["identity_verified_at"]:
            live = s["otp_hash"] and datetime.fromisoformat(s["otp_expires"]) > now() and s["otp_attempts"] < 5
            if not live:
                code = f"{secrets.randbelow(10**6):06d}"
                c.execute(
                    "update signers set otp_hash=?, otp_expires=?, otp_attempts=0 where token=?",
                    (core.sha256(code.encode()), (now() + timedelta(seconds=OTP_TTL)).isoformat(), token),
                )
                chain.append("identity_challenged", s["email"], {"method": "email_otp"})
                save_chain(c, env["id"], chain)
                send_mail(c, s["email"], f"Your code to sign {env['title']}", f"Your verification code is {code}. It expires in {OTP_TTL // 60} minutes.")
            return OTP_HTML.replace("__EMAIL__", s["email"]).replace("__TITLE__", env["title"])
    return SIGN_HTML.replace("__EMAIL__", s["email"]).replace("__TITLE__", env["title"]).replace("__ENV__", env["id"])


@app.post("/sign/{token}/otp")
async def sign_otp(token: str, request: Request):
    LIMITER.check("otp:" + client_ip(request), RATE_OTP, 60)
    body = await request.json()
    code = str(body.get("code", "")).strip()
    with db() as c:
        s, env = _signer_and_env(c, token)
        if s["identity_verified_at"]:
            return {"verified": True}
        if not s["otp_hash"] or datetime.fromisoformat(s["otp_expires"]) < now():
            raise HTTPException(410, "code expired, reload the page for a new one")
        if s["otp_attempts"] >= 5:
            raise HTTPException(429, "too many attempts, reload the page for a new code")
        c.execute("update signers set otp_attempts=otp_attempts+1 where token=?", (token,))
        c.commit()  # must survive the exception below or lockout never triggers
        if not hmac.compare_digest(core.sha256(code.encode()), s["otp_hash"]):
            raise HTTPException(401, "wrong code")
        c.execute("update signers set identity_verified_at=?, otp_hash=null where token=?", (core.now_iso(), token))
        chain = load_chain(env)
        chain.append("identity_verified", s["email"], {"method": "email_otp", "ip": request.client.host if request.client else None})
        save_chain(c, env["id"], chain)
    return {"verified": True}


@app.post("/sign/{token}")
async def sign_submit(token: str, request: Request, background: BackgroundTasks):
    body = await request.json()
    if body.get("typed"):
        try:
            png = core.render_typed_signature(str(body["typed"])[:80])
        except ValueError:
            raise HTTPException(422, "typed name is empty")
        method = "typed"
    else:
        try:
            png = base64.b64decode(body["png"])
            assert png[:8] == b"\x89PNG\r\n\x1a\n"
        except Exception:
            raise HTTPException(422, "png must be base64 PNG, or pass typed")
        method = "drawn"

    with db() as c:
        s, env = _signer_and_env(c, token)
        if s["signed_at"]:
            raise HTTPException(409, "already signed")
        why = envelope_open(env)
        if why:
            raise HTTPException(410, f"envelope {why}")
        if not s["identity_verified_at"]:
            raise HTTPException(403, "verify your email first")
        chain = load_chain(env)
        chain.append(
            "signed",
            s["email"],
            {
                "signer_index": s["idx"],
                "method": method,
                "image_sha256": core.sha256(png),
                "placements": json.loads(s["placements_json"]),
                "ip": request.client.host if request.client else None,
            },
        )
        c.execute("update signers set image=?, signed_at=? where token=?", (png, core.now_iso(), token))
        save_chain(c, env["id"], chain)

        remaining = c.execute("select count(*) from signers where envelope_id=? and signed_at is null", (env["id"],)).fetchone()[0]
        if remaining:
            return {"status": "signed", "remaining": remaining}

        rows = c.execute("select * from signers where envelope_id=? order by idx", (env["id"],)).fetchall()
        pngs = [r["image"] for r in rows]
        placements = [[core.Placement(**p) for p in json.loads(r["placements_json"])] for r in rows]
        pdf = core.seal(env["id"], env["original"], pngs, placements, chain, KEYRING.active)
        transparency.append(TLOG, env["id"], chain.root_hash, KEYRING.active_id)
        c.execute("insert or replace into completed values (?,?)", (env["id"], pdf))
        c.execute("update envelopes set status='completed' where id=?", (env["id"],))
        save_chain(c, env["id"], chain)
        for r in rows:
            send_mail(c, r["email"], f"Completed: {env['title']}", "Everyone has signed. The sender will share the sealed copy.")
    if env["webhook_url"]:
        background.add_task(deliver_webhook, env["id"])
    return {"status": "completed"}


# ------------------------------------------------------------ public verification


@app.get("/.well-known/signet-key")
def well_known_key():
    return {
        "algorithm": "ed25519",
        "active_key_id": KEYRING.active_id,
        "keys": [{"key_id": kid, "public_key": pub} for kid, pub in KEYRING.trusted().items()],
    }


@app.get("/transparency.log")
def transparency_log():
    return Response(TLOG.read_bytes() if TLOG.exists() else b"", media_type="application/x-ndjson")


@app.post("/verify")
async def verify_endpoint(request: Request, file: UploadFile = File(...)):
    LIMITER.check("verify:" + client_ip(request), RATE_VERIFY, 60)
    pdf = await file.read(MAX_UPLOAD + 1)
    if len(pdf) > MAX_UPLOAD:
        raise HTTPException(413, "file too large")
    r = core.verify(pdf, KEYRING.trusted())
    body = {"ok": r.ok, "reason": r.reason}
    if r.record:
        body["envelope_id"] = r.record.get("envelope_id")
        body["key_id"] = r.record.get("key_id")
        body["events"] = r.record.get("events")
        if r.ok:
            logged = TLOG.exists() and transparency.contains(TLOG.read_text(), r.record["root_hash"])
            body["in_transparency_log"] = bool(logged)
            if not logged:
                body["ok"], body["reason"] = False, "seal valid but root hash is not in the transparency log"
                return JSONResponse(body, status_code=400)
    return JSONResponse(body, status_code=200 if r.ok else 400)
