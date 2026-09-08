"""Signet core: audit chain, sealing, flattening, verification.

Pure functions where possible. No web framework, no database.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature
from pypdf import PdfReader, PdfWriter
from reportlab.lib.utils import ImageReader
from reportlab.pdfgen import canvas

ZERO_HASH = "0" * 64


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- audit chain


@dataclass
class AuditChain:
    events: list[dict] = field(default_factory=list)

    def append(self, type_: str, actor: str, data: dict | None = None, ts: str | None = None) -> dict:
        prev = self.events[-1]["hash"] if self.events else ZERO_HASH
        body = {
            "seq": len(self.events),
            "ts": ts or now_iso(),
            "type": type_,
            "actor": actor,
            "data": data or {},
        }
        ev = {**body, "prev_hash": prev, "hash": sha256(prev.encode() + canonical(body))}
        self.events.append(ev)
        return ev

    @property
    def root_hash(self) -> str:
        return self.events[-1]["hash"] if self.events else ZERO_HASH

    @staticmethod
    def verify_events(events: list[dict]) -> str | None:
        """Return None if chain is intact, else a reason string."""
        prev = ZERO_HASH
        for i, ev in enumerate(events):
            if ev.get("seq") != i:
                return f"event {i}: bad seq"
            if ev.get("prev_hash") != prev:
                return f"event {i}: prev_hash mismatch"
            body = {k: ev[k] for k in ("seq", "ts", "type", "actor", "data")}
            expect = sha256(prev.encode() + canonical(body))
            if ev.get("hash") != expect:
                return f"event {i}: hash mismatch"
            prev = ev["hash"]
        return None


# ---------------------------------------------------------------- keys


def generate_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def key_to_pem(k: Ed25519PrivateKey) -> bytes:
    return k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def key_from_pem(pem: bytes) -> Ed25519PrivateKey:
    k = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(k, Ed25519PrivateKey)
    return k


def public_key_b64(k: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = k.public_key() if isinstance(k, Ed25519PrivateKey) else k
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def public_key_from_b64(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(s))


def key_id(k: Ed25519PrivateKey | Ed25519PublicKey | str) -> str:
    """Stable short id: first 16 hex of sha256 over the raw public key."""
    b64 = k if isinstance(k, str) else public_key_b64(k)
    return sha256(base64.b64decode(b64))[:16]


@dataclass
class KeyRing:
    """Several vendor keys; one active for sealing, all trusted for verifying."""

    keys: dict[str, Ed25519PrivateKey]
    active_id: str

    @property
    def active(self) -> Ed25519PrivateKey:
        return self.keys[self.active_id]

    def trusted(self) -> dict[str, str]:
        return {kid: public_key_b64(k) for kid, k in self.keys.items()}

    def rotate(self) -> str:
        k = generate_key()
        kid = key_id(k)
        self.keys[kid] = k
        self.active_id = kid
        return kid


# ---------------------------------------------------------------- typed signatures

TYPED_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSerif-BoldItalic.ttf"
TYPED_FONT_FALLBACK = "/usr/share/fonts/truetype/dejavu/DejaVuSerif-Bold.ttf"


def render_typed_signature(name: str, width: int = 800, height: int = 200) -> bytes:
    """Render a typed name as a transparent PNG. Deterministic for a given name."""
    from PIL import Image, ImageDraw, ImageFont

    name = name.strip()
    if not name:
        raise ValueError("empty name")
    try:
        font = ImageFont.truetype(TYPED_FONT, 96)
    except OSError:
        font = ImageFont.truetype(TYPED_FONT_FALLBACK, 96)
    img = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    while font.size > 20 and d.textlength(name, font=font) > width - 40:
        font = font.font_variant(size=font.size - 4)
    d.text((20, height // 2), name, font=font, fill=(20, 24, 80, 255), anchor="lm")
    d.line([(20, height - 30), (width - 20, height - 30)], fill=(20, 24, 80, 120), width=2)
    out = io.BytesIO()
    img.save(out, "PNG")
    return out.getvalue()


# ---------------------------------------------------------------- flattening


@dataclass
class Placement:
    page: int  # 0-based
    x: float  # fraction of page width from left
    y: float  # fraction of page height from top
    w: float  # fraction of page width
    h: float  # fraction of page height


def _overlay_page(width: float, height: float, draws: list[tuple[Placement, bytes]]) -> Any:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(width, height))
    for p, png in draws:
        img = ImageReader(io.BytesIO(png))
        x = p.x * width
        w = p.w * width
        h = p.h * height
        y = height - (p.y * height) - h
        c.drawImage(img, x, y, width=w, height=h, mask="auto", preserveAspectRatio=True)
    c.showPage()
    c.save()
    buf.seek(0)
    return PdfReader(buf).pages[0]


def flatten(original: bytes, signatures: list[tuple[Placement, bytes]]) -> PdfWriter:
    """Draw signature PNGs onto the original pages. Returns an open writer."""
    reader = PdfReader(io.BytesIO(original))
    writer = PdfWriter()
    by_page: dict[int, list[tuple[Placement, bytes]]] = {}
    for p, png in signatures:
        by_page.setdefault(p.page, []).append((p, png))
    for i, page in enumerate(reader.pages):
        if i in by_page:
            w = float(page.mediabox.width)
            h = float(page.mediabox.height)
            page.merge_page(_overlay_page(w, h, by_page[i]))
        writer.add_page(page)
    return writer


def _certificate_page(envelope_id: str, events: list[dict], root_hash: str, pub_b64: str) -> Any:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    y = 740
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Signing certificate")
    y -= 24
    c.setFont("Helvetica", 9)
    c.drawString(50, y, f"Envelope {envelope_id}")
    y -= 14
    c.drawString(50, y, f"Root hash {root_hash}")
    y -= 14
    c.drawString(50, y, f"Vendor key {pub_b64}")
    y -= 24
    c.setFont("Helvetica-Bold", 10)
    c.drawString(50, y, "Events")
    y -= 16
    c.setFont("Helvetica", 9)
    for ev in events:
        line = f"{ev['seq']:>3}  {ev['ts']}  {ev['type']:<10} {ev['actor']}"
        c.drawString(50, y, line[:110])
        y -= 13
        if y < 60:
            c.showPage()
            c.setFont("Helvetica", 9)
            y = 740
    y -= 10
    c.drawString(50, y, "Verify offline: extract signet-audit.json and check it against the vendor public key.")
    c.showPage()
    c.save()
    buf.seek(0)
    return PdfReader(buf).pages[0]


def page_content_hashes(pages) -> list[str]:
    out = []
    for page in pages:
        contents = page.get_contents()
        data = contents.get_data() if contents is not None else b""
        out.append(sha256(data))
    return out


# ---------------------------------------------------------------- sealing


def seal(
    envelope_id: str,
    original: bytes,
    signature_pngs: list[bytes],
    placements: list[list[Placement]],
    chain: AuditChain,
    key: Ed25519PrivateKey,
) -> bytes:
    """Produce the completed, self-verifying PDF.

    signature_pngs[i] belongs to signer i and is drawn at placements[i].
    chain must already contain created/signed events. A completed event is added here.
    """
    draws = [(p, png) for png, plist in zip(signature_pngs, placements) for p in plist]
    writer = flatten(original, draws)

    chain.append("completed", "signet", {"signers": len(signature_pngs)})
    pub_b64 = public_key_b64(key)
    writer.add_page(_certificate_page(envelope_id, chain.events, chain.root_hash, pub_b64))

    record = {
        "version": 1,
        "envelope_id": envelope_id,
        "original_sha256": sha256(original),
        "events": chain.events,
        "page_content_sha256": page_content_hashes(writer.pages),
        "root_hash": chain.root_hash,
        "signed_at": now_iso(),
        "public_key": pub_b64,
        "key_id": key_id(key),
    }
    sig = key.sign(canonical(record))
    record["signature"] = base64.b64encode(sig).decode()

    writer.add_attachment("signet-original.pdf", original)
    for i, png in enumerate(signature_pngs):
        writer.add_attachment(f"signet-signature-{i}.png", png)
    writer.add_attachment("signet-audit.json", canonical(record))

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


# ---------------------------------------------------------------- verification


@dataclass
class VerifyResult:
    ok: bool
    reason: str
    record: dict | None = None


def _attachments(reader: PdfReader) -> dict[str, bytes]:
    out = {}
    for name, blobs in reader.attachments.items():
        out[name] = blobs[0]
    return out


def verify(pdf: bytes, trusted: str | dict[str, str]) -> VerifyResult:
    """trusted: one public key (b64) or a {key_id: public_key_b64} map of all vendor keys."""
    trusted_map = {key_id(trusted): trusted} if isinstance(trusted, str) else dict(trusted)
    try:
        reader = PdfReader(io.BytesIO(pdf))
        att = _attachments(reader)
    except Exception as e:  # noqa: BLE001
        return VerifyResult(False, f"unreadable pdf: {e}")

    if "signet-audit.json" not in att or "signet-original.pdf" not in att:
        return VerifyResult(False, "missing signet attachments")
    try:
        record = json.loads(att["signet-audit.json"])
    except Exception:  # noqa: BLE001
        return VerifyResult(False, "audit json unparsable")

    if sha256(att["signet-original.pdf"]) != record.get("original_sha256"):
        return VerifyResult(False, "original document hash mismatch", record)

    for ev in record.get("events", []):
        if ev.get("type") == "signed":
            idx = ev["data"].get("signer_index")
            name = f"signet-signature-{idx}.png"
            if name not in att:
                return VerifyResult(False, f"missing {name}", record)
            if sha256(att[name]) != ev["data"].get("image_sha256"):
                return VerifyResult(False, f"signature image {idx} hash mismatch", record)

    reason = AuditChain.verify_events(record.get("events", []))
    if reason:
        return VerifyResult(False, f"chain broken: {reason}", record)
    if record.get("root_hash") != (record["events"][-1]["hash"] if record.get("events") else ZERO_HASH):
        return VerifyResult(False, "root hash mismatch", record)

    if page_content_hashes(reader.pages) != record.get("page_content_sha256"):
        return VerifyResult(False, "visible page content changed after sealing", record)

    doc_pub = record.get("public_key", "")
    doc_kid = record.get("key_id") or key_id(doc_pub) if doc_pub else None
    if doc_kid not in trusted_map or trusted_map[doc_kid] != doc_pub:
        return VerifyResult(False, "vendor key in document is not a trusted key", record)
    sig = base64.b64decode(record.get("signature", ""))
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    try:
        public_key_from_b64(doc_pub).verify(sig, canonical(unsigned))
    except (InvalidSignature, ValueError):
        return VerifyResult(False, "vendor signature invalid", record)

    return VerifyResult(True, "ok", record)
