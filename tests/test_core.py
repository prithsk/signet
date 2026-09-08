import io
import json
import base64

import pytest
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas

from signet.core import (
    AuditChain,
    Placement,
    generate_key,
    public_key_b64,
    seal,
    sha256,
    verify,
)


def make_pdf(text="Agreement", pages=2) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    for i in range(pages):
        c.drawString(72, 720, f"{text} page {i + 1}")
        c.showPage()
    c.save()
    return buf.getvalue()


def make_png() -> bytes:
    # 1x1 transparent PNG, deterministic
    return base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
    )


@pytest.fixture
def sealed():
    key = generate_key()
    original = make_pdf()
    png = make_png()
    chain = AuditChain()
    chain.append("created", "sender@example.com", {"signers": ["alice@example.com"]})
    chain.append("viewed", "alice@example.com", {"ip": "127.0.0.1"})
    chain.append(
        "signed",
        "alice@example.com",
        {"signer_index": 0, "image_sha256": sha256(png), "placements": [{"page": 1, "x": 0.1, "y": 0.8, "w": 0.3, "h": 0.08}]},
    )
    pdf = seal("env-1", original, [png], [[Placement(1, 0.1, 0.8, 0.3, 0.08)]], chain, key)
    return pdf, public_key_b64(key), original


def test_seal_verifies(sealed):
    pdf, pub, _ = sealed
    r = verify(pdf, pub)
    assert r.ok, r.reason
    assert r.record["events"][-1]["type"] == "completed"


def test_seal_adds_certificate_page(sealed):
    pdf, _, original = sealed
    assert len(PdfReader(io.BytesIO(pdf)).pages) == len(PdfReader(io.BytesIO(original)).pages) + 1


def test_signature_drawn_on_page(sealed):
    pdf, _, original = sealed
    sealed_page = PdfReader(io.BytesIO(pdf)).pages[1]
    orig_page = PdfReader(io.BytesIO(original)).pages[1]
    assert sealed_page.get_contents().get_data() != orig_page.get_contents().get_data()
    assert "/XObject" in sealed_page["/Resources"]


def test_wrong_public_key_fails(sealed):
    pdf, _, _ = sealed
    r = verify(pdf, public_key_b64(generate_key()))
    assert not r.ok and "key" in r.reason


def test_chain_tamper_detected():
    chain = AuditChain()
    chain.append("created", "a")
    chain.append("signed", "b", {"signer_index": 0})
    chain.events[0]["actor"] = "mallory"
    assert AuditChain.verify_events(chain.events) is not None


def _rewrite_with_attachment(pdf: bytes, name: str, data: bytes) -> bytes:
    """Rebuild the PDF replacing one attachment. Simulates a tamperer with pypdf."""
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    for n, blobs in reader.attachments.items():
        writer.add_attachment(n, data if n == name else blobs[0])
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_audit_edit_detected(sealed):
    pdf, pub, _ = sealed
    rec = json.loads(PdfReader(io.BytesIO(pdf)).attachments["signet-audit.json"][0])
    rec["events"][1]["ts"] = "1999-01-01T00:00:00+00:00"
    tampered = _rewrite_with_attachment(pdf, "signet-audit.json", json.dumps(rec).encode())
    r = verify(tampered, pub)
    assert not r.ok and "chain" in r.reason


def test_original_swap_detected(sealed):
    pdf, pub, _ = sealed
    tampered = _rewrite_with_attachment(pdf, "signet-original.pdf", make_pdf("Different"))
    r = verify(tampered, pub)
    assert not r.ok and "original" in r.reason


def test_signature_image_swap_detected(sealed):
    pdf, pub, _ = sealed
    other = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg=="
    )
    tampered = _rewrite_with_attachment(pdf, "signet-signature-0.png", other)
    r = verify(tampered, pub)
    assert not r.ok and "signature image" in r.reason


def test_visible_page_edit_detected(sealed):
    pdf, pub, _ = sealed
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    # draw extra text on page 1 after sealing
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(612, 792))
    c.drawString(72, 400, "I also agree to pay $1,000,000")
    c.showPage()
    c.save()
    buf.seek(0)
    writer.pages[0].merge_page(PdfReader(buf).pages[0])
    for n, blobs in reader.attachments.items():
        writer.add_attachment(n, blobs[0])
    out = io.BytesIO()
    writer.write(out)
    r = verify(out.getvalue(), pub)
    assert not r.ok and "visible page" in r.reason


def test_stripped_attachments_fails(sealed):
    pdf, pub, _ = sealed
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    out = io.BytesIO()
    writer.write(out)
    r = verify(out.getvalue(), pub)
    assert not r.ok and "missing" in r.reason


def test_garbage_input():
    r = verify(b"not a pdf", "AAAA")
    assert not r.ok


def test_untouched_resave_still_verifies(sealed):
    pdf, pub, _ = sealed
    reader = PdfReader(io.BytesIO(pdf))
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    for n, blobs in reader.attachments.items():
        writer.add_attachment(n, blobs[0])
    out = io.BytesIO()
    writer.write(out)
    assert verify(out.getvalue(), pub).ok
