import base64
import hashlib
import hmac
import io
import json
import os
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ["SIGNET_DATA"] = tempfile.mkdtemp()
os.environ["SIGNET_APIKEY"] = "test-key"
os.environ["SIGNET_MAIL"] = "memory"
os.environ["SIGNET_ALLOW_PRIVATE_WEBHOOKS"] = "1"
os.environ["SIGNET_OTP_TTL"] = "600"

from fastapi.testclient import TestClient  # noqa: E402

from signet import app as appmod  # noqa: E402
from signet import core  # noqa: E402
from tests.test_core import make_pdf, make_png  # noqa: E402

client = TestClient(app=appmod.app)
H = {"x-api-key": "test-key"}
OUT = appmod.OUTBOX


def create(signers, **extra):
    data = {"signers": json.dumps(signers), "title": "Test Agreement", **extra}
    return client.post("/envelopes", headers=H, files={"file": ("a.pdf", make_pdf(), "application/pdf")}, data=data)


def token_of(link):
    return link["url"].rsplit("/", 1)[1]


def last_code_for(email: str) -> str:
    for m in reversed(OUT.sent):
        if m.to == email and "verification code" in m.body:
            return re.search(r"code is (\d{6})", m.body).group(1)
    raise AssertionError("no code mailed")


def verify_identity(tok, email):
    r = client.get(f"/sign/{tok}")
    assert r.status_code == 200 and "verification code" in r.text.lower() or "Verification code" in r.text
    r = client.post(f"/sign/{tok}/otp", json={"code": last_code_for(email)})
    assert r.status_code == 200, r.text
    r = client.get(f"/sign/{tok}")
    assert "Sign document" in r.text


# ------------------------------------------------------------ basics


def test_requires_api_key():
    r = client.post("/envelopes", files={"file": ("a.pdf", make_pdf(), "application/pdf")}, data={"signers": "[]"})
    assert r.status_code == 401


def test_rejects_non_pdf():
    r = client.post(
        "/envelopes", headers=H, files={"file": ("a.pdf", b"nope", "application/pdf")},
        data={"signers": json.dumps([{"email": "a@x.com", "placements": []}])},
    )
    assert r.status_code == 422


def test_unknown_token():
    assert client.get("/sign/nope").status_code == 404


def test_create_sends_signing_email():
    before = len(OUT.sent)
    r = create([{"email": "mail@x.com", "placements": []}])
    assert r.status_code == 200
    new = OUT.sent[before:]
    assert len(new) == 1 and new[0].to == "mail@x.com" and token_of(r.json()["signing_links"][0]) in new[0].body


# ------------------------------------------------------------ identity


def test_cannot_sign_before_otp():
    r = create([{"email": "a@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    client.get(f"/sign/{tok}")
    r = client.post(f"/sign/{tok}", json={"png": base64.b64encode(make_png()).decode()})
    assert r.status_code == 403


def test_wrong_otp_then_right():
    r = create([{"email": "otp@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    client.get(f"/sign/{tok}")
    assert client.post(f"/sign/{tok}/otp", json={"code": "000000"}).status_code == 401
    assert client.post(f"/sign/{tok}/otp", json={"code": last_code_for("otp@x.com")}).status_code == 200


def test_otp_lockout_after_five():
    r = create([{"email": "lock@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    client.get(f"/sign/{tok}")
    for _ in range(5):
        client.post(f"/sign/{tok}/otp", json={"code": "111111"})
    assert client.post(f"/sign/{tok}/otp", json={"code": last_code_for("lock@x.com")}).status_code == 429


def test_otp_expired(monkeypatch):
    monkeypatch.setattr(appmod, "OTP_TTL", -1)
    r = create([{"email": "exp@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    client.get(f"/sign/{tok}")
    assert client.post(f"/sign/{tok}/otp", json={"code": last_code_for("exp@x.com")}).status_code == 410


# ------------------------------------------------------------ expiry and void


def test_expired_link_rejected(monkeypatch):
    monkeypatch.setattr(appmod, "LINK_TTL", -1)
    r = create([{"email": "late@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    assert client.get(f"/sign/{tok}").status_code == 410
    assert client.post(f"/sign/{tok}", json={"typed": "Late"}).status_code == 410


def test_void_blocks_signing():
    r = create([{"email": "v@x.com", "placements": []}])
    env_id, tok = r.json()["envelope_id"], token_of(r.json()["signing_links"][0])
    verify_identity(tok, "v@x.com")
    assert client.post(f"/envelopes/{env_id}/void", headers=H).json()["status"] == "voided"
    assert client.post(f"/sign/{tok}", json={"typed": "V"}).status_code == 410
    assert client.post(f"/envelopes/{env_id}/void", headers=H).status_code == 409
    ev = client.get(f"/envelopes/{env_id}", headers=H).json()["events"]
    assert ev[-1]["type"] == "voided"


# ------------------------------------------------------------ signing methods


def test_typed_signature_renders_png():
    png = core.render_typed_signature("Ada Lovelace")
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert png == core.render_typed_signature("Ada Lovelace")
    assert png != core.render_typed_signature("Bob")
    with pytest.raises(ValueError):
        core.render_typed_signature("   ")


def test_bad_png_rejected():
    r = create([{"email": "b@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    verify_identity(tok, "b@x.com")
    assert client.post(f"/sign/{tok}", json={"png": base64.b64encode(b"hello").decode()}).status_code == 422
    assert client.post(f"/sign/{tok}", json={"typed": " "}).status_code == 422


# ------------------------------------------------------------ webhooks


class Hook(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        n = int(self.headers["content-length"])
        Hook.received.append((self.headers.get("x-signet-signature"), self.rfile.read(n)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def hook_server():
    srv = HTTPServer(("127.0.0.1", 0), Hook)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/hook"
    srv.shutdown()


def test_two_signer_lifecycle_with_webhook(hook_server):
    r = create(
        [
            {"email": "a@x.com", "placements": [{"page": 0, "x": 0.1, "y": 0.8, "w": 0.3, "h": 0.06}]},
            {"email": "b@x.com", "placements": [{"page": 1, "x": 0.5, "y": 0.8, "w": 0.3, "h": 0.06}]},
        ],
        webhook_url=hook_server,
    )
    assert r.status_code == 200, r.text
    env = r.json()
    env_id, secret = env["envelope_id"], env["webhook_secret"]
    tok_a, tok_b = (token_of(l) for l in env["signing_links"])

    assert client.get(f"/envelopes/{env_id}/completed.pdf", headers=H).status_code == 404

    verify_identity(tok_a, "a@x.com")
    r = client.post(f"/sign/{tok_a}", json={"png": base64.b64encode(make_png()).decode()})
    assert r.json() == {"status": "signed", "remaining": 1}
    assert client.post(f"/sign/{tok_a}", json={"typed": "A"}).status_code == 409

    verify_identity(tok_b, "b@x.com")
    r = client.post(f"/sign/{tok_b}", json={"typed": "Bea Signer"})
    assert r.json() == {"status": "completed"}

    status = client.get(f"/envelopes/{env_id}", headers=H).json()
    assert status["status"] == "completed"
    types = [e["type"] for e in status["events"]]
    assert types == [
        "created",
        "viewed", "identity_challenged", "identity_verified", "viewed", "signed",
        "viewed", "identity_challenged", "identity_verified", "viewed", "signed",
        "completed",
    ]
    assert status["events"][5]["data"]["method"] == "drawn"
    assert status["events"][10]["data"]["method"] == "typed"

    # webhook was delivered with a valid HMAC
    assert len(status["webhook_deliveries"]) == 1 and status["webhook_deliveries"][0]["status"] == 200
    sig, payload = Hook.received[-1]
    assert sig == "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert json.loads(payload)["envelope_id"] == env_id

    # completion emails went to both
    assert {m.to for m in OUT.sent if m.subject.startswith("Completed")} >= {"a@x.com", "b@x.com"}

    pdf = client.get(f"/envelopes/{env_id}/completed.pdf", headers=H).content
    r = client.post("/verify", files={"file": ("c.pdf", pdf, "application/pdf")})
    assert r.status_code == 200 and r.json()["ok"], r.text
    keys = {k["key_id"]: k["public_key"] for k in client.get("/.well-known/signet-key").json()["keys"]}
    assert core.verify(pdf, keys).ok

    bad = pdf.replace(b"a@x.com", b"z@x.com", 1)
    r = client.post("/verify", files={"file": ("c.pdf", bad, "application/pdf")})
    assert r.status_code == 400 and not r.json()["ok"]


def test_webhook_failure_is_recorded_and_retried():
    r = create([{"email": "w@x.com", "placements": []}], webhook_url="http://127.0.0.1:9/nothing")
    env_id, tok = r.json()["envelope_id"], token_of(r.json()["signing_links"][0])
    verify_identity(tok, "w@x.com")
    assert client.post(f"/sign/{tok}", json={"typed": "W"}).json()["status"] == "completed"
    d = client.get(f"/envelopes/{env_id}", headers=H).json()["webhook_deliveries"]
    assert len(d) == 3 and all(x["status"] is None and x["error"] for x in d)


# ------------------------------------------------------------ key rotation


def test_key_rotation_keeps_old_docs_verifiable():
    r = create([{"email": "k@x.com", "placements": []}])
    env_id, tok = r.json()["envelope_id"], token_of(r.json()["signing_links"][0])
    verify_identity(tok, "k@x.com")
    client.post(f"/sign/{tok}", json={"typed": "K"})
    old_pdf = client.get(f"/envelopes/{env_id}/completed.pdf", headers=H).content
    old_kid = client.get("/.well-known/signet-key").json()["active_key_id"]

    new_kid = client.post("/keys/rotate", headers=H).json()["active_key_id"]
    assert new_kid != old_kid
    wk = client.get("/.well-known/signet-key").json()
    assert wk["active_key_id"] == new_kid and {k["key_id"] for k in wk["keys"]} >= {old_kid, new_kid}

    # old doc still verifies against the published key set, and reports its key id
    r = client.post("/verify", files={"file": ("c.pdf", old_pdf, "application/pdf")})
    assert r.json()["ok"] and r.json()["key_id"] == old_kid

    # new doc is sealed with the new key
    r = create([{"email": "k2@x.com", "placements": []}])
    env2, tok2 = r.json()["envelope_id"], token_of(r.json()["signing_links"][0])
    verify_identity(tok2, "k2@x.com")
    client.post(f"/sign/{tok2}", json={"typed": "K2"})
    pdf2 = client.get(f"/envelopes/{env2}/completed.pdf", headers=H).content
    assert core.verify(pdf2, {new_kid: wk["keys"][[k["key_id"] for k in wk["keys"]].index(new_kid)]["public_key"]}).ok
    assert not core.verify(pdf2, {old_kid: dict((k["key_id"], k["public_key"]) for k in wk["keys"])[old_kid]}).ok

    # keys survive a restart
    ring = appmod.load_keyring()
    assert ring.active_id == new_kid and set(ring.keys) >= {old_kid, new_kid}


# ------------------------------------------------------------ cron jobs


def test_expire_job_marks_and_logs(monkeypatch):
    from signet import jobs

    monkeypatch.setattr(appmod, "LINK_TTL", -1)
    r = create([{"email": "cron@x.com", "placements": []}])
    env_id = r.json()["envelope_id"]
    monkeypatch.setattr(appmod, "LINK_TTL", 3600)
    fresh = create([{"email": "cron2@x.com", "placements": []}]).json()["envelope_id"]
    assert jobs.expire() >= 1
    assert client.get(f"/envelopes/{env_id}", headers=H).json()["status"] == "expired"
    assert client.get(f"/envelopes/{env_id}", headers=H).json()["events"][-1]["type"] == "expired"
    assert client.get(f"/envelopes/{fresh}", headers=H).json()["status"] == "pending"
    assert jobs.expire() == 0


# ------------------------------------------------------------ security


def test_ssrf_blocked_when_private_webhooks_disallowed(monkeypatch):
    monkeypatch.setattr(appmod, "ALLOW_PRIVATE_WEBHOOKS", False)
    for url in ("http://127.0.0.1/x", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://user:pw@example.com/", "ftp://x/"):
        r = create([{"email": "s@x.com", "placements": []}], webhook_url=url)
        assert r.status_code == 422, url


def test_upload_size_limit(monkeypatch):
    monkeypatch.setattr(appmod, "MAX_UPLOAD", 100)
    r = create([{"email": "big@x.com", "placements": []}])
    assert r.status_code == 413


def test_placement_validation():
    bad = [
        [{"page": 5, "x": 0.1, "y": 0.1, "w": 0.1, "h": 0.1}],
        [{"page": 0, "x": 0.95, "y": 0.1, "w": 0.2, "h": 0.1}],
        [{"page": 0, "x": -1, "y": 0.1, "w": 0.1, "h": 0.1}],
        [{"page": 0, "x": 0.1, "y": 0.1, "w": 0, "h": 0.1}],
        [{"page": 0, "x": 0.1}],
    ]
    for pl in bad:
        assert create([{"email": "p@x.com", "placements": pl}]).status_code == 422, pl
    assert create([{"email": "p@x.com", "placements": [{"page": 1, "x": 0.1, "y": 0.1, "w": 0.2, "h": 0.1}]}]).status_code == 200


def test_signer_validation():
    assert create([{"email": "not-an-email", "placements": []}]).status_code == 422
    assert create([{"email": "a@x.com", "placements": []}, {"email": "A@x.com", "placements": []}]).status_code == 422


def test_refresh_does_not_resend_otp():
    r = create([{"email": "spam@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    client.get(f"/sign/{tok}")
    n = len([m for m in OUT.sent if m.to == "spam@x.com" and "code" in m.body])
    for _ in range(10):
        client.get(f"/sign/{tok}")
    assert len([m for m in OUT.sent if m.to == "spam@x.com" and "code" in m.body]) == n
    # but a locked-out signer gets a fresh code on reload
    for _ in range(5):
        client.post(f"/sign/{tok}/otp", json={"code": "000000"})
    client.get(f"/sign/{tok}")
    assert len([m for m in OUT.sent if m.to == "spam@x.com" and "code" in m.body]) == n + 1
    assert client.post(f"/sign/{tok}/otp", json={"code": last_code_for("spam@x.com")}).status_code == 200


def test_security_headers_on_sign_page():
    r = create([{"email": "h@x.com", "placements": []}])
    tok = token_of(r.json()["signing_links"][0])
    r = client.get(f"/sign/{tok}")
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_public_url_used_for_links(monkeypatch):
    monkeypatch.setattr(appmod, "PUBLIC_URL", "https://sign.example.com")
    r = create([{"email": "u@x.com", "placements": []}])
    assert r.json()["signing_links"][0]["url"].startswith("https://sign.example.com/sign/")
