#!/usr/bin/env python3
"""Verify a Signet-sealed PDF with no Signet code and no network.

Usage: python verify_offline.py completed.pdf <vendor_public_key_b64 | path/to/signet-key.json>
       (fetch the json from https://<vendor>/.well-known/signet-key and keep a copy you trust)
Deps:  pip install pypdf cryptography
"""
import base64, hashlib, json, sys
from pypdf import PdfReader
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def h(b): return hashlib.sha256(b).hexdigest()
def fail(msg): print("FAIL:", msg); sys.exit(1)

pdf_path, key_arg = sys.argv[1], sys.argv[2]
if key_arg.endswith(".json"):
    trusted = {k["key_id"]: k["public_key"] for k in json.load(open(key_arg))["keys"]}
else:
    trusted = {h(base64.b64decode(key_arg))[:16]: key_arg}
r = PdfReader(pdf_path)
att = {k: v[0] for k, v in r.attachments.items()}
rec = json.loads(att["signet-audit.json"])
pub_b64 = trusted.get(rec.get("key_id") or h(base64.b64decode(rec["public_key"]))[:16])

if h(att["signet-original.pdf"]) != rec["original_sha256"]: fail("original changed")
prev = "0" * 64
for i, ev in enumerate(rec["events"]):
    body = {k: ev[k] for k in ("seq", "ts", "type", "actor", "data")}
    if ev["prev_hash"] != prev or ev["hash"] != h(prev.encode() + canon(body)): fail(f"chain broken at {i}")
    if ev["type"] == "signed":
        if h(att[f"signet-signature-{ev['data']['signer_index']}.png"]) != ev["data"]["image_sha256"]: fail("signature image changed")
    prev = ev["hash"]
pages = [h(p.get_contents().get_data() if p.get_contents() is not None else b"") for p in r.pages]
if pages != rec["page_content_sha256"]: fail("visible pages edited after sealing")
if pub_b64 is None or rec["public_key"] != pub_b64: fail("document key is not a key you trust")
unsigned = {k: v for k, v in rec.items() if k != "signature"}
Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(rec["signature"]), canon(unsigned))
print("OK  envelope", rec["envelope_id"], "root", rec["root_hash"][:16])
for ev in rec["events"]:
    print(f"  {ev['ts']}  {ev['type']:<10} {ev['actor']}")
