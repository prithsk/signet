# Signet

Embedded e-signature API whose output proves itself. A completed PDF carries its original,
every signature image, and a hash-chained audit record sealed with an Ed25519 signature.
Anyone can verify it offline with `verify_offline.py` and the vendor public key. No account,
no API call, no trust in the vendor's database.

## Why this wedge

DocuSign sells trust in DocuSign. Signet sells a document that does not need it. That is the
moat: every sealed document is a public proof that only Signet's format provides, and the
verification script is 40 lines with two dependencies. Open source competitors (Documenso,
DocuSeal) have signing UIs but no self-contained verification story.

First customers: developers embedding signing in their own product, who today pay per envelope
and spend weeks on DocuSign's API.

## Run

```
pip install -r requirements.txt
SIGNET_DEV=1 uvicorn signet.app:app --reload          # local: weak key allowed, mail goes to stdout
```

Production refuses to start without a strong `SIGNET_APIKEY`. Set `SIGNET_PUBLIC_URL` to the
https origin signers will use, `SIGNET_MAIL=smtp` with `SMTP_HOST/PORT/USER/PASS/FROM`, and
put a TLS-terminating proxy in front. Uploads cap at 20 MB (`SIGNET_MAX_UPLOAD`). Webhook
URLs must be https and public; `SIGNET_ALLOW_PRIVATE_WEBHOOKS=1` relaxes that for local
testing only.

```
# create an envelope
curl -X POST localhost:8000/envelopes -H "x-api-key: dev" \
  -F file=@contract.pdf \
  -F 'signers=[{"email":"alice@x.com","placements":[{"page":0,"x":0.2,"y":0.7,"w":0.3,"h":0.06}]}]'
# send alice the returned signing link; when everyone signs:
curl localhost:8000/envelopes/<id>/completed.pdf -H "x-api-key: dev" -o done.pdf
# anyone can verify
curl localhost:8000/.well-known/signet-key
curl localhost:8000/.well-known/signet-key > keys.json
python verify_offline.py done.pdf keys.json
```

Placements are fractions of the page (x, y from top-left; w, h) so the same field works on
any page size.

## What is built

- Envelope API with API key, per-signer links, titles, link expiry, void
- Signer identity by email OTP (6 digits, 10 minute TTL, 5 attempts then lockout)
- Drawn or typed signatures, both flattened into the PDF
- Sealing: original, signature images, and hash-chained audit record attached and
  Ed25519-signed; certificate page appended
- Key ring with key IDs, `/keys/rotate`, old documents keep verifying
- `/verify` endpoint, `/.well-known/signet-key`, and `verify_offline.py` (no Signet code)
- Signed webhooks on completion (HMAC-SHA256 header, 3 attempts, deliveries logged)
- Email outbox: `SIGNET_MAIL=memory|log|smtp`
- Transparency log: every sealed root hash appended to a chained, public `/transparency.log`;
  `/verify` rejects a valid seal whose root is not in the log; `scripts/publish_transparency.sh`
  mirrors it to a public git repo and refuses to push if the log was rewritten
- In-app rate limits on envelope creation (per key), OTP attempts and verify (per IP)
- `/health`, nightly cron (expire, prune OTPs, check log chain, backup), Docker + Caddy TLS

## Verification signal

`pytest` runs 39 tests, and CI runs them on every push. The ones that matter:

- sealed PDF verifies with the right key and fails with the wrong one
- editing the audit record, swapping the original, swapping a signature image, drawing on a
  visible page after sealing, or stripping attachments each fail with a distinct reason
- a plain re-save with no edits still verifies (so the check is not brittle)
- full two-signer lifecycle over HTTP with OTP, drawn plus typed signatures, HMAC-verified
  webhook delivery, completion emails, then offline verification using the published key set
- signing before OTP is refused, wrong code is refused, five wrong codes lock the signer out,
  expired code and expired link are refused, voided envelopes cannot be signed
- key rotation: old documents still verify and report their key id, new ones use the new key,
  keys survive a restart
- failed webhook is retried three times and every attempt is recorded

Security tests: SSRF via webhook URL is refused, oversized uploads are refused, bad
placements are refused at creation instead of crashing at sealing, refreshing a signing
link does not re-mail the code, signing pages send anti-clickjacking headers, API key
comparison is constant-time, and the server will not boot with a weak key.

Two bugs the tests caught while building: pypdf's `ContentStream` is falsy when empty
(broke the offline verifier), and raising inside `with db()` rolled back the OTP attempt
counter (lockout never fired). Both are the reason the tests exist.

See `docs/AUDIT_SPEC.md` for exactly what is and is not proven.

## Deploy

```
cp .env.example .env    # fill in SIGNET_APIKEY, domain, SMTP
cd deploy && docker compose up -d --build
curl https://$SIGNET_DOMAIN/health
```

Caddy gets a TLS cert automatically and caps request bodies. Uvicorn trusts forwarded headers
only from the compose network, so audit IPs are the real client. The `cron` service runs the
nightly jobs against the same volume. On the host, add a cron line for
`scripts/publish_transparency.sh` so the log lives somewhere you cannot edit.

## Next signal

Five developers integrate against a hosted sandbox. Metric: minutes from API key to first
verified completed PDF. Failures in that hour are the roadmap.

## What this does not do yet, on purpose

Templates, field types beyond signature (date, initials, text), and a sender dashboard. Templates and dashboard wait for sandbox data: build what
five developers ask for, not what a feature list says. The log exists now; what is
missing is a second, independent mirror (an object store with versioning, or a
witness run by someone who is not you).

Nothing here is a claim of ESIGN or eIDAS compliance. Get a lawyer to read `AUDIT_SPEC.md`
before saying that word to a customer.

## Security posture, plainly

Threats handled: forged or edited documents (the seal), OTP brute force (lockout), mail
bombing through a signing link (single live code), SSRF through webhooks, oversized
uploads, clickjacking of the sign page, timing attacks on the API key.

Threats not handled: an attacker who reads the signer's email can sign as them (that is
true of every e-signature product using email OTP). A compromised server can still seal a
document, but not without appending to the public log, so forgery leaves evidence unless the
attacker also controls the mirror. Rate limits are per process; if you run more than one
replica, move them to Redis or the proxy.

## Maintenance this now requires

- `data/keys/*.pem` are the whole business. Back them up off the box. Never delete an old
  key; documents sealed with it stop verifying.
- SQLite stores full PDFs as blobs. Fine to a few GB. Move blobs to object storage before that.
- The page content hash depends on pypdf's content stream handling staying stable across
  versions. Pin pypdf, and add a fixture of a sealed PDF plus its expected hashes so an
  upgrade that changes behavior fails CI.
- Nightly jobs run in the `cron` container. Watch its logs for "TRANSPARENCY LOG BROKEN".
- Backups land in `/data/backups` inside the volume. Copy them off the box; a backup on the
  same disk as the thing it backs up is a wish, not a backup.
- The transparency mirror repo is now part of the product. If the publish script ever refuses
  to push, stop and find out why before anything else.
- Webhook delivery runs in-process. If the box restarts mid-delivery it is lost; the
  `webhook_deliveries` table shows the gap. Move to a queue once anyone depends on it.
- The OTP code goes over email in plain text. That is standard, but the mail provider
  becomes part of the trust chain. Say so in the spec when you write the compliance page.
