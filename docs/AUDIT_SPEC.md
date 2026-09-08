# Signet audit and verification spec (v1.1)

Goal: a completed PDF proves itself. Anyone with the vendor public key can verify it
offline with pypdf and cryptography. No vendor API call, no account.

## What a completed PDF contains

1. Visible pages: the original pages with signature images drawn on them, plus one
   certificate page listing signers, times, and the chain root hash.
2. Attachment `signet-original.pdf`: the untouched uploaded document.
3. Attachment `signet-signature-<n>.png`: each captured signature image.
4. Attachment `signet-audit.json`: the audit record below.

## Audit record

```
{
  "version": 1,
  "envelope_id": "...",
  "original_sha256": "<sha256 of signet-original.pdf>",
  "events": [ {seq, ts, type, actor, data, prev_hash, hash}, ... ],
  "page_content_sha256": ["<sha256 of page 1 content stream>", ...],
  "root_hash": "<hash of last event>",
  "signed_at": "...",
  "signature": "<base64 ed25519 signature over canonical(record without signature)>",
  "public_key": "<base64 raw ed25519 public key>",
  "key_id": "<first 16 hex of sha256(raw public key)>"
}
```

Each event hash is `sha256(prev_hash + canonical_json({seq, ts, type, actor, data}))`.
The first event has `prev_hash` = 64 zero characters. Canonical JSON means sorted keys,
no whitespace, UTF-8.

Event types: `created`, `viewed`, `identity_challenged`, `identity_verified`, `signed`,
`completed`, `voided`, `expired`. A `signed` event carries the signer index, `method`
(`drawn` or `typed`), the field placements, and `image_sha256` of the signature PNG.
An `identity_verified` event carries `method` (`email_otp` today) and the source IP.

## Verifier checks, in order

1. Extract the four attachment kinds. Missing any: FAIL.
2. sha256(original attachment) == original_sha256. Else FAIL.
3. For each `signed` event, sha256 of the matching PNG == image_sha256. Else FAIL.
4. Recompute every event hash from seq 0. Any mismatch: FAIL.
5. Recompute sha256 of each visible page content stream, compare to
   page_content_sha256. Else FAIL (visible content edited after sealing).
6. Look up `key_id` in the trusted key set fetched earlier from
   `/.well-known/signet-key`, confirm the embedded `public_key` matches that entry,
   then Ed25519 verify `signature` over canonical(record minus signature). The key
   inside the PDF is informational only; it must match a key already trusted. Else FAIL.

Any FAIL is final. There is no partial pass.

## What this does not claim

It proves that whoever held the signing link also controlled the signer's email inbox
at `identity_verified` time, produced this image at `signed` time, and that nothing
changed afterward. It does not prove a legal identity. Stronger checks (SMS, ID document)
would add new `identity_verified` methods without changing the format.

## Known limits of v1

- Keys rotate and old keys stay published, but there is no transparency log yet. Until
  root hashes are published somewhere the vendor cannot rewrite, a vendor with the key
  could forge a document. That log is what makes this trustless.
- Page content stream hashing catches content edits but not changes to fonts or
  resources referenced by the page. v2 should hash the full page object graph.
