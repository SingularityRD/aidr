# Signed incident anchor receipts (local candidate)

`writeSignedIncidentAnchorReceipt` checks the SQLite incident snapshot, event index,
and local revision chain, then signs a SHA-256 digest of their ordered chain heads with an Ed25519
private key read from a **separate PEM file**. It creates a separate JSON receipt
with exclusive file creation (`wx`, mode `0600`) and never writes the private key
into the database or receipt. The receipt contains an explicit `scope` (tenant /
deployment / candidate), incident and revision counts, the aggregate head digest, a public-key
fingerprint, and host-generated creation time. Its Base64 payload is signed as
exact bytes so an independent verifier can check the signature without relying
on JSON key ordering.
New receipts include `head_order: "utf16"` so incident heads are sorted by stable
UTF-16 code units before hashing, independent of host locale. Earlier local
schema-v1 receipts omit this marker; verification retains their legacy locale
ordering for compatibility on the issuing host. Verify and re-anchor those
receipts on their original host before moving them to another locale.

On Windows, `0600` does not replace a reviewed NTFS ACL. The deployment must
restrict private-key and receipt access using the host's native access controls.

`verifySignedIncidentAnchorReceipt` needs only the SQLite path, the retained
receipt, a separately supplied Ed25519 public-key PEM file, and the expected
scope. It verifies the signature and key fingerprint before comparing the signed
counts and aggregate head digest with a fresh local store consistency check. A database rewrite
that recomputes every local SHA-256 hash changes the signed heads and yields
`anchor_state_mismatch` unless the signer key is compromised.
Verify against the same frozen snapshot used for signing; legitimate revisions
appended later also change the head digest and require a new receipt. An anchor
receipt is not a moving proof for a live, mutating database.

For any evidentiary use, keep the private key under separate access control and
retain the receipt and pinned public key outside the database host (for example,
in a controlled evidence archive). A same-host receipt can be deleted or rolled
back with the database; a stolen private key can sign a replacement. The host
clock is **not** a trusted timestamp. These APIs do not prove that every event
was captured, establish external WORM retention, protect against key compromise,
or provide independent forensic/production acceptance. Those gates remain open.

The incident SQLite backend uses optional `node:sqlite`; on runtimes without it,
the receipt writer cannot sign a locally verified SQLite store. A JSONL fallback
does not currently have equivalent signed receipts.
