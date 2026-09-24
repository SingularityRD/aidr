# Architecture and threat model

## Data flow

```text
Authenticated AIDR boundary + destination authorization (external)
  -> complete text or bounded UTF-8 / JSON message
  -> input limits + Unicode validity
  -> normalized and explicitly decoded detection views, with original-offset maps
  -> TR/EN structural rules + check digits + field context + bounded literal dictionary
  -> optional approved local NER process over bounded stdin/stdout IPC
  -> validate all spans + evaluate all policies
  -> union overlaps + label / redact / HMAC replacements
  -> allow or redact: safe-to-forward decision within detector coverage
  -> block or review: output = null, caller sends nothing
```

The module never makes an HTTP call. It imports `node:net` only for local IP address validation. It does not start a socket server. The optional provider starts an approved local subprocess; isolation and actual networking restrictions belong to the host.

## Offsets and Unicode

Findings refer to half-open `[start,end)` UTF-16 code-unit ranges in the ORIGINAL JavaScript string. Directly applying Python code-point offsets to a JS string is incorrect for supplementary characters. The worker converts offsets explicitly. The engine rejects spans that bisect surrogate pairs.

Normalization uses NFKC, selected Unicode digit folding and format-character removal. Grapheme segmentation maps expansions and compositions to the complete original cluster. A fast path applies only to NFKC-stable ASCII/basic Turkish characters. Explicit percent, selected HTML, Unicode/hex escape and `[at]`/`[dot]` decoding retains source maps. Up to three decoding passes are allowed; deeper changing encodings are denied. Some percent-encoded runs are conservatively masked as a whole.

The implementation does not claim full Unicode spoof/confusable coverage. Bidi policy is additional blocking, not a visual reordering engine.

## Detection and policy

Structured identifiers use deterministic checks when supported. Explicitly labeled fields and schema keys are still considered sensitive if malformed. Contextual names and street patterns supplement rules but must not be marketed as learned entity recognition. The optional NER interface can add PERSON, ADDRESS and other canonical types.

Findings are bounded. Overflow blocks instead of truncating findings. Model output requires `complete:true`; missing completion, bad spans/types/scores, invalid encoding, crashes or timeouts deny the request. A defense configuration also checks PERSON/ADDRESS separately for both languages. Low-confidence predicted entities are not silently discarded.

A model returning no entities can still be wrong. There is no classifier-independent proof that an empty result means safe content. Independent quality evaluation and destination controls remain essential.

## Overlap and redaction

All overlapping intervals are unioned so no lower-priority tail survives. A priority chooses the displayed label only. Policies evaluate every raw finding before merging: a block cannot be hidden by a wider lower-priority redaction. Label/redact modes reveal no last-four digits or original length. They can over-redact useful information by design.

The HMAC tuple binds a domain string, tenant, key ID, entity type and canonicalized value. No plain hashes or reversible mappings are stored. Canonicalization is specific to supported identifiers, not a general multilingual equivalence relation. Encoded variants can produce different tokens despite being fully redacted.

## Structured data and streaming

The strict JSON parser detects duplicate decoded keys and dangerous prototype property names before processing values. Depth, nodes, input length and unsafe numeric values are bounded. Keys are also inspected; sensitive content in a key blocks rather than creating an ambiguous renamed key. Marked fields can be replaced wholesale, including subtrees. Downstream schemas must be revalidated.

`AtomicTextGate.push()` only copies into bounded local buffers. `finish()` decodes the complete UTF-8 message and runs the policy. This prevents a secret split across byte chunks from being emitted before recognition. It is not a low-latency incremental redaction transducer and does not correlate independent messages or reassembled semantic fragments across JSON fields.

## Trust boundaries

Untrusted: text, JSON fields/keys, tool arguments, model responses, raw byte chunks.

Administrator-trusted: tenant binding, policies/dictionaries, approved command/model paths, artifact digest, external destination authorization, OS network restrictions.

The TypeScript process and Python executable/dependencies are trusted computing base. A malicious in-process NerProvider is arbitrary code and cannot be sandboxed by a TypeScript interface. Prefer the local process provider with explicit host restrictions.
