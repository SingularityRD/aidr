# aidr-pii-tiny — small in-browser TR/EN PII model

The rule layer (`packages/privacy/src/detectors.ts`) already catches everything with a
checksum or a shape: e-mail, phone, TCKN, VKN, IBAN, cards, secrets. What it cannot see is
free-text **PERSON**, **ADDRESS** and **LOCATION** — `Müşterimiz Ayşe Demir dün aradı` leaks
today (free-text name recall 10% on `packages/browser-guard/src/__tests__/pii-quality-corpus.test.ts`).
This model covers exactly those three labels and runs next to the rules inside Browser Guard.

## Targets (release gate)

| Metric (held-out eval set, unseen names) | Gate |
|---|---|
| PERSON span recall (exact or covering) | ≥ 95% |
| ADDRESS / LOCATION recall | ≥ 90% |
| False-positive rate on slot-free / hard-negative prompts | ≤ 2% of prompts |
| Model size shipped in the extension | ≤ 40 MB (int8 ONNX) |
| Latency, 2 KB prompt, CPU WASM, 4-core laptop | ≤ 150 ms p95 |
| Free-text name cases in `pii-quality-corpus.test.ts` | all masked |

A model that misses a gate is not shipped; the rules-only path stays the default.

## Data

Templates are written by language-model authors per `data/TEMPLATE_SPEC.md` (realistic prompts
with `{PERSON1}`-style slots, hard negatives, Turkish suffixes) across ten domain groups, plus two
**independently authored** evaluation sets in `data/eval/` that the training authors never saw.
`gen.py` fills slots from `data/pools/`, inflects Turkish case suffixes (outside the span, as
the product masks them), and adds whole-text typing variants (no Turkish characters,
lower-case). Every pool is split by hash: 15% of names, streets and places appear **only** in
evaluation, so the eval measures generalisation to unseen values, not memorisation.

```bash
python3 gen.py --split train --per-template 40 --out out/train.jsonl
python3 gen.py --split eval  --per-template 10 --out out/eval.jsonl
```

## Models compared

- **A — pretrained student (primary):** a small multilingual encoder, vocabulary pruned to the
  TR+EN tokens seen in the corpus, fine-tuned for BIO token classification, exported to ONNX
  and int8-quantised. Needs `huggingface.co` for the base weights.
- **B — from-scratch tiny model (fallback/baseline):** character + subword features, trained
  only on the generated corpus; a few MB.

Both are scored by the same `eval.py` on the same held-out set; the numbers decide.

## Runtime (Browser Guard)

ONNX Runtime Web (WASM, WebGPU when available) in the extension's offscreen document; model
spans are mapped back to source offsets and merged with rule spans by `mergeFindings`. If the
model is unavailable the guard reports rules-only coverage visibly; `requireNativeNer`-style
policy can make that fail closed.
