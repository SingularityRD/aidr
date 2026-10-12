#!/usr/bin/env python3
"""Write the TypeScript featurizer parity fixture.

    python3 tools/parity_fixture.py --model out/model-b-v2 --texts out/eval.jsonl \
        --out ../../packages/browser-guard/src/__tests__/fixtures/ner-featurize-parity.json

The fixture holds a reduced vocabulary (so it stays small), a set of real eval prompts plus
Unicode edge cases, and for each prompt the SHA-256 of its features serialised as compact JSON
({"tokens","words","chars","shape"}, integers only). The browser test recomputes the same
digest with engine/ner/featurize.ts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from train_b import GAZ_KEYS, MAX_CHARS, Vocab, encode, load, load_model  # noqa: E402

EDGE = [
    "İSTANBUL'da IŞIK ve ılık; İzmir'deki Iğdır",
    "Ayşe 😀 Kaya 👩‍💻 dün geldi",
    "x² + y³ = 10 and Ⅻ chapters, ٣٤٥ items, ５５５",
    "été café — naïve Zoë",
    "a_b c_d __init__ snake_case",
    "\tTab\nNew line\r\nCRLF\n\nDouble",
    "'quoted' “curly” ‘single’ Ahmet’in Okan'a",
    "ALLCAPS lower MiXeD single A b I ı İ i",
    "",
    "   ",
    "John O'Brien-Smith; Mary-Jane McDonald",
]


def digest(e) -> str:
    payload = {
        "tokens": [list(t) for t in e["toks"]],
        "words": e["wids"],
        "chars": [c for row in e["cids"] for c in row],
        "shape": [int(x) for row in e["shp"] for x in row],
    }
    return hashlib.sha256(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--texts", required=True)
    ap.add_argument("--n", type=int, default=250)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    _, full = load_model(args.model)
    rng = random.Random(7)
    texts = [r["text"] for r in rng.sample(load(args.texts), args.n)] + EDGE
    # Reduced vocabulary: every word/char the fixture texts use, plus distractor-free filler.
    keep_words = set()
    for t in texts:
        from train_b import featurize, norm

        _, words, _ = featurize(t)
        keep_words |= {norm(w) for w in words}
    words = ["<pad>", "<unk>"] + [w for w in full.words[2:] if w in keep_words]
    words = words[: 2 + 3000]
    gaz = {k: sorted(v for v in full.gaz[k] if v in keep_words or rng.random() < 0.05) for k in GAZ_KEYS} if full.gaz else None
    vocab = Vocab(words, full.chars, {k: set(v) for k, v in gaz.items()} if gaz else None)
    cases = [{"text": t, "sha256": digest(encode({"text": t, "spans": []}, vocab))} for t in texts]
    fixture = {
        "vocab": {"words": words, "chars": full.chars, "tags": [], "maxChars": MAX_CHARS, "gazetteer": gaz},
        "cases": cases,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(fixture, ensure_ascii=False), encoding="utf-8")
    print(f"{len(cases)} cases, {len(words)} words -> {args.out} ({Path(args.out).stat().st_size / 1e3:.0f} kB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
