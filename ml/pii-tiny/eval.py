#!/usr/bin/env python3
"""Score predicted spans against gold spans.

    python3 eval.py --gold out/eval.jsonl --pred out/pred-b.jsonl

Both files are JSONL in the same order; each record has `text` and `spans`
([{start,end,label}]). Reported per label:
- exact P/R/F1: same start, end and label;
- masked recall: the share of gold spans whose every character is covered by some predicted
  span of any label. This is what the product needs (a masked name is safe even if the label
  is wrong or the span is wider);
- FP prompts: records without any gold span that receive a prediction (benign prompts the
  guard would rewrite), overall and for PERSON + ADDRESS only (the release gate; LOCATION is
  off by default in the product).
"""
from __future__ import annotations

import argparse
import json
from collections import Counter

LABELS = ("PERSON", "ADDRESS", "LOCATION")


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def covered(gold, preds) -> bool:
    chars = set(range(gold["start"], gold["end"]))
    for p in preds:
        chars -= set(range(p["start"], p["end"]))
        if not chars:
            return True
    return not chars


def score(gold_recs, pred_recs) -> dict:
    assert len(gold_recs) == len(pred_recs), "gold/pred length mismatch"
    tp, fp, fn, cov, tot = Counter(), Counter(), Counter(), Counter(), Counter()
    benign = benign_fp = benign_fp_core = 0
    for g, p in zip(gold_recs, pred_recs):
        assert g["text"] == p["text"], "gold/pred text mismatch"
        gs = {(s["start"], s["end"], s["label"]) for s in g["spans"]}
        ps = {(s["start"], s["end"], s["label"]) for s in p["spans"]}
        for s in gs:
            tot[s[2]] += 1
            if s in ps:
                tp[s[2]] += 1
            else:
                fn[s[2]] += 1
        for s in ps - gs:
            fp[s[2]] += 1
        for s in g["spans"]:
            if covered(s, p["spans"]):
                cov[s["label"]] += 1
        if not g["spans"]:
            benign += 1
            benign_fp += bool(p["spans"])
            benign_fp_core += any(x["label"] != "LOCATION" for x in p["spans"])
    out = {}
    for label in LABELS + ("ALL",):
        keys = LABELS if label == "ALL" else (label,)
        t, f_p, f_n = (sum(c[k] for k in keys) for c in (tp, fp, fn))
        n, c = sum(tot[k] for k in keys), sum(cov[k] for k in keys)
        prec = t / (t + f_p) if t + f_p else 0.0
        rec = t / (t + f_n) if t + f_n else 0.0
        out[label] = {
            "gold": n,
            "exact_p": round(prec, 4),
            "exact_r": round(rec, 4),
            "exact_f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "masked_recall": round(c / n, 4) if n else None,
        }
    out["benign_prompts"] = benign
    out["benign_fp_rate"] = round(benign_fp / benign, 4) if benign else None
    # LOCATION is off by default in Browser Guard; the release gate uses PERSON + ADDRESS.
    out["benign_fp_rate_core"] = round(benign_fp_core / benign, 4) if benign else None
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gold", required=True)
    ap.add_argument("--pred", required=True)
    args = ap.parse_args(argv)
    res = score(load(args.gold), load(args.pred))
    print(f"{'label':<9} {'gold':>6} {'P':>7} {'R':>7} {'F1':>7} {'masked R':>9}")
    for label in LABELS + ("ALL",):
        r = res[label]
        mr = "-" if r["masked_recall"] is None else f"{r['masked_recall']:.3f}"
        print(f"{label:<9} {r['gold']:>6} {r['exact_p']:>7.3f} {r['exact_r']:>7.3f} {r['exact_f1']:>7.3f} {mr:>9}")
    print(f"benign prompts: {res['benign_prompts']}, FP rate: {res['benign_fp_rate']} (PERSON+ADDRESS only: {res['benign_fp_rate_core']})")
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
