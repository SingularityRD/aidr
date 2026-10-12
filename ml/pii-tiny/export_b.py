#!/usr/bin/env python3
"""Export model B to ONNX (fp32 + dynamic int8) and check it against PyTorch.

    python3 export_b.py --model out/model-b --data out/eval.jsonl

Writes model.onnx, model.int8.onnx and vocab.json (words, chars, tags, max_chars, token regex
and the shape features' order) next to the checkpoint, then reports size, agreement of the
int8 model with PyTorch on real eval texts, and CPU latency per prompt.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from onnxruntime.quantization import QuantType, quantize_dynamic

from train_b import MAX_CHARS, TAGS, TOKEN, Tagger, Vocab, batchify, encode, load


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="out/model-b")
    ap.add_argument("--data", default="out/eval.jsonl")
    ap.add_argument("--n", type=int, default=300)
    args = ap.parse_args(argv)
    out = Path(args.model)
    ck = torch.load(out / "model.pt")
    vocab = Vocab(ck["words"], ck["chars"])
    model = Tagger(len(vocab.words), len(vocab.chars))
    model.load_state_dict(ck["state"])
    model.eval()

    recs = load(args.data)[: args.n]
    w, c, s, _ = batchify([encode(recs[0], vocab)])
    torch.onnx.export(
        model,
        (w, c, s),
        out / "model.onnx",
        input_names=["words", "chars", "shape"],
        output_names=["logits"],
        dynamic_axes={"words": {0: "b", 1: "t"}, "chars": {0: "b", 1: "t"}, "shape": {0: "b", 1: "t"}, "logits": {0: "b", 1: "t"}},
        opset_version=17,
        dynamo=False,
    )
    quantize_dynamic(str(out / "model.onnx"), str(out / "model.int8.onnx"), weight_type=QuantType.QInt8)
    (out / "vocab.json").write_text(
        json.dumps({"words": vocab.words, "chars": vocab.chars, "tags": TAGS, "maxChars": MAX_CHARS, "token": TOKEN.pattern}, ensure_ascii=False),
        encoding="utf-8",
    )

    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    sess = ort.InferenceSession(str(out / "model.int8.onnx"), so, providers=["CPUExecutionProvider"])
    agree = total = 0
    times = []
    with torch.no_grad():
        for r in recs:
            e = encode(r, vocab)
            if not e["wids"]:
                continue
            w, c, s, _ = batchify([e])
            ref = model(w, c, s).argmax(-1).numpy()
            t0 = time.perf_counter()
            got = sess.run(None, {"words": w.numpy(), "chars": c.numpy(), "shape": s.numpy()})[0].argmax(-1)
            times.append((time.perf_counter() - t0) * 1000)
            agree += int((ref == got).sum())
            total += ref.size
    for name in ("model.onnx", "model.int8.onnx", "vocab.json"):
        print(f"{name}: {(out / name).stat().st_size / 1e6:.2f} MB")
    times.sort()
    chars = sum(len(r["text"]) for r in recs) / len(recs)
    print(f"int8 vs torch tag agreement: {agree / total:.4f} over {total} tokens")
    print(f"latency (1 thread, avg {chars:.0f} chars/prompt): p50 {times[len(times) // 2]:.2f} ms, p95 {times[int(len(times) * 0.95)]:.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
