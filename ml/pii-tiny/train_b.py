#!/usr/bin/env python3
"""Model B: a tiny from-scratch tagger (char-CNN + word embedding + shape features + BiLSTM).

    python3 train_b.py --train out/train.jsonl --dev out/eval.jsonl --out out/model-b
    python3 train_b.py --predict out/eval.jsonl --model out/model-b --pred out/pred-b.jsonl

Text is pre-tokenised by `tokenize` (letters / digits / single other characters); the same
rule is reimplemented in the browser runtime. Labels are BIO over PERSON, ADDRESS, LOCATION.
Word embeddings see only frequent non-entity words plus dropout, so the model must recognise
names from characters, shape and context rather than memorise the training pools.
"""
from __future__ import annotations

import argparse
import json
import math
import random
import re
import time
from collections import Counter
from pathlib import Path

import torch
from torch import nn

LABELS = ("PERSON", "ADDRESS", "LOCATION")
TAGS = ["O"] + [f"{p}-{l}" for l in LABELS for p in ("B", "I")]
TAG_ID = {t: i for i, t in enumerate(TAGS)}
TOKEN = re.compile(r"[^\W\d_]+|\d+|\S")
MAX_CHARS = 20
TR_LOWER = str.maketrans({"I": "ı", "İ": "i"})


def tokenize(text: str):
    return [(m.start(), m.end()) for m in TOKEN.finditer(text)]


def norm(word: str) -> str:
    return word.translate(TR_LOWER).lower()


def shape(word: str, prev: str, nxt: str) -> list[float]:
    alpha = word[0].isalpha()
    return [
        float(alpha and word[0].isupper()),
        float(alpha and word.isupper() and len(word) > 1),
        float(word.isdigit()),
        float(not alpha and not word.isdigit()),
        float(nxt == "'" or nxt == "’"),
        float(prev in (".", "!", "?", "\n", "") ),
        float(prev == ":" or prev == "="),
        float(len(word) == 1),
    ]


N_SHAPE = 8


def featurize(text: str):
    toks = tokenize(text)
    words = [text[a:b] for a, b in toks]
    feats = []
    for i, w in enumerate(words):
        prev = words[i - 1] if i else ""
        if i and "\n" in text[toks[i - 1][1] : toks[i][0]]:
            prev = "\n"
        nxt = words[i + 1] if i + 1 < len(words) else ""
        feats.append(shape(w, prev, nxt))
    return toks, words, feats


def bio(toks, spans):
    tags = ["O"] * len(toks)
    for s in spans:
        first = True
        for i, (a, b) in enumerate(toks):
            if a >= s["start"] and b <= s["end"]:
                tags[i] = ("B-" if first else "I-") + s["label"]
                first = False
    return tags


class Vocab:
    def __init__(self, words=None, chars=None):
        self.words = words or ["<pad>", "<unk>"]
        self.chars = chars or ["<pad>", "<unk>"]
        self.w = {x: i for i, x in enumerate(self.words)}
        self.c = {x: i for i, x in enumerate(self.chars)}

    @classmethod
    def build(cls, records, max_words=30000, min_count=3):
        wc, cc = Counter(), Counter()
        for r in records:
            toks, words, _ = featurize(r["text"])
            tags = bio(toks, r["spans"])
            for w, t in zip(words, tags):
                cc.update(w)
                if t == "O":  # entity tokens never enter the word vocabulary
                    wc[norm(w)] += 1
        words = ["<pad>", "<unk>"] + [w for w, n in wc.most_common(max_words) if n >= min_count]
        chars = ["<pad>", "<unk>"] + [c for c, n in cc.most_common() if n >= 2]
        return cls(words, chars)

    def word_id(self, w):
        return self.w.get(norm(w), 1)

    def char_ids(self, w):
        w = w[:MAX_CHARS]
        return [self.c.get(ch, 1) for ch in w] + [0] * (MAX_CHARS - len(w))


class Tagger(nn.Module):
    def __init__(self, n_words, n_chars, wdim=64, cdim=32, cfilters=64, hidden=128):
        super().__init__()
        self.wemb = nn.Embedding(n_words, wdim, padding_idx=0)
        self.cemb = nn.Embedding(n_chars, cdim, padding_idx=0)
        self.conv = nn.Conv1d(cdim, cfilters, kernel_size=3, padding=1)
        self.drop = nn.Dropout(0.25)
        self.lstm = nn.LSTM(wdim + cfilters + N_SHAPE, hidden, num_layers=2, bidirectional=True, batch_first=True, dropout=0.25)
        self.out = nn.Linear(2 * hidden, len(TAGS))

    def forward(self, wids, cids, shp):
        b, t, _ = cids.shape
        c = self.cemb(cids.view(b * t, MAX_CHARS)).transpose(1, 2)
        c = torch.relu(self.conv(c)).max(dim=2).values.view(b, t, -1)
        x = torch.cat([self.wemb(wids), c, shp], dim=-1)
        h, _ = self.lstm(self.drop(x))
        return self.out(self.drop(h))


def encode(rec, vocab, train=False, wdrop=0.0):
    toks, words, feats = featurize(rec["text"])
    wids = [vocab.word_id(w) for w in words]
    if train and wdrop:
        wids = [1 if random.random() < wdrop else i for i in wids]
    return {
        "toks": toks,
        "wids": wids,
        "cids": [vocab.char_ids(w) for w in words],
        "shp": feats,
        "tags": [TAG_ID[t] for t in bio(toks, rec.get("spans", []))],
    }


def batchify(items):
    n = max(1, max(len(x["wids"]) for x in items))
    w = torch.zeros(len(items), n, dtype=torch.long)
    c = torch.zeros(len(items), n, MAX_CHARS, dtype=torch.long)
    s = torch.zeros(len(items), n, N_SHAPE)
    y = torch.full((len(items), n), -100, dtype=torch.long)
    for i, x in enumerate(items):
        k = len(x["wids"])
        if not k:
            continue
        w[i, :k] = torch.tensor(x["wids"])
        c[i, :k] = torch.tensor(x["cids"])
        s[i, :k] = torch.tensor(x["shp"])
        y[i, :k] = torch.tensor(x["tags"])
    return w, c, s, y


def decode(toks, tag_ids):
    """BIO (tolerant: an I- without B- starts a span) -> char spans."""
    spans, cur = [], None
    for (a, b), t in zip(toks, tag_ids):
        tag = TAGS[t]
        if tag == "O":
            cur = None
            continue
        kind, label = tag.split("-", 1)
        if kind == "B" or cur is None or cur["label"] != label:
            cur = {"start": a, "end": b, "label": label}
            spans.append(cur)
        else:
            cur["end"] = b
    return spans


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def predict(model, vocab, records, bs=64):
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(records), bs):
            chunk = records[i : i + bs]
            enc = [encode(r, vocab) for r in chunk]
            w, c, s, _ = batchify(enc)
            pred = model(w, c, s).argmax(-1).tolist()
            for r, e, p in zip(chunk, enc, pred):
                out.append({"text": r["text"], "spans": decode(e["toks"], p[: len(e["toks"])])})
    return out


def train(args):
    torch.set_num_threads(args.threads)
    random.seed(1729)
    torch.manual_seed(1729)
    recs = load(args.train)
    dev = load(args.dev)[: args.dev_limit]
    vocab = Vocab.build(recs)
    model = Tagger(len(vocab.words), len(vocab.chars))
    print(f"vocab words={len(vocab.words)} chars={len(vocab.chars)} params={sum(p.numel() for p in model.parameters()):,}")
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    weights = torch.ones(len(TAGS))
    weights[0] = 0.5  # O is the vast majority
    lossf = nn.CrossEntropyLoss(weight=weights, ignore_index=-100)
    steps = math.ceil(len(recs) / args.bs) * args.epochs
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=args.lr, total_steps=steps, pct_start=0.1)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    step, t0 = 0, time.time()
    from eval import score  # local module

    for epoch in range(args.epochs):
        model.train()
        order = list(range(len(recs)))
        random.shuffle(order)
        # Bucket by length for speed.
        order.sort(key=lambda i: len(recs[i]["text"]) // 200 + random.random())
        batches = [order[i : i + args.bs] for i in range(0, len(order), args.bs)]
        random.shuffle(batches)
        for bidx in batches:
            w, c, s, y = batchify([encode(recs[i], vocab, train=True, wdrop=args.wdrop) for i in bidx])
            loss = lossf(model(w, c, s).reshape(-1, len(TAGS)), y.reshape(-1))
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            step += 1
            if step % 200 == 0:
                print(f"epoch {epoch} step {step}/{steps} loss {loss.item():.4f} {time.time() - t0:.0f}s", flush=True)
        res = score(dev, predict(model, vocab, dev))
        print(f"epoch {epoch} dev: " + json.dumps({k: res[k] for k in ("ALL", "PERSON")}) + f" benign_fp={res['benign_fp_rate']}", flush=True)
        torch.save({"state": model.state_dict(), "words": vocab.words, "chars": vocab.chars}, out / "model.pt")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--train")
    ap.add_argument("--dev")
    ap.add_argument("--out", default="out/model-b")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--bs", type=int, default=32)
    ap.add_argument("--lr", type=float, default=3e-3)
    ap.add_argument("--wdrop", type=float, default=0.15)
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--dev-limit", type=int, default=3000)
    ap.add_argument("--predict")
    ap.add_argument("--model")
    ap.add_argument("--pred")
    args = ap.parse_args(argv)
    if args.predict:
        ck = torch.load(Path(args.model) / "model.pt")
        vocab = Vocab(ck["words"], ck["chars"])
        model = Tagger(len(vocab.words), len(vocab.chars))
        model.load_state_dict(ck["state"])
        with open(args.pred, "w", encoding="utf-8") as fh:
            for r in predict(model, vocab, load(args.predict)):
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        return 0
    train(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
