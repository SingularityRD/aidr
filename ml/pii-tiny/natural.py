#!/usr/bin/env python3
"""Turn inline-annotated natural prompts (`[[P:...]]`, see data/TEMPLATE_SPEC.md) into span JSONL.

    python3 natural.py --src data/natural --variants 6 --out out/natural.jsonl          # training
    python3 natural.py --src data/natural-eval --variants 0 --out out/natural-eval.jsonl # evaluation

Training records are augmented: every PERSON value is swapped for a pool name of the same shape
(single given name, full name, lower-case, ALL CAPS, no Turkish characters), consistently within
the prompt, and a Turkish case suffix written right after it is re-inflected for the new name
("Okan'a" -> "Ayşe'ye"). A prompt whose suffix after a name is not one we can re-inflect keeps
its original names only, so no ungrammatical variant is produced.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

from gen import ASCII, Pools, name_of, suffix, tr_lower, tr_upper

MARK = re.compile(r"\[\[([PAL]):([^\[\]]+)\]\]")
LABEL = {"P": "PERSON", "A": "ADDRESS", "L": "LOCATION"}
# Apostrophe + one case suffix as written after a name, mapped back to its case.
CASE_OF = [
    (re.compile(r"^['’](?:n?[ıiuü]n)(?![\w])", re.I), "GEN"),
    (re.compile(r"^['’](?:y?[ae])(?![\w])", re.I), "DAT"),
    (re.compile(r"^['’](?:[dt][ae]n)(?![\w])", re.I), "ABL"),
    (re.compile(r"^['’](?:[dt][ae])(?![\w])", re.I), "LOC"),
    (re.compile(r"^['’](?:y?l[ae])(?![\w])", re.I), "INS"),
    (re.compile(r"^['’](?:l[ae]r)(?![\w])", re.I), "PLU"),
    (re.compile(r"^['’](?:y?[ıiuü])(?![\w])", re.I), "ACC"),
]


def parse(text: str) -> tuple[str, list[dict]]:
    out, spans, pos = [], [], 0
    n = 0
    for m in MARK.finditer(text):
        out.append(text[pos : m.start()])
        n += m.start() - pos
        value = m.group(2)
        spans.append({"start": n, "end": n + len(value), "label": LABEL[m.group(1)]})
        out.append(value)
        n += len(value)
        pos = m.end()
    out.append(text[pos:])
    plain = "".join(out)
    if "[[" in plain or "]]" in plain:
        raise ValueError("unbalanced marker")
    return plain, spans


def style(value: str) -> str:
    if value.isupper() and any(c.isalpha() for c in value):
        return "upper"
    if value == tr_lower(value):
        return "ascii-lower" if value == value.translate(ASCII) and re.search("[a-z]", value) else "lower"
    return "title"


def apply_style(value: str, kind: str, turkish: bool) -> str:
    """Case of the original value; only Turkish spelling maps i <-> İ and ı <-> I."""
    if kind == "upper":
        return tr_upper(value) if turkish else value.upper()
    if kind == "lower":
        return tr_lower(value) if turkish else value.lower()
    if kind == "ascii-lower":
        return (tr_lower(value) if turkish else value.lower()).translate(ASCII)
    return value


def new_name(original: str, pools: Pools, rng: random.Random) -> str | None:
    words = original.replace(".", ". ").split()
    if not words or len(words) > 4 or any(not re.fullmatch(r"[\w'’.-]+", w) for w in words):
        return None  # handles, e-mail-like user names, odd tokens: keep the original
    tr = rng.random() < 0.6
    firsts = pools.tr_first if tr else pools.en_first
    lasts = pools.tr_last if tr else pools.en_last
    if len(words) == 1:
        v = name_of(rng.choice(firsts)) if rng.random() < 0.7 else rng.choice(lasts)
    elif len(words) == 2 and words[0].endswith("."):
        v = f"{name_of(rng.choice(firsts))[0]}. {rng.choice(lasts)}"
    else:
        given = [name_of(rng.choice(firsts)) for _ in range(len(words) - 1)]
        v = " ".join(given + [rng.choice(lasts)])
    return apply_style(v, style(original), tr)


def variant(plain: str, spans: list[dict], pools: Pools, rng: random.Random) -> dict | None:
    mapping: dict[str, str] = {}
    out, new_spans, pos, n = [], [], 0, 0
    for s in spans:
        out.append(plain[pos : s["start"]])
        n += s["start"] - pos
        value = plain[s["start"] : s["end"]]
        rest = plain[s["end"] :]
        if s["label"] == "PERSON":
            if value not in mapping:
                repl = new_name(value, pools, rng)
                if repl is None:
                    return None
                mapping[value] = repl
            repl = mapping[value]
        else:
            repl = value
        out.append(repl)
        new_spans.append({"start": n, "end": n + len(repl), "label": s["label"]})
        n += len(repl)
        pos = s["end"]
        if s["label"] == "PERSON" and rest[:1].isalpha():
            return None  # "Kerim'cim" typed as "Kerimcim": a swapped name would get the wrong harmony
        if s["label"] == "PERSON" and rest[:1] in ("'", "’"):
            hit = next(((c, m) for rx, c in CASE_OF if (m := rx.match(rest))), None)
            if hit is None:
                return None
            case, m = hit
            sfx = suffix(repl.split()[-1], case)
            if rest[0] == "’":
                sfx = "’" + sfx[1:]
            out.append(sfx)
            n += len(sfx)
            pos = s["end"] + m.end()
    out.append(plain[pos:])
    return {"text": "".join(out), "spans": new_spans}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--variants", type=int, default=6)
    ap.add_argument("--seed", type=int, default=4242)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    rng = random.Random(args.seed)
    pools = Pools("train") if args.variants else None
    n_src = n_out = n_bad = 0
    with open(args.out, "w", encoding="utf-8") as fh:
        for path in sorted(Path(args.src).glob("*.jsonl")):
            for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
                if not line.strip():
                    continue
                d = json.loads(line)
                try:
                    plain, spans = parse(d["text"])
                except ValueError:
                    n_bad += 1
                    continue
                n_src += 1
                meta = {"lang": d.get("lang", ""), "domain": d.get("domain", ""), "template": f"{path.stem}:{i}"}
                fh.write(json.dumps({"text": plain, "spans": spans, **meta}, ensure_ascii=False) + "\n")
                n_out += 1
                if not spans:
                    continue
                for _ in range(args.variants):
                    v = variant(plain, spans, pools, rng)
                    if v is None:
                        break
                    fh.write(json.dumps({**v, **meta}, ensure_ascii=False) + "\n")
                    n_out += 1
    print(f"{args.src}: {n_src} prompts ({n_bad} skipped: bad markers) -> {n_out} records -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
