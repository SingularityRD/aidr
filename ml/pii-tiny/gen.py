#!/usr/bin/env python3
"""Fill PII templates (data/TEMPLATE_SPEC.md) from value pools into span-labelled JSONL.

    python3 gen.py --split train --per-template 40 --out out/train.jsonl
    python3 gen.py --split eval  --per-template 10 --out out/eval.jsonl

Pools are split deterministically by value hash: 85% of every pool is used for training and
the other 15% only for evaluation, so the eval set measures recall on names, streets and
places the model has never seen. Turkish case suffixes are inflected with vowel harmony and
consonant assimilation and stay OUTSIDE the labelled span, as the product masks them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
POOLS = HERE / "data" / "pools"
LABELS = ("PERSON", "ADDRESS", "LOCATION")
SLOT = re.compile(r"\{(PERSON|ADDRESS|LOCATION)([0-9]+)(?:\.([a-z_0-9]+))?(?:\+(GEN|DAT|ACC|LOC|ABL|INS|PLU))?\}")
# Distractor slot: a capitalised non-personal name, filled from pools/distractors.json, labelled O.
NEG_KINDS = ("tech", "ai", "org", "brand", "institution", "law", "eponym", "place", "media", "club", "word")
ANY_SLOT = re.compile(
    r"\{(?:(PERSON|ADDRESS|LOCATION)([0-9]+)(?:\.([a-z_0-9]+))?|NEG:(" + "|".join(NEG_KINDS) + r"))(?:\+(GEN|DAT|ACC|LOC|ABL|INS|PLU))?\}"
)

# ---------------------------------------------------------------- Turkish orthography

TR_UPPER = str.maketrans({"i": "İ", "ı": "I"})
TR_LOWER = str.maketrans({"I": "ı", "İ": "i"})
ASCII = str.maketrans("çğıöşüÇĞİÖŞÜâîûÂÎÛ", "cgiosuCGIOSUaiuAIU")  # 1:1, offsets preserved
BACK, FRONT = set("aıou"), set("eiöü")
VOWELS = BACK | FRONT | set("âîû")
VOICELESS = set("fstkçşhp")


def tr_upper(s: str) -> str:
    return s.translate(TR_UPPER).upper()


def tr_lower(s: str) -> str:
    return s.translate(TR_LOWER).lower()


def last_vowel(word: str) -> str:
    for ch in reversed(tr_lower(word)):
        if ch in VOWELS:
            return {"â": "a", "î": "i", "û": "u"}.get(ch, ch)
    return "e"  # acronyms / no vowel: Turkish reads them with a front vowel by default


def suffix(word: str, case: str) -> str:
    """Apostrophe + suffix for a proper noun, e.g. ("Ahmet","DAT") -> "'e"."""
    low = tr_lower(word.rstrip("."))
    v = last_vowel(low)
    a = "a" if v in BACK else "e"
    i4 = {"a": "ı", "ı": "ı", "o": "u", "u": "u", "e": "i", "i": "i", "ö": "ü", "ü": "ü"}[v]
    ends_vowel = bool(low) and low[-1] in VOWELS
    hard = bool(low) and low[-1] in VOICELESS
    d = "t" if hard else "d"
    out = {
        "GEN": ("n" if ends_vowel else "") + i4 + "n",
        "DAT": ("y" if ends_vowel else "") + a,
        "ACC": ("y" if ends_vowel else "") + i4,
        "LOC": d + a,
        "ABL": d + a + "n",
        "INS": ("y" if ends_vowel else "") + "l" + a,
        "PLU": "l" + a + "r",
    }[case]
    if word.isupper() and any(c.isalpha() for c in word):
        out = tr_upper(out)
    return "'" + out


# ---------------------------------------------------------------- pools


def _held_out(value: str) -> bool:
    return hashlib.sha256(value.encode()).digest()[0] < 39  # ~15%


class Pools:
    def __init__(self, split: str):
        self.split = split

        def load(name):
            return json.loads((POOLS / name).read_text(encoding="utf-8"))

        def pick(items, key=lambda x: x):
            keep = [x for x in items if _held_out(key(x)) == (split == "eval")]
            if not keep:
                raise SystemExit(f"empty {split} pool")
            return keep

        name_of = lambda x: x["name"] if isinstance(x, dict) else x  # noqa: E731
        self.tr_first = pick(load("tr_first_names.json"), name_of)
        self.tr_last = pick(load("tr_surnames.json"))
        self.en_first = pick(load("en_first_names.json"), name_of)
        self.en_last = pick(load("en_surnames.json"))
        self.other = pick(load("other_names.json"), lambda x: x["first"] + " " + x["last"])
        tr = load("tr_places.json")
        self.provinces = tr["provinces"]  # tiny closed set: shared by both splits
        self.districts = pick(tr["districts"], lambda x: x["district"])
        self.neighborhoods = pick(tr["neighborhoods"])
        self.streets = pick(tr["streets"])
        world = load("world_places.json")
        self.cities = pick(world["cities"])
        self.countries = world["countries"]
        self.countries_tr = world["countries_tr"]
        self.en_streets = pick(world["en_streets"])
        self.en_street_types = world["en_street_types"]
        self.us_states = world["us_states"]
        neg_path = POOLS / "distractors.json"
        self.neg = {k: v for k, v in json.loads(neg_path.read_text(encoding="utf-8")).items()} if neg_path.exists() else {}
        # Name-like ordinary words by language, so "I {NEG:word} call you" gets "will", not "deniz".
        tr_names = {tr_lower(name_of(x)) for x in load("tr_first_names.json")} | {tr_lower(x) for x in load("tr_surnames.json")}
        en_names = {name_of(x).lower() for x in load("en_first_names.json")} | {x.lower() for x in load("en_surnames.json")}
        words = self.neg.get("word", [])
        self.neg_word = {
            "tr": [w for w in words if tr_lower(w) in tr_names or re.search("[çğıöşü]", w)] or words,
            "en": [w for w in words if w.lower() in en_names and not re.search("[çğıöşü]", w)] or words,
        }
        self.uk_areas = world["uk_postcode_areas"]


# ---------------------------------------------------------------- values


class Filler:
    def __init__(self, pools: Pools, rng: random.Random, lang: str):
        self.p, self.r, self.lang = pools, rng, lang
        self.people: dict[str, dict] = {}
        self.places: dict[str, dict] = {}

    def _origin(self) -> str:
        roll = self.r.random()
        if self.lang == "tr":
            return "tr" if roll < 0.8 else ("en" if roll < 0.9 else "other")
        if self.lang == "en":
            return "en" if roll < 0.6 else ("tr" if roll < 0.85 else "other")
        return "tr" if roll < 0.55 else ("en" if roll < 0.85 else "other")

    def person(self, n: str) -> dict:
        if n not in self.people:
            o = self._origin()
            name = lambda x: x["name"] if isinstance(x, dict) else x  # noqa: E731
            if o == "other":
                x = self.r.choice(self.p.other)
                first, first2, last = x["first"], None, x["last"]
            elif o == "tr":
                first, first2 = name(self.r.choice(self.p.tr_first)), name(self.r.choice(self.p.tr_first))
                last = self.r.choice(self.p.tr_last)
            else:
                first, first2 = name(self.r.choice(self.p.en_first)), name(self.r.choice(self.p.en_first))
                last = self.r.choice(self.p.en_last)
            self.people[n] = {"first": first, "first2": first2 or first, "last": last}
        return self.people[n]

    def person_form(self, n: str, form: str) -> str:
        p = self.person(n)
        full = f"{p['first']} {p['last']}"
        if form in ("", "full"):
            return full
        if form == "first":
            return p["first"]
        if form == "last":
            return p["last"]
        if form == "firstlast2":
            return f"{p['first']} {p['first2']} {p['last']}" if p["first2"] != p["first"] else full
        if form == "upper":
            return tr_upper(full)
        if form == "lower":
            low = tr_lower(full)
            return low.translate(ASCII) if self.r.random() < 0.4 else low
        if form == "initial":
            return f"{p['first'][0]}. {p['last']}"
        return full

    def _num(self, lo=1, hi=200) -> int:
        return self.r.randint(lo, hi)

    def tr_street(self) -> str:
        r = self.r
        kind = r.choice(["Cad.", "Caddesi", "Cd.", "Sok.", "Sokak", "Sk.", "Bulvarı", "Blv."])
        no = r.choice([f"No:{self._num()}", f"No: {self._num()}", f"No {self._num()}", f"No:{self._num()}/{self._num(1, 9)}"])
        return f"{r.choice(self.p.streets)} {kind} {no}"

    def tr_address(self) -> str:
        r = self.r
        mah = r.choice(self.p.neighborhoods) + r.choice([" Mah.", " Mahallesi", " Mh."])
        parts = [mah, self.tr_street()]
        if r.random() < 0.6:
            parts.append(r.choice([f"D:{self._num(1, 40)}", f"Daire {self._num(1, 40)}", f"Kat {self._num(1, 12)} D.{self._num(1, 40)}"]))
        d = r.choice(self.p.districts)
        tail = r.choice([f"{d['district']}/{d['province']}", f"{d['district']} / {tr_upper(d['province'])}", f"{d['district']}, {d['province']}"])
        if r.random() < 0.3:
            tail = f"{r.randint(1, 81):02d}{r.randint(0, 999):03d} {tail}"
        sep = r.choice([" ", ", "])
        return sep.join(parts) + r.choice([" ", ", "]) + tail

    def en_street(self) -> str:
        return f"{self._num(1, 9999)} {self.r.choice(self.p.en_streets)} {self.r.choice(self.p.en_street_types)}"

    def en_address(self) -> str:
        r = self.r
        if r.random() < 0.6:
            st = r.choice(self.p.us_states)
            return f"{self.en_street()}{r.choice(['', f', Apt {self._num(1, 40)}'])}, {r.choice(self.p.cities)}, {st['code']} {r.randint(10000, 99999)}"
        area = r.choice(self.p.uk_areas)
        flat = r.choice(["", f"Flat {self._num(1, 30)}, "])
        return f"{flat}{self.en_street()}, {r.choice(self.p.cities)} {area} {r.randint(1, 9)}{r.choice('ABDEFGHJLNPQRSTUWXYZ')}{r.choice('ABDEFGHJLNPQRSTUWXYZ')}"

    def address(self, n: str, form: str) -> str:
        key = f"{n}.{form}"
        if key not in self.places:
            en = form.startswith("en") or (form == "" and self.lang == "en")
            street_only = form.endswith("street")
            if en:
                v = self.en_street() if street_only else self.en_address()
            else:
                v = self.tr_street() if street_only else self.tr_address()
            self.places[key] = {"v": v}
        return self.places[key]["v"]

    def location(self, n: str, form: str) -> str:
        key = f"L{n}.{form}"
        if key not in self.places:
            r = self.r
            if form == "district":
                v = r.choice(self.p.districts)["district"]
            elif form == "neighborhood":
                v = r.choice(self.p.neighborhoods) + r.choice(["", "", " Mahallesi"])
            elif form == "country":
                v = r.choice(self.p.countries_tr if self.lang == "tr" else self.p.countries)
            else:  # city
                tr_city = self.lang == "tr" or (self.lang == "mix" and r.random() < 0.7)
                v = r.choice(self.p.provinces) if tr_city and r.random() < 0.85 else r.choice(self.p.cities)
            self.places[key] = {"v": v}
        return self.places[key]["v"]


# ---------------------------------------------------------------- fill


def fill(template: dict, pools: Pools, rng: random.Random) -> dict:
    lang = template.get("lang", "tr")
    f = Filler(pools, rng, lang)
    text, spans, pos = [], [], 0
    out_len = 0
    src = template["text"]
    for m in ANY_SLOT.finditer(src):
        literal = src[pos : m.start()]
        text.append(literal)
        out_len += len(literal)
        kind, n, form, neg, case = m.group(1), m.group(2), m.group(3) or "", m.group(4), m.group(5)
        if neg:
            if neg == "word" and lang in ("tr", "en"):
                value = rng.choice(pools.neg_word[lang])
            else:
                value = rng.choice(pools.neg.get(neg) or ["Kafka"])
            if neg == "word" and rng.random() < 0.3:
                value = value[:1].upper() + value[1:]  # sentence-case ordinary word
            elif neg != "word" and rng.random() < 0.2:
                value = tr_lower(value)  # people type "kafka", "koç holding" too
            text.append(value)
            out_len += len(value)
            if case:
                sfx = suffix(value.split()[-1], case)
                text.append(sfx)
                out_len += len(sfx)
            pos = m.end()
            continue
        if kind == "PERSON":
            value = f.person_form(n, form)
            # `@{PERSON1.lower}`, `user={PERSON1.lower}`: a handle, not two words.
            if m.start() and src[m.start() - 1] in "@=" and " " in value:
                value = value.replace(". ", ".").replace(" ", rng.choice([".", "_", ""]))
        elif kind == "ADDRESS":
            value = f.address(n, form)
        else:
            value = f.location(n, form)
            # The template already says "Mahallesi" after the slot: do not double it.
            if re.match(r"\s*(?:mah\.|mahalle)", src[m.end() :], re.I) and value.endswith(" Mahallesi"):
                value = value[: -len(" Mahallesi")]
        spans.append({"start": out_len, "end": out_len + len(value), "label": kind})
        text.append(value)
        out_len += len(value)
        if case:
            sfx = suffix(value.split()[-1], case)
            text.append(sfx)
            out_len += len(sfx)
        pos = m.end()
    text.append(src[pos:])
    out = "".join(text)
    # Whole-text typing variants: no Turkish characters / all lower-case (offsets preserved).
    # str.lower() turns "İ" into two code units; tr_lower folds it first, so offsets hold.
    roll = rng.random()
    variant = out
    if lang != "en" and roll < 0.06:
        variant = out.translate(ASCII)
    elif roll < 0.09:
        variant = tr_lower(out)
    if len(variant) == len(out):
        out = variant
    return {"text": out, "spans": spans, "lang": lang, "domain": template.get("domain", "")}


def check(rec: dict) -> None:
    prev = -1
    for s in rec["spans"]:
        assert s["label"] in LABELS
        assert prev <= s["start"] < s["end"] <= len(rec["text"]), rec
        frag = rec["text"][s["start"] : s["end"]]
        assert frag == frag.strip() and frag, (frag, rec)
        prev = s["end"]


def _key(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _read(folder: Path) -> list[dict]:
    out = []
    for path in sorted(folder.glob("*.jsonl")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if line.strip():
                t = json.loads(line)
                t["_id"] = f"{path.stem}:{i}"
                out.append(t)
    return out


def load_templates(split: str) -> list[dict]:
    """Templates of one split, each text once; training never includes an eval text."""
    evals = _read(HERE / "data" / "eval")
    chosen = evals if split == "eval" else _read(HERE / "data" / "templates")
    banned = {_key(t["text"]) for t in evals} if split == "train" else set()
    seen, out = set(), []
    for t in chosen:
        k = _key(t["text"])
        if k in seen or k in banned:
            continue
        seen.add(k)
        out.append(t)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", choices=["train", "eval"], required=True)
    ap.add_argument("--per-template", type=int, default=40)
    ap.add_argument("--seed", type=int, default=1729)
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    templates = load_templates(args.split)
    pools = Pools(args.split)
    rng = random.Random(args.seed)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(args.out, "w", encoding="utf-8") as fh:
        for t in templates:
            # Slot-free templates carry no variation: one copy is enough.
            copies = args.per_template if ANY_SLOT.search(t["text"]) else max(1, args.per_template // 10)
            for _ in range(copies):
                rec = fill(t, pools, rng)
                rec["template"] = t["_id"]
                check(rec)
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                n += 1
    print(f"{args.split}: {len(templates)} templates -> {n} records -> {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
