#!/usr/bin/env python3
"""Generate an inventory of an ALREADY APPROVED local OCR installation.
A self-generated hash inventory does not establish supply-chain trust or authenticity.
"""
import argparse
import hashlib
import json
from pathlib import Path
from importlib.metadata import version
p = argparse.ArgumentParser()
p.add_argument('--tesseract', required=True)
p.add_argument('--tessdata', required=True)
p.add_argument('--output', required=True)
a = p.parse_args()
for value in (a.tesseract, a.tessdata):
    if not Path(value).is_absolute():
        raise SystemExit('Absolute approved paths required')
m = dict(schemaVersion=1, tesseractSha256=hashlib.sha256(Path(a.tesseract).read_bytes()).hexdigest(),
         models={lang: hashlib.sha256((Path(a.tessdata) / f'{lang}.traineddata').read_bytes()).hexdigest() for lang in ('eng', 'tur')},
         pillowVersion=version('Pillow'), pyzbarVersion=version('pyzbar'))
with open(a.output, 'x', encoding='utf-8') as out:
    json.dump(m, out, indent=2)
    out.write('\n')
