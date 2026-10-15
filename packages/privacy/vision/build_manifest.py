#!/usr/bin/env python3
"""Generate an inventory of an ALREADY APPROVED local OCR installation.
A self-generated hash inventory does not establish supply-chain trust or authenticity.

Tesseract (default):  --tesseract <exe> --tessdata <dir> --output <json>
Windows built-in OCR: --ocr-engine windows --powershell <powershell.exe> --windows-ocr-script <windows_ocr.ps1>
                      --languages tr[,en-US] --output <json>
--barcode-engine none records that no barcode decoder is available (pyzbar/libzbar missing), so
the worker reports barcodeCoverage "none" instead of failing every image.
"""
import argparse
import hashlib
import json
from pathlib import Path
from importlib.metadata import version

WINDOWS_LANGUAGES = ("tr", "tr-TR", "en", "en-US", "en-GB")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


p = argparse.ArgumentParser()
p.add_argument('--ocr-engine', choices=('tesseract', 'windows'), default='tesseract')
p.add_argument('--tesseract')
p.add_argument('--tessdata')
p.add_argument('--powershell')
p.add_argument('--windows-ocr-script')
p.add_argument('--languages', default='tr')
p.add_argument('--barcode-engine', choices=('pyzbar', 'none'), default='pyzbar')
p.add_argument('--output', required=True)
a = p.parse_args()
m = dict(schemaVersion=1)
if a.ocr_engine == 'windows':
    for value in (a.powershell, a.windows_ocr_script):
        if not value or not Path(value).is_absolute():
            raise SystemExit('Absolute approved paths required')
    languages = [t for t in a.languages.split(',') if t]
    if not languages or any(t not in WINDOWS_LANGUAGES for t in languages) or not any(t.startswith('tr') for t in languages):
        raise SystemExit('Languages must include tr and use ' + ','.join(WINDOWS_LANGUAGES))
    m.update(ocrEngine='windows', powershellSha256=sha256(a.powershell),
             windowsOcrScriptSha256=sha256(a.windows_ocr_script), languages=languages)
else:
    for value in (a.tesseract, a.tessdata):
        if not value or not Path(value).is_absolute():
            raise SystemExit('Absolute approved paths required')
    m.update(tesseractSha256=sha256(a.tesseract),
             models={lang: sha256(Path(a.tessdata) / f'{lang}.traineddata') for lang in ('eng', 'tur')})
m['pillowVersion'] = version('Pillow')
if a.barcode_engine == 'pyzbar':
    m['pyzbarVersion'] = version('pyzbar')
else:
    m['barcodeEngine'] = 'none'
with open(a.output, 'x', encoding='utf-8') as out:
    json.dump(m, out, indent=2)
    out.write('\n')
