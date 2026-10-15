#!/usr/bin/env python3
"""Write a SYNTHETIC demo screenshot for the AIDR Privacy companion (OCR) check.

Every value is generated here and is fake: a T.C. kimlik number with a valid checksum built
from fixed digits, a TR IBAN with valid mod-97 check digits for a made-up bank/account, and an
address on the reserved example.com domain. Needs Pillow (the companion venv has it) and a
TrueType font (Windows: Arial). Usage: python make_demo_image.py <out.png> [--clean]
"""
import argparse
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


def tckn(first9: str) -> str:
    d = [int(c) for c in first9]
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = (sum(d) + d10) % 10
    return first9 + str(d10) + str(d11)


def tr_iban(bank: str, account: str) -> str:
    bban = bank + "0" + account  # 5-digit bank code, reserve digit, 16-digit account
    numeric = int(bban + "2927" + "00")  # T=29, R=27
    return "TR%02d%s" % (98 - numeric % 97, bban)


def grouped(iban: str) -> str:
    return " ".join(iban[i:i + 4] for i in range(0, len(iban), 4))


def font(size: int):
    for candidate in (r"C:\Windows\Fonts\arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                      "/Library/Fonts/Arial.ttf"):
        if Path(candidate).is_file():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default(size=size)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("output")
    p.add_argument("--clean", action="store_true", help="no personal data (a control image)")
    a = p.parse_args()
    if a.clean:
        lines = ["Toplanti notlari", "Yarin saat 10:00 da proje durumu konusulacak.",
                 "Gundem: yol haritasi ve test plani."]
    else:
        lines = ["Musteri kaydi (SENTETIK TEST VERISI)",
                 "TC Kimlik No: " + tckn("384915726"),
                 "IBAN: " + grouped(tr_iban("00061", "0000012345678901")),
                 "E-posta: ayse.demo@example.com"]
    f = font(34)
    image = Image.new("RGB", (1100, 90 + 70 * len(lines)), "white")
    draw = ImageDraw.Draw(image)
    for i, line in enumerate(lines):
        draw.text((40, 40 + 70 * i), line, fill="black", font=f)
    out = Path(a.output)
    if out.exists():
        print("output exists", file=sys.stderr)
        return 2
    image.save(out, format="PNG")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
