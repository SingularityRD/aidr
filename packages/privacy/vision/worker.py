#!/usr/bin/env python3
"""Local image DLP worker. No network, no image temp files, no user-content logs.
Trusted executable/config, untrusted image bytes. One bounded request per process.
A process boundary is NOT an OS sandbox: deploy with network denial/seccomp/cgroups.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import math
import os
import struct
import subprocess
import sys
import threading
import warnings
from pathlib import Path
from importlib.metadata import version
from PIL import Image, ImageDraw, ImageFile, ImageOps, PngImagePlugin

MAX_INPUT = 8 * 1024 * 1024
MAX_PIXELS = 12_000_000
MAX_DIMENSION = 8192
MAX_WORDS = 10000
MAX_TEXT = 262144
MAX_IPC = 16 * 1024 * 1024
MAX_REGIONS = 4096
Image.MAX_IMAGE_PIXELS = MAX_PIXELS
ImageFile.LOAD_TRUNCATED_IMAGES = False
PngImagePlugin.MAX_TEXT_CHUNK = 1024 * 1024
PngImagePlugin.MAX_TEXT_MEMORY = 2 * 1024 * 1024
warnings.simplefilter("error", Image.DecompressionBombWarning)

class GuardError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

def fail(code: str):
    raise GuardError(code)

def positive(value, lower, upper, code="IMAGE_PROTOCOL_INVALID"):
    if type(value) is not int or not lower <= value <= upper:
        fail(code)
    return value

def dimensions(width, height, limits):
    positive(width, 1, limits["maxDimension"], "IMAGE_DIMENSION_LIMIT")
    positive(height, 1, limits["maxDimension"], "IMAGE_DIMENSION_LIMIT")
    if width * height > limits["maxPixels"]:
        fail("IMAGE_PIXEL_LIMIT")

def normalize(raw: bytes, limits: dict):
    if not raw or len(raw) > limits["maxBytes"]:
        fail("IMAGE_INPUT_LIMIT")
    png = raw.startswith(b"\x89PNG\r\n\x1a\n")
    jpg = raw.startswith(b"\xff\xd8\xff")
    webp = raw.startswith(b"RIFF") and len(raw) >= 12 and raw[8:12] == b"WEBP"
    if not (png or jpg or webp):
        fail("IMAGE_FORMAT_UNSUPPORTED")
    if webp and struct.unpack("<I", raw[4:8])[0] + 8 != len(raw):
        fail("IMAGE_DECODE_FAILED")
    try:
        with Image.open(io.BytesIO(raw), formats=["PNG", "JPEG", "WEBP"]) as original:
            dimensions(*original.size, limits)
            if getattr(original, "n_frames", 1) != 1 or getattr(original, "is_animated", False):
                fail("IMAGE_ANIMATION_BLOCKED")
            fmt = original.format
            original.verify()
        with Image.open(io.BytesIO(raw), formats=["PNG", "JPEG", "WEBP"]) as original:
            oriented = ImageOps.exif_transpose(original)
            oriented.load()
            dimensions(*oriented.size, limits)
            rgba = oriented.convert("RGBA")
            white = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
            opaque = Image.alpha_composite(white, rgba).convert("RGB")
            # Copy ONLY pixels, never info/exif/palette/thumbnail/application metadata.
            result = Image.frombytes("RGB", opaque.size, opaque.tobytes())
        return result, fmt
    except GuardError:
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        fail("IMAGE_PIXEL_LIMIT")
    except Exception:
        fail("IMAGE_DECODE_FAILED")

def pixel_hash(im):
    h = hashlib.sha256(struct.pack(">II", *im.size))
    h.update(im.tobytes())
    return h.hexdigest()

def png_bytes(im):
    out = io.BytesIO()
    Image.frombytes("RGB", im.size, im.tobytes()).save(out, format="PNG", compress_level=3)
    return out.getvalue()

def box_check(box, width, height):
    if type(box) is not dict:
        fail("IMAGE_GEOMETRY_INVALID")
    x = positive(box.get("x"), 0, width - 1, "IMAGE_GEOMETRY_INVALID")
    y = positive(box.get("y"), 0, height - 1, "IMAGE_GEOMETRY_INVALID")
    w = positive(box.get("width"), 1, width, "IMAGE_GEOMETRY_INVALID")
    h = positive(box.get("height"), 1, height, "IMAGE_GEOMETRY_INVALID")
    if x + w > width or y + h > height:
        fail("IMAGE_GEOMETRY_INVALID")
    return x, y, x + w, y + h

def render(im, boxes):
    if type(boxes) is not list or len(boxes) > MAX_REGIONS:
        fail("IMAGE_REGION_LIMIT")
    clean = Image.frombytes("RGB", im.size, im.tobytes())
    draw = ImageDraw.Draw(clean)
    for box in boxes:
        x, y, r, b = box_check(box, *clean.size)
        draw.rectangle((x, y, r - 1, b - 1), fill=(0, 0, 0))
    for box in boxes:
        if clean.crop(box_check(box, *clean.size)).getextrema() != ((0, 0), (0, 0), (0, 0)):
            fail("IMAGE_PIXEL_VERIFICATION_FAILED")
    return clean

def run_bounded(command: list[str], payload: bytes, timeout: float, max_output: int) -> bytes:
    """Drain stdout/stderr concurrently with strict byte caps; no shell or temp files."""
    env = {"OMP_THREAD_LIMIT": "1", "OMP_NUM_THREADS": "1", "LC_ALL": "C.UTF-8"}
    for key in ("PATH", "SYSTEMROOT", "WINDIR"):
        if key in os.environ:
            env[key] = os.environ[key]
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env, shell=False)
    except Exception:
        fail("IMAGE_OCR_UNAVAILABLE")
    chunks = []
    errors = []
    def write():
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
    def read(stream, cap, keep):
        count = 0
        try:
            while True:
                item = stream.read(65536)
                if not item:
                    break
                count += len(item)
                if count > cap:
                    errors.append("IMAGE_OCR_LIMIT")
                    proc.kill()
                    return
                if keep:
                    chunks.append(item)
        except OSError:
            errors.append("IMAGE_OCR_FAILED")
        finally:
            stream.close()
    threads = [threading.Thread(target=write, daemon=True),
               threading.Thread(target=read, args=(proc.stdout, max_output, True), daemon=True),
               threading.Thread(target=read, args=(proc.stderr, 262144, False), daemon=True)]
    for thread in threads:
        thread.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        errors.append("IMAGE_OCR_TIMEOUT")
    finally:
        for thread in threads:
            thread.join(timeout=1)
    if errors:
        fail(errors[0])
    if proc.returncode != 0 or any(thread.is_alive() for thread in threads):
        fail("IMAGE_OCR_FAILED")
    return b"".join(chunks)

TSV_HEADER = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"
def parse_tsv(raw: bytes, width: int, height: int, limits: dict):
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
        if not lines or lines[0] != TSV_HEADER:
            fail("IMAGE_PROTOCOL_INVALID")
        words = []
        line_ids = {}
        text_bytes = 0
        for line in lines[1:]:
            cells = line.split("\t", 11)
            if len(cells) != 12:
                fail("IMAGE_PROTOCOL_INVALID")
            if cells[0] != "5":
                continue
            text = cells[11]
            if not text.strip():
                continue
            if any(ch.isspace() for ch in text) or len(text) > 1024:
                fail("IMAGE_PROTOCOL_INVALID")
            confidence = float(cells[10])
            if not math.isfinite(confidence) or not 0 <= confidence <= 100:
                fail("IMAGE_PROTOCOL_INVALID")
            key = tuple(cells[1:5])
            if key not in line_ids:
                line_ids[key] = len(line_ids)
            box = dict(x=int(cells[6]), y=int(cells[7]), width=int(cells[8]), height=int(cells[9]))
            box_check(box, width, height)
            words.append(dict(box, text=text, confidence=confidence, line=line_ids[key]))
            text_bytes += len(text.encode("utf-8")) + 1
            if len(words) > limits["maxWords"] or text_bytes > limits["maxTextBytes"]:
                fail("IMAGE_OCR_LIMIT")
        return {"words": words}
    except GuardError:
        raise
    except Exception:
        fail("IMAGE_PROTOCOL_INVALID")

WINDOWS_LANGUAGE = {"tr": "tur", "tr-TR": "tur", "en": "eng", "en-US": "eng", "en-GB": "eng"}

def ocr(im, args, psms, limits, manifest):
    encoded = png_bytes(im)
    pages = []
    if manifest.get("ocrEngine") == "windows":
        # Windows.Media.Ocr through the pinned helper script: one page per installed recognizer
        # language recorded in the manifest (psm values do not apply to this engine).
        for tag in manifest["languages"]:
            command = [args.powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                       "-File", args.windows_ocr_script, "-Languages", tag]
            data = run_bounded(command, encoded, 20, 4 * 1024 * 1024)
            pages.append(parse_tsv(data, *im.size, limits))
    else:
        for psm in psms:
            command = [args.tesseract, "stdin", "stdout", "--tessdata-dir", args.tessdata,
                       "-l", "eng+tur", "--oem", "1", "--psm", str(psm), "-c", "tessedit_create_tsv=1"]
            data = run_bounded(command, encoded, 12, 4 * 1024 * 1024)
            pages.append(parse_tsv(data, *im.size, limits))
    if sum(len(page["words"]) for page in pages) > limits["maxWords"]:
        fail("IMAGE_OCR_LIMIT")
    return pages

def scan_languages(manifest):
    if manifest.get("ocrEngine") == "windows":
        return sorted({WINDOWS_LANGUAGE[tag] for tag in manifest["languages"]})
    return ["eng", "tur"]

def barcodes(im, manifest=None):
    if (manifest or {}).get("barcodeEngine") == "none":
        # No barcode decoder on this endpoint (recorded in the manifest): report none found and
        # say so in barcodeCoverage, so the engine never treats the image as fully inspected.
        return []
    try:
        from pyzbar.pyzbar import decode
    except Exception:
        fail("IMAGE_BARCODE_UNAVAILABLE")
    try:
        codes = decode(im)
        if len(codes) > 256:
            fail("IMAGE_OCR_LIMIT")
        result = []
        for code in codes:
            # QR/barcode payload is never serialized or logged, regardless of content.
            b = dict(x=int(code.rect.left), y=int(code.rect.top), width=int(code.rect.width), height=int(code.rect.height))
            box_check(b, *im.size)
            result.append(b)
        return result
    except GuardError:
        raise
    except Exception:
        fail("IMAGE_BARCODE_UNAVAILABLE")

def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def check_artifacts(args):
    """Verify the pinned OCR installation against the manifest; returns the manifest."""
    try:
        if not Path(args.manifest).is_absolute():
            fail("IMAGE_ARTIFACT_MISMATCH")
        manifest_path = Path(args.manifest)
        if manifest_path.stat().st_size > 65536:
            fail("IMAGE_ARTIFACT_MISMATCH")
        m = json.loads(manifest_path.read_text("utf-8"))
        if m["schemaVersion"] != 1:
            fail("IMAGE_ARTIFACT_MISMATCH")
        engine = m.get("ocrEngine", "tesseract")
        if engine != getattr(args, "ocr_engine", "tesseract"):
            fail("IMAGE_ARTIFACT_MISMATCH")
        if engine == "windows":
            for p in (getattr(args, "powershell", None), getattr(args, "windows_ocr_script", None)):
                if not p or not Path(p).is_absolute():
                    fail("IMAGE_ARTIFACT_MISMATCH")
            langs = m["languages"]
            if type(langs) is not list or not 1 <= len(langs) <= 4 or any(type(t) is not str or t not in WINDOWS_LANGUAGE for t in langs):
                fail("IMAGE_ARTIFACT_MISMATCH")
            if "tur" not in {WINDOWS_LANGUAGE[t] for t in langs}:
                fail("IMAGE_ARTIFACT_MISMATCH")
            if sha256_file(args.windows_ocr_script) != m["windowsOcrScriptSha256"]:
                fail("IMAGE_ARTIFACT_MISMATCH")
            if sha256_file(args.powershell) != m["powershellSha256"]:
                fail("IMAGE_ARTIFACT_MISMATCH")
        elif engine == "tesseract":
            for p in (args.tesseract, args.tessdata):
                if not p or not Path(p).is_absolute():
                    fail("IMAGE_ARTIFACT_MISMATCH")
            if sha256_file(args.tesseract) != m["tesseractSha256"]:
                fail("IMAGE_ARTIFACT_MISMATCH")
            for lang in ("eng", "tur"):
                if sha256_file(Path(args.tessdata) / (lang + ".traineddata")) != m["models"][lang]:
                    fail("IMAGE_ARTIFACT_MISMATCH")
        else:
            fail("IMAGE_ARTIFACT_MISMATCH")
        if m.get("barcodeEngine", "pyzbar") not in ("pyzbar", "none"):
            fail("IMAGE_ARTIFACT_MISMATCH")
        if version("Pillow") != m["pillowVersion"]:
            fail("IMAGE_ARTIFACT_MISMATCH")
        if m.get("barcodeEngine", "pyzbar") == "pyzbar" and version("pyzbar") != m["pyzbarVersion"]:
            fail("IMAGE_ARTIFACT_MISMATCH")
        return m
    except GuardError:
        raise
    except Exception:
        fail("IMAGE_ARTIFACT_MISMATCH")

def restrict_process():
    if os.name == "posix":
        import resource
        for kind, limit in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0),
                            (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CPU, 28),
                            (resource.RLIMIT_AS, 1024 * 1024 * 1024)):
            resource.setrlimit(kind, (limit, limit))

def limits_from(request):
    source = request.get("limits", {})
    caps = dict(maxBytes=MAX_INPUT, maxPixels=MAX_PIXELS, maxDimension=MAX_DIMENSION,
                maxWords=MAX_WORDS, maxTextBytes=MAX_TEXT)
    if type(source) is not dict:
        fail("IMAGE_PROTOCOL_INVALID")
    return {key: positive(source.get(key, cap), 1, cap) for key, cap in caps.items()}

def coverage(manifest):
    """Extra scan fields for a non-default installation (absent for Tesseract + pyzbar)."""
    extra = {}
    if manifest.get("ocrEngine") == "windows":
        extra["ocrEngine"] = "windows"
    if manifest.get("barcodeEngine") == "none":
        extra["barcodeCoverage"] = "none"
    return extra

def handle(request, args, manifest):
    if type(request) is not dict or request.get("protocol") != 1 or request.get("task") not in ("inspect", "render"):
        fail("IMAGE_PROTOCOL_INVALID")
    psms = request.get("psms", [11, 6])
    if type(psms) is not list or not psms or len(psms) > 2 or any(type(p) is not int or p not in (6, 11) for p in psms) or len(set(psms)) != len(psms):
        fail("IMAGE_PROTOCOL_INVALID")
    limits = limits_from(request)
    b64 = request.get("image")
    if type(b64) is not str or len(b64) > (limits["maxBytes"] + 2) // 3 * 4:
        fail("IMAGE_INPUT_LIMIT")
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception:
        fail("IMAGE_INPUT_INVALID")
    im, fmt = normalize(raw, limits)
    pixel_sha = pixel_hash(im)
    if request["task"] == "render":
        if request.get("pixelSha256") != pixel_sha:
            fail("IMAGE_HASH_MISMATCH")
        im = render(im, request.get("regions"))
        output = png_bytes(im)
        return dict(protocol=1, complete=True, width=im.width, height=im.height,
                    png=base64.b64encode(output).decode("ascii"), pages=ocr(im, args, psms, limits, manifest),
                    barcodes=barcodes(im, manifest), **coverage(manifest))
    return dict(protocol=1, complete=True, inputSha256=hashlib.sha256(raw).hexdigest(),
                pixelSha256=pixel_sha, width=im.width, height=im.height, format=fmt,
                pages=ocr(im, args, psms, limits, manifest), barcodes=barcodes(im, manifest),
                languages=scan_languages(manifest), **coverage(manifest))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ocr-engine", choices=("tesseract", "windows"), default="tesseract")
    parser.add_argument("--tesseract")
    parser.add_argument("--tessdata")
    parser.add_argument("--powershell")
    parser.add_argument("--windows-ocr-script")
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args()
    try:
        restrict_process()
        manifest = check_artifacts(args)
        data = sys.stdin.buffer.read(MAX_IPC + 1)
        if len(data) > MAX_IPC:
            fail("IMAGE_INPUT_LIMIT")
        result = handle(json.loads(data.decode("utf-8", "strict")), args, manifest)
    except GuardError as error:
        result = dict(protocol=1, complete=False, code=error.code)
    except Exception:
        result = dict(protocol=1, complete=False, code="IMAGE_WORKER_FAILED")
    sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()

if __name__ == "__main__":
    main()
