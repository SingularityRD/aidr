"""Native image decoding/renderer and protocol tests. OCR inference lives ONLY in e2e.mjs."""
import base64
import hashlib
import io
import json
import os
import random
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from PIL import Image, PngImagePlugin
import worker as w

LIMITS = dict(maxBytes=w.MAX_INPUT, maxPixels=w.MAX_PIXELS, maxDimension=w.MAX_DIMENSION,
              maxWords=w.MAX_WORDS, maxTextBytes=w.MAX_TEXT)

def encoded(im=None, fmt='PNG', **kwargs):
    im = im or Image.new('RGB', (40, 30), (61, 107, 203))
    out = io.BytesIO()
    im.save(out, format=fmt, **kwargs)
    return out.getvalue()

def tsv(text='jane@example.com', left=1, top=2, width=20, height=12, conf=95):
    return (w.TSV_HEADER + '\n' + f'5\t1\t1\t1\t1\t1\t{left}\t{top}\t{width}\t{height}\t{conf}\t{text}\n').encode('utf-8')

class WorkerTests(unittest.TestCase):
    def code(self, expected, fn, *args):
        with self.assertRaises(w.GuardError) as cm:
            fn(*args)
        self.assertEqual(cm.exception.code, expected)

    def test_opaque_alpha_removes_hidden_rgb(self):
        im=Image.new('RGBA',(40,30),(123,77,33,0))
        clean,_=w.normalize(encoded(im),LIMITS)
        self.assertEqual(clean.mode,'RGB')
        self.assertEqual(clean.getextrema(),((255,255),(255,255),(255,255)))

    def test_semitransparent_input_has_one_unambiguous_canvas(self):
        im=Image.new('RGBA',(40,30),(0,0,0,128))
        clean,_=w.normalize(encoded(im),LIMITS)
        self.assertEqual(clean.getpixel((0,0)),(127,127,127))

    def test_metadata_and_appended_bytes_do_not_survive_normalization(self):
        info=PngImagePlugin.PngInfo();info.add_text('Comment','SYNTHETIC-PII@example.com')
        clean,_=w.normalize(encoded(pnginfo=info)+b'SECRET TRAILER',LIMITS)
        output=w.png_bytes(clean)
        self.assertNotIn(b'SYNTHETIC-PII',output)
        self.assertNotIn(b'SECRET TRAILER',output)
        self.assertEqual(Image.open(io.BytesIO(output)).info,{})

    def test_mask_changes_pixels_not_overlay(self):
        im=Image.new('RGB',(40,30),(61,107,203));box=dict(x=5,y=7,width=10,height=11)
        clean=w.render(im,[box]);result=Image.open(io.BytesIO(w.png_bytes(clean)))
        self.assertEqual(result.crop((5,7,15,18)).getextrema(),((0,0),(0,0),(0,0)))
        self.assertEqual(result.getpixel((4,7)),(61,107,203))
        self.assertEqual(result.getpixel((15,17)),(61,107,203))
        self.assertEqual(im.getpixel((5,7)),(61,107,203))

    def test_generated_mask_coverage_2000_rectangles(self):
        rng=random.Random(20260924)
        for _ in range(2000):
            width,height=rng.randint(1,40),rng.randint(1,40)
            x,y=rng.randrange(width),rng.randrange(height)
            box=dict(x=x,y=y,width=rng.randint(1,width-x),height=rng.randint(1,height-y))
            im=Image.new('RGB',(width,height),'white');out=w.render(im,[box]);mask=w.box_check(box,width,height)
            self.assertEqual(out.crop(mask).getextrema(),((0,0),(0,0),(0,0)))
            for px,py in [(0,0),(width-1,0),(0,height-1),(width-1,height-1)]:
                expected=(0,0,0) if x<=px<x+box['width'] and y<=py<y+box['height'] else (255,255,255)
                self.assertEqual(out.getpixel((px,py)),expected)

    def test_dimensions_bound_before_full_decode(self):
        self.code('IMAGE_PIXEL_LIMIT',w.normalize,encoded(),{**LIMITS,'maxPixels':10})
        self.code('IMAGE_DIMENSION_LIMIT',w.normalize,encoded(),{**LIMITS,'maxDimension':10})

    def test_compression_bomb_threshold(self):
        with patch.object(Image,'MAX_IMAGE_PIXELS',20):
            self.code('IMAGE_PIXEL_LIMIT',w.normalize,encoded(),LIMITS)

    def test_empty_input(self):
        self.code('IMAGE_INPUT_LIMIT',w.normalize,b'',LIMITS)

    def test_input_byte_cap(self):
        self.code('IMAGE_INPUT_LIMIT',w.normalize,encoded(),{**LIMITS,'maxBytes':4})

    def test_bad_png_crc(self):
        raw=bytearray(encoded());raw[29]^=1
        self.code('IMAGE_DECODE_FAILED',w.normalize,bytes(raw),LIMITS)

    def test_bad_webp_riff_size(self):
        raw=bytearray(encoded(fmt='WEBP'));raw[4]=1
        self.code('IMAGE_DECODE_FAILED',w.normalize,bytes(raw),LIMITS)

    def test_animated_png_blocked(self):
        frames=[Image.new('RGB',(40,30),'red'),Image.new('RGB',(40,30),'blue')]
        data=encoded(frames[0],save_all=True,append_images=frames[1:],duration=100,loop=0)
        self.code('IMAGE_ANIMATION_BLOCKED',w.normalize,data,LIMITS)

    def test_animated_webp_blocked(self):
        frames=[Image.new('RGB',(40,30),'red'),Image.new('RGB',(40,30),'blue')]
        data=encoded(frames[0],fmt='WEBP',save_all=True,append_images=frames[1:],duration=100,loop=0)
        self.code('IMAGE_ANIMATION_BLOCKED',w.normalize,data,LIMITS)

    def test_rectangles_are_half_open(self):
        im=Image.new('RGB',(2,2),'white');out=w.render(im,[dict(x=1,y=1,width=1,height=1)])
        self.assertEqual(list(out.getdata()),[(255,255,255)]*3+[(0,0,0)])

    def test_tsv_retains_low_confidence_instead_of_hiding_it(self):
        words=w.parse_tsv(tsv(conf=0),40,30,LIMITS)['words']
        self.assertEqual(len(words),1);self.assertEqual(words[0]['confidence'],0)

    def test_tsv_turkish_is_not_ascii_transliterated(self):
        self.assertEqual(w.parse_tsv(tsv('Çağrı'),40,30,LIMITS)['words'][0]['text'],'Çağrı')

    def test_tsv_empty_page(self):
        self.assertEqual(w.parse_tsv((w.TSV_HEADER+'\n').encode(),40,30,LIMITS),dict(words=[]))

    def test_tsv_word_limit(self):
        data=tsv()+tsv().split(b'\n',1)[1]
        self.code('IMAGE_OCR_LIMIT',w.parse_tsv,data,40,30,{**LIMITS,'maxWords':1})

    def test_tsv_byte_limit(self):
        self.code('IMAGE_OCR_LIMIT',w.parse_tsv,tsv(),40,30,{**LIMITS,'maxTextBytes':1})

    def test_line_ids_stable(self):
        data=tsv('one')+tsv('two').split(b'\n',1)[1]
        words=w.parse_tsv(data,40,30,LIMITS)['words']
        self.assertEqual([word['line'] for word in words],[0,0])

    def test_pixel_hash_includes_dimensions(self):
        a=Image.new('RGB',(2,3),'white');b=Image.new('RGB',(3,2),'white')
        self.assertNotEqual(w.pixel_hash(a),w.pixel_hash(b))

    def test_bounded_process_success(self):
        out=w.run_bounded([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'SYNTHETIC',2,100)
        self.assertEqual(out,b'SYNTHETIC')

    def test_bounded_process_stdout_limit(self):
        self.code('IMAGE_OCR_LIMIT',w.run_bounded,[sys.executable,'-c','print("x"*65536)'],b'',2,100)

    def test_bounded_process_stderr_limit(self):
        self.code('IMAGE_OCR_LIMIT',w.run_bounded,[sys.executable,'-c','import sys;sys.stderr.write("x"*300000)'],b'',2,100)

    def test_bounded_process_timeout(self):
        self.code('IMAGE_OCR_TIMEOUT',w.run_bounded,[sys.executable,'-c','import time;time.sleep(2)'],b'',.03,100)

    def test_bounded_process_exit_failure(self):
        self.code('IMAGE_OCR_FAILED',w.run_bounded,[sys.executable,'-c','raise SystemExit(2)'],b'',2,100)

    def test_bounded_process_no_executable(self):
        self.code('IMAGE_OCR_UNAVAILABLE',w.run_bounded,['/does/not/exist'],b'',1,100)

    def test_qr_payload_is_not_exported(self):
        import qrcode
        im=qrcode.make('mailto:synthetic@example.com').convert('RGB')
        boxes=w.barcodes(im)
        self.assertEqual(len(boxes),1)
        self.assertNotIn('synthetic',json.dumps(boxes))
        self.assertEqual(w.barcodes(w.render(im,boxes)),[])

    def test_artifact_tampering(self):
        from importlib.metadata import version
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);exe=root/'tesseract';exe.write_bytes(b'SYNTHETIC EXECUTABLE')
            for lang in ('eng','tur'):(root/(lang+'.traineddata')).write_bytes(lang.encode())
            m=dict(schemaVersion=1,tesseractSha256=hashlib.sha256(exe.read_bytes()).hexdigest(),
                   models={lang:hashlib.sha256((root/(lang+'.traineddata')).read_bytes()).hexdigest() for lang in ('eng','tur')},
                   pillowVersion=version('Pillow'),pyzbarVersion=version('pyzbar'))
            manifest=root/'manifest.json';manifest.write_text(json.dumps(m))
            args=SimpleNamespace(tesseract=str(exe),tessdata=temp,manifest=str(manifest))
            w.check_artifacts(args)
            (root/'tur.traineddata').write_bytes(b'TAMPERED')
            self.code('IMAGE_ARTIFACT_MISMATCH',w.check_artifacts,args)

    def test_windows_ocr_manifest_and_missing_barcode_decoder(self):
        from importlib.metadata import version
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);ps=root/'powershell.exe';ps.write_bytes(b'SYNTHETIC POWERSHELL');script=root/'windows_ocr.ps1';script.write_bytes(b'# synthetic')
            m=dict(schemaVersion=1,ocrEngine='windows',powershellSha256=hashlib.sha256(ps.read_bytes()).hexdigest(),
                   windowsOcrScriptSha256=hashlib.sha256(script.read_bytes()).hexdigest(),languages=['tr'],
                   pillowVersion=version('Pillow'),barcodeEngine='none')
            manifest=root/'manifest.json';manifest.write_text(json.dumps(m))
            args=SimpleNamespace(ocr_engine='windows',powershell=str(ps),windows_ocr_script=str(script),manifest=str(manifest))
            self.assertEqual(w.check_artifacts(args)['ocrEngine'],'windows')
            self.assertEqual(w.scan_languages(m),['tur'])
            self.assertEqual(w.coverage(m),{'ocrEngine':'windows','barcodeCoverage':'none'})
            # No decoder recorded: no barcodes are reported (and coverage says so) instead of failing.
            self.assertEqual(w.barcodes(Image.new('RGB',(20,20),'white'),m),[])
            # A Tesseract worker invocation must not accept a Windows manifest, and vice versa.
            self.code('IMAGE_ARTIFACT_MISMATCH',w.check_artifacts,SimpleNamespace(ocr_engine='tesseract',tesseract=str(ps),tessdata=temp,manifest=str(manifest)))
            for bad in (dict(languages=['en-US']),dict(languages=['xx']),dict(barcodeEngine='zxing')):
                manifest.write_text(json.dumps({**m,**bad}));self.code('IMAGE_ARTIFACT_MISMATCH',w.check_artifacts,args)
            manifest.write_text(json.dumps(m));script.write_bytes(b'# TAMPERED')
            self.code('IMAGE_ARTIFACT_MISMATCH',w.check_artifacts,args)

for fmt in ('PNG','JPEG','WEBP'):
    def test(self,fmt=fmt):
        im,actual=w.normalize(encoded(fmt=fmt),LIMITS)
        self.assertEqual(im.size,(40,30));self.assertEqual(actual,fmt);self.assertEqual(im.mode,'RGB')
    setattr(WorkerTests,'test_format_'+fmt.lower(),test)

for mode in ('RGB','RGBA','L','LA','P','1'):
    def test(self,mode=mode):
        clean,_=w.normalize(encoded(Image.new(mode,(40,30))),LIMITS)
        self.assertEqual(clean.mode,'RGB');self.assertEqual(clean.size,(40,30))
    setattr(WorkerTests,'test_pixel_mode_'+mode,test)

for orientation in range(1,9):
    def test(self,orientation=orientation):
        im=Image.new('RGB',(40,30));exif=Image.Exif();exif[274]=orientation
        clean,_=w.normalize(encoded(im,exif=exif),LIMITS)
        self.assertEqual(clean.size,(30,40) if orientation>=5 else (40,30))
        self.assertEqual(clean.info,{})
    setattr(WorkerTests,'test_exif_orientation_'+str(orientation),test)

for fmt in ('GIF','TIFF','BMP','PPM'):
    def test(self,fmt=fmt):self.code('IMAGE_FORMAT_UNSUPPORTED',w.normalize,encoded(fmt=fmt),LIMITS)
    setattr(WorkerTests,'test_reject_'+fmt.lower(),test)

for i,raw in enumerate((b'<svg onload="evil()"/>',b'%PDF-1.7',b'PK\x03\x04',b'\xff\xd8\xff',b'\x89PNG\r\n\x1a\n')):
    def test(self,raw=raw):
        with self.assertRaises(w.GuardError):w.normalize(raw,LIMITS)
    setattr(WorkerTests,'test_bad_image_'+str(i),test)

for field,value in [('left',-1),('top',-1),('width',0),('width',999),('height',-1),('conf',-1),('conf',101),('conf',float('nan')),('conf',float('inf')),('text','a\tb'),('text','x'*1025)]:
    def test(self,field=field,value=value):
        with self.assertRaises(w.GuardError):w.parse_tsv(tsv(**{field:value}),40,30,LIMITS)
    setattr(WorkerTests,'test_invalid_tsv_'+field+'_'+str(value)[:12],test)

for i,box in enumerate((None,{},dict(x=True,y=0,width=1,height=1),dict(x=0,y=0,width=0,height=1),dict(x=1,y=1,width=40,height=30),dict(x=.5,y=0,width=1,height=1))):
    def test(self,box=box):self.code('IMAGE_GEOMETRY_INVALID',w.render,Image.new('RGB',(40,30)),[box])
    setattr(WorkerTests,'test_invalid_rect_'+str(i),test)

if __name__=='__main__':unittest.main()
