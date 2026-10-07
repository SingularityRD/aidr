"""Format-preserving (raster) PDF redaction tests. Fixtures are written byte by byte here (base-14
Helvetica, no embedded fonts or blobs). As in test_office_redaction.py a tiny regex detector stands in
for the TypeScript PrivacyEngine; tests/platform/pdf-redaction.test.mjs drives the real detector."""
import unittest,io,re,base64,pathlib,importlib.util,warnings
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cdr_worker_pdf',ROOT/'worker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
import pypdfium2 as pdfium
from pypdf import PdfReader
DETECT=re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\b\d{16}\b')
# PII ends each line so the blanked comparison fixture keeps every other glyph at the same position.
LINES=[['Email today: jane.doe@example.com','Card ok 4111111111111111'],['Page two bob@example.org','Plain closing line']]

def pdf(pages=None,rotate=0,mediabox=(0,0,612,792),cropbox=None,extra=b'',info=True):
    """Minimal classic-xref PDF. Each page is a list of text lines; `extra` is appended to page 1's content."""
    pages=LINES if pages is None else pages;objs=[]
    def add(b):objs.append(b);return len(objs)
    font=add(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')
    contents=[]
    for n,lines in enumerate(pages):
        ops=b''.join(b'BT /F1 12 Tf %d %d Td (%s) Tj ET\n'%(mediabox[0]+72,mediabox[1]+720-20*i,l.encode('latin-1')) for i,l in enumerate(lines))
        if n==0:ops+=extra
        contents.append(add(b'<< /Length %d >>\nstream\n'%len(ops)+ops+b'\nendstream'))
    tree=len(objs)+len(pages)+1;kids=[]
    for c in contents:
        page=b'<< /Type /Page /Parent %d 0 R /MediaBox [%d %d %d %d] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R'%((tree,)+tuple(mediabox)+(font,c))
        if rotate:page+=b' /Rotate %d'%rotate
        if cropbox:page+=b' /CropBox [%d %d %d %d]'%tuple(cropbox)
        kids.append(add(page+b' >>'))
    assert add(b'<< /Type /Pages /Kids ['+b' '.join(b'%d 0 R'%k for k in kids)+b'] /Count %d >>'%len(kids))==tree
    meta=add(b'<< /Producer (Secret Producer) /Author (Jane Doe) /Title (meta.owner@example.com) >>') if info else None
    cat=add(b'<< /Type /Catalog /Pages %d 0 R >>'%tree)
    out=io.BytesIO();out.write(b'%PDF-1.4\n');offs=[]
    for i,o in enumerate(objs,1):offs.append(out.tell());out.write(b'%d 0 obj\n'%i+o+b'\nendobj\n')
    x=out.tell();out.write(b'xref\n0 %d\n0000000000 65535 f \n'%(len(objs)+1))
    for o in offs:out.write(b'%010d 00000 n \n'%o)
    out.write(b'trailer\n<< /Size %d /Root %d 0 R'%(len(objs)+1,cat)+(b' /Info %d 0 R'%meta if meta else b'')+b' >>\nstartxref\n%d\n%%%%EOF\n'%x)
    return out.getvalue()

def edits_for(units):
    return [[i,a.start(),a.end(),'[X]'] for i,u in enumerate(units) for a in DETECT.finditer(u)]

def render(b,page=0,scale=m.PDF_SCALE):
    doc=pdfium.PdfDocument(b)
    try:
        bm=doc[page].render(scale=scale,draw_annots=False,fill_color=(255,255,255,255),rev_byteorder=True)
        img=bm.to_pil().convert('RGB');img.load();return img
    finally:doc.close()

def embedded(b,page=0):
    """The page raster exactly as written (re-rendering would resample it)."""
    from PIL import Image
    im=PdfReader(io.BytesIO(b)).pages[page]['/Resources']['/XObject']['/Im0'].get_object()
    return Image.frombytes('RGB',(int(im['/Width']),int(im['/Height'])),im.get_data())

def redact(b,edits=None):
    d=m.PdfDoc(m.Parser(),b)
    try:return d.redact(edits_for(d.units) if edits is None else edits),d.texts()
    finally:d.close()

def rejects(test,reason,fn):
    with test.assertRaises(m.Rejected) as c:fn()
    test.assertEqual(str(c.exception),reason)

class PdfRedactionTests(unittest.TestCase):
    def test_01_units_are_pdfium_page_text(self):
        d=m.PdfDoc(m.Parser(),pdf())
        try:
            self.assertEqual(len(d.units),2);self.assertIn('jane.doe@example.com',d.units[0]);self.assertIn('bob@example.org',d.units[1])
            self.assertEqual(len(d.digest()),64)
        finally:d.close()
    def test_02_output_is_image_only_pdf_without_metadata(self):
        out,_=redact(pdf())
        self.assertTrue(out.startswith(b'%PDF-1.4\n'))
        for needle in (b'/Info',b'Producer',b'Creator',b'Secret',b'Jane Doe',b'example',b'/Font',b'/ID',b'Metadata'):self.assertNotIn(needle,out)
        r=PdfReader(io.BytesIO(out),strict=True)
        self.assertEqual(len(r.pages),2);self.assertIsNone(r.metadata);self.assertEqual(set(r.trailer.keys()),{'/Size','/Root'})
        self.assertTrue(all(p.extract_text().strip()=='' for p in r.pages))
        self.assertEqual([tuple(map(float,p.mediabox)) for p in r.pages],[(0.0,0.0,612.0,792.0)]*2)
        doc=pdfium.PdfDocument(out)
        try:
            self.assertEqual(len(doc),2);self.assertFalse(any(doc.get_metadata_dict().values()))
            self.assertTrue(all(doc[i].get_textpage().count_chars()==0 for i in range(2)))
        finally:doc.close()
    def assert_pii_ink_covered(self,original,without_pii,out,page=0):
        """Ink present in the original but absent from a copy without the PII strings is PII ink:
        every such pixel must be black in the output, independent of the worker's coordinate mapping."""
        a,b,o=render(original,page),render(without_pii,page),embedded(out,page)
        self.assertEqual(a.size,o.size)
        pa,pb,po=a.load(),b.load(),o.load();ink=0
        for y in range(a.size[1]):
            for x in range(a.size[0]):
                if sum(pa[x,y])<300 and sum(pb[x,y])>=700:
                    ink+=1;self.assertEqual(po[x,y],(0,0,0),(x,y))
        self.assertGreater(ink,100)
        # Non-PII text is kept visible (not blacked out).
        kept=sum(1 for y in range(a.size[1]) for x in range(a.size[0]) if sum(pb[x,y])<300 and sum(po[x,y])>0)
        self.assertGreater(kept,100)
    def test_03_spans_painted_over_glyphs(self):
        blank=[[DETECT.sub(lambda x:' '*len(x.group()),l) for l in p] for p in LINES]
        out,_=redact(pdf());self.assert_pii_ink_covered(pdf(),pdf(blank),out);self.assert_pii_ink_covered(pdf(),pdf(blank),out,1)
    def test_04_rotation_and_cropbox_honoured(self):
        blank=[[DETECT.sub(lambda x:' '*len(x.group()),l) for l in p] for p in LINES]
        for kw in ({'rotate':90},{'rotate':270},{'cropbox':(36,300,600,780)},{'mediabox':(100,50,712,842)}):
            out,_=redact(pdf(**kw));self.assert_pii_ink_covered(pdf(**kw),pdf(blank,**kw),out)
            r=PdfReader(io.BytesIO(out));w,h=pdfium.PdfDocument(pdf(**kw))[0].get_size()
            self.assertEqual((float(r.pages[0].mediabox.width),float(r.pages[0].mediabox.height)),(round(w,4),round(h,4)))
    def test_05_no_findings_still_rasterizes(self):
        out,_=redact(pdf(),[]);self.assertEqual(len(PdfReader(io.BytesIO(out)).pages),2)
    def test_06_handle_roundtrip_and_digest(self):
        data=pdf();b64=base64.b64encode(data).decode()
        u=m.handle({'kind':'pdf','data':b64,'mode':'units'},data);self.assertEqual(u['format'],'aidr-pdf-units-v1');self.assertEqual(u['pages'],2)
        a=m.handle({'kind':'pdf','data':b64,'mode':'apply','edits':edits_for(u['units']),'unitsDigest':u['unitsDigest']},data);self.assertEqual(a['format'],'aidr-pdf-redacted-v1')
        out=base64.b64decode(a['data']);v=m.handle({'kind':'pdf','data':a['data'],'mode':'verify'},out)
        self.assertEqual(v['format'],'aidr-pdf-verify-v1');self.assertEqual(v['pages'],2);self.assertEqual(v['units'],['',''])
        self.assertFalse(any(s.strip() for s in v['segments']))
        rejects(self,'REDACT_UNITS_CHANGED',lambda:m.handle({'kind':'pdf','data':b64,'mode':'apply','edits':[],'unitsDigest':'0'*64},data))
    def test_07_verify_refuses_anything_but_the_writer_shape(self):
        rejects(self,'REDACT_VALIDATION',lambda:m.verify_pdf_output(pdf()))
        rejects(self,'REDACT_VALIDATION',lambda:m.verify_pdf_output(pdf(info=False)))
    def test_08_bad_edits_fail_closed(self):
        d=m.PdfDoc(m.Parser(),pdf());n=len(d.units[0])
        try:
            for bad in ([[0,0,n+1,'[X]']],[[2,0,1,'[X]']],[[0,5,5,'[X]']],[[0,0,4,'bad\n']],[[0,0,4,'\x00']],[[0,0,6,'[X]'],[0,3,8,'[X]']],[['0',0,1,'[X]']]):rejects(self,'REDACT_EDITS',lambda:d.boxes(bad))
            crlf=d.units[0].index('\r\n');rejects(self,'PDF_REDACT_UNMAPPED',lambda:d.boxes([[0,crlf,crlf+2,'[X]']]))
        finally:d.close()
    def test_09_inline_image_rejected(self):
        rejects(self,'PDF_ACTIVE_OR_IMAGE',lambda:m.PdfDoc(m.Parser(),pdf(extra=b'q 10 0 0 10 300 300 cm BI /W 1 /H 1 /CS /G /BPC 8 ID \x80 EI Q\n')))
    def test_10_extractor_disagreement_rejected(self):
        with mock.patch.object(m.Parser,'pdf',lambda self,b:['Email: other@example.com','Page two bob@example.org']):rejects(self,'PDF_TEXT_MISMATCH',lambda:m.PdfDoc(m.Parser(),pdf()))
        with mock.patch.object(m.Parser,'pdf',lambda self,b:['only one page']):rejects(self,'PDF_PAGE_MISMATCH',lambda:m.PdfDoc(m.Parser(),pdf()))
    def test_11_unmappable_unicode_rejected(self):
        with mock.patch.object(m.pdfium_c,'FPDFText_HasUnicodeMapError',lambda tp,i:1):rejects(self,'PDF_TEXT_UNMAPPABLE',lambda:m.PdfDoc(m.Parser(),pdf()))
    def test_12_char_without_box_rejected(self):
        d=m.PdfDoc(m.Parser(),pdf())
        try:
            with mock.patch.object(type(d.pages[0][1]),'get_charbox',lambda self,i,loose=False:(0.0,0.0,0.0,0.0)):rejects(self,'PDF_REDACT_UNMAPPED',lambda:d.boxes(edits_for(d.units)))
        finally:d.close()
    def test_13_oversized_page_rejected(self):
        rejects(self,'PDF_PAGE_TOO_LARGE',lambda:redact(pdf(mediabox=(0,0,14400,14400))))
    def test_14_text_path_safety_checks_still_apply(self):
        from pypdf import PdfWriter
        w=PdfWriter();w.add_blank_page(width=100,height=100);b=io.BytesIO();w.write(b);rejects(self,'PDF_OCR_REQUIRED',lambda:m.PdfDoc(m.Parser(),b.getvalue()))
        w=PdfWriter();w.append(io.BytesIO(pdf()))
        with warnings.catch_warnings():warnings.simplefilter('ignore',DeprecationWarning);w.add_js('app.alert(1)')
        b=io.BytesIO();w.write(b);rejects(self,'PDF_ACTIVE_OR_IMAGE',lambda:m.PdfDoc(m.Parser(),b.getvalue()))
        rejects(self,'FORMAT_MISMATCH',lambda:m.PdfDoc(m.Parser(),b'PK\x03\x04'))
    def test_15_residual_text_in_output_rejected(self):
        with mock.patch.object(m,'verify_pdf_output',lambda b:(['left jane@example.com'],[''])):rejects(self,'REDACTION_RESIDUAL',lambda:redact(pdf(pages=[LINES[0]])))

if __name__=='__main__':unittest.main()
