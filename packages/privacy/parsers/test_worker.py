import unittest,io,zipfile,json,base64,subprocess,pathlib,stat,importlib.util
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cdr_worker',ROOT/'worker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def package(entries,compression=zipfile.ZIP_DEFLATED):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w',compression=compression) as z:
  for name,data in entries:z.writestr(name,data)
 return b.getvalue()
def office(kind='docx',extra=None):
 expected={'docx':'word/document.xml','xlsx':'xl/workbook.xml','pptx':'ppt/presentation.xml'}[kind]
 return package([('[Content_Types].xml','<Types/>'),(expected,'<document><p><t>Email: jane@example.com</t></p></document>')]+(extra or []))
class WorkerTests(unittest.TestCase):
 def rejects(self,b,kind,reason=None):
  with self.assertRaises(Exception) as c:m.Parser().parse(b,kind)
  if reason:self.assertIn(reason,str(c.exception))
 def test_01_real_seccomp_blocks_network(self):
  p=subprocess.run(['python3','-I',str(ROOT/'worker.py')],input=b'{"sandboxProbe":true}',capture_output=True,timeout=15);self.assertTrue(json.loads(p.stdout)['networkDenied'])
 def test_02_real_worker_plaintext(self):
  req={'kind':'txt','data':base64.b64encode('E-posta: ali@example.com'.encode()).decode()};p=subprocess.run(['python3','-I',str(ROOT/'worker.py')],input=json.dumps(req).encode(),capture_output=True,timeout=15);r=json.loads(p.stdout);self.assertTrue(r['ok']);self.assertIn('ali@example.com',r['segments'][0]);self.assertEqual(r['sandbox'],'linux-seccomp-no-network-filesystem-open-exec')
 def test_03_office_all_three_formats(self):
  for kind in ('docx','xlsx','pptx'):
   p=m.Parser();p.parse(office(kind),kind);self.assertIn('jane@example.com',''.join(p.segments))
 def test_04_word_comments_and_hidden_text(self):
  p=m.Parser();p.parse(office(extra=[('word/comments.xml','<comments><t>hidden@example.com</t></comments>')]),'docx');self.assertIn('hidden@example.com',''.join(p.segments))
 def test_05_macro(self):self.rejects(office(extra=[('word/vbaProject.bin',b'x')]),'docx','EMBEDDED')
 def test_06_ole(self):self.rejects(office(extra=[('word/embeddings/object.bin',b'x')]),'docx','EMBEDDED')
 def test_07_image_requires_separate_processing(self):self.rejects(office(extra=[('word/media/image.png',b'x')]),'docx','EMBEDDED')
 def test_08_external_relationship(self):self.rejects(office(extra=[('word/_rels/document.xml.rels','<Relationships><Relationship Target="https://outside.example" TargetMode="External"/></Relationships>')]),'docx','EXTERNAL')
 def test_09_dtd_entities(self):self.rejects(office(extra=[('word/comments.xml','<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')]),'docx')
 def test_10_zip_slip(self):self.rejects(package([('../outside.txt','x')]),'zip','PATH')
 def test_11_zip_absolute(self):self.rejects(package([('/outside.txt','x')]),'zip','PATH')
 def test_12_zip_windows_path(self):self.rejects(package([('C:\\outside.txt','x')]),'zip','PATH')
 def test_13_zip_duplicate(self):self.rejects(package([('A.txt','x'),('a.txt','y')]),'zip','DUPLICATE')
 def test_14_zip_bomb(self):self.rejects(package([('bomb.txt','a'*1000000)]),'zip','EXPANSION')
 def test_15_zip_count(self):self.rejects(package([(str(i)+'.txt','x') for i in range(101)]),'zip','FILE_LIMIT')
 def test_16_zip_depth(self):
  b=package([('a.txt','x')])
  for i in range(4):b=package([('inner.zip',b)],zipfile.ZIP_STORED)
  self.rejects(b,'zip','DEPTH')
 def test_17_zip_symlink(self):
  b=io.BytesIO()
  with zipfile.ZipFile(b,'w') as z:
   i=zipfile.ZipInfo('link.txt');i.create_system=3;i.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(i,'/etc/passwd')
  self.rejects(b.getvalue(),'zip','LINK')
 def test_18_zip_unknown_file(self):self.rejects(package([('app.exe',b'MZ')]),'zip','UNSUPPORTED')
 def test_19_zip_filename_scanned(self):
  p=m.Parser();p.parse(package([('jane@example.com.txt','Public text')]),'zip');self.assertIn('jane@example.com.txt',p.segments)
 def test_20_mail_headers_and_body(self):
  p=m.Parser();p.parse(b'From: jane@example.com\r\nTo: ali@example.com\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello bob@example.com','eml');self.assertIn('jane@example.com',''.join(p.segments));self.assertIn('bob@example.com',''.join(p.segments))
 def test_21_html_external(self):self.rejects(b'<img src="https://outside.example/pixel">','html','ACTIVE')
 def test_22_html_safe(self):
  p=m.Parser();p.parse(b'<p>Hello <b>Jane</b></p>','html');self.assertIn('Jane',''.join(p.segments))
 def test_23_binary_text(self):self.rejects(b'\xff\xfe\x00','txt')
 def test_24_pdf_blank_requires_ocr(self):
  from pypdf import PdfWriter
  w=PdfWriter();w.add_blank_page(width=100,height=100);b=io.BytesIO();w.write(b);self.rejects(b.getvalue(),'pdf','OCR')
 def test_25_pdf_password(self):
  from pypdf import PdfWriter
  w=PdfWriter();w.add_blank_page(width=100,height=100);w.encrypt('secret');b=io.BytesIO();w.write(b);self.rejects(b.getvalue(),'pdf','ENCRYPTED')
 def test_26_pdf_javascript(self):
  from pypdf import PdfWriter
  w=PdfWriter();w.add_blank_page(width=100,height=100);w.add_js('app.alert(1)');b=io.BytesIO();w.write(b);self.rejects(b.getvalue(),'pdf','ACTIVE')
 def test_27_pdf_embedded(self):
  from pypdf import PdfWriter
  w=PdfWriter();w.add_blank_page(width=100,height=100);w.add_attachment('secret.txt',b'secret');b=io.BytesIO();w.write(b);self.rejects(b.getvalue(),'pdf','ACTIVE')
 def test_28_pdf_real_text(self):
  from test_pdf_redaction import pdf # hand-written base-14 font PDF; no reportlab dependency
  p=m.Parser();p.parse(pdf([['Email: jane@example.com']]),'pdf');self.assertIn('jane@example.com',''.join(p.segments));self.assertIn('meta.owner@example.com',''.join(p.segments))
 def test_29_office_mismatched_extension(self):self.rejects(office(),'xlsx','MISMATCH')
 def test_30_unsupported_old_office(self):self.rejects(b'\xd0\xcf\x11\xe0','doc','UNSUPPORTED')
 def test_31_limit_large_text(self):self.rejects(b'a'*(m.MAX_TEXT+1),'txt','TEXT_LIMIT')
 def test_32_invalid_xml(self):self.rejects(b'<root><unclosed>','xml')
 def test_33_zip_crc_corrupt(self):
  b=bytearray(package([('a.txt','unique text')],zipfile.ZIP_STORED));i=b.find(b'unique text');b[i]^=1;self.rejects(bytes(b),'zip')
if __name__=='__main__':unittest.main()
