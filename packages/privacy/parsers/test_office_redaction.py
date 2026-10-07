"""Format-preserving OOXML redaction tests. Fixtures are generated programmatically (no blobs).
The production detector is the TypeScript PrivacyEngine; these unit tests stand in a tiny
regex detector (EMAIL / 16-digit card) purely to drive the worker's apply logic. The TypeScript
test tests/platform/office-redaction.test.mjs exercises the real detector end to end."""
import unittest,io,zipfile,re,base64,pathlib,importlib.util
ROOT=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cdr_worker_office',ROOT/'worker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
R='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
S='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
A='http://schemas.openxmlformats.org/drawingml/2006/main'
P='http://schemas.openxmlformats.org/presentationml/2006/main'
PR='http://schemas.openxmlformats.org/package/2006/relationships'
RT='http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
CT='http://schemas.openxmlformats.org/package/2006/content-types'
DETECT=re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|\b\d{16}\b')

def package(entries):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
  for name,data in entries:z.writestr(name,data)
 return b.getvalue()
def rels(items):
 return '<Relationships xmlns="%s">%s</Relationships>'%(PR,''.join('<Relationship Id="rId%d" Type="%s%s" Target="%s"/>'%(i+1,RT if not t.startswith('http') else '',t,target) for i,(t,target) in enumerate(items)))
def types(overrides):
 return ('<Types xmlns="%s"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="jpeg" ContentType="image/jpeg"/>'%CT
  +''.join('<Override PartName="/%s" ContentType="%s"/>'%(n,c) for n,c in overrides)+'<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>')
CORE=('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
      '<dc:creator>Jane Doe</dc:creator><cp:lastModifiedBy>meta.owner@example.com</cp:lastModifiedBy></cp:coreProperties>')
APP='<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Secret Corp</Company></Properties>'
def root_rels(main):
 return rels([('officeDocument',main),('http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties','docProps/core.xml'),('extended-properties','docProps/app.xml'),('http://schemas.openxmlformats.org/package/2006/relationships/metadata/thumbnail','docProps/thumbnail.jpeg')])

def docx(body=None,extra=None,ignorable='w14'):
 body=body or ('<w:p><w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">Contact: jane.doe@exa</w:t></w:r><w:r><w:rPr><w:i/></w:rPr><w:t>mple.com today</w:t></w:r></w:p>'
  '<w:p><w:ins w:id="1" w:author="Jane Doe" w:date="2026-01-01T00:00:00Z"><w:r><w:t>added ins.user@example.com</w:t></w:r></w:ins>'
  '<w:del w:id="2" w:author="Jane Doe" w:date="2026-01-01T00:00:00Z"><w:r><w:delText>deleted.user@example.com</w:delText></w:r></w:del></w:p>'
  '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> HYPERLINK "mailto:field.user@example.com" </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r>'
  '<w:commentRangeStart w:id="0"/><w:r><w:t>see note</w:t></w:r><w:commentRangeEnd w:id="0"/><w:r><w:commentReference w:id="0"/></w:r>'
  '<w:r><w:footnoteReference w:id="1"/></w:r></w:p>'
  '<w:p><w:fldSimple w:instr=" HYPERLINK &quot;mailto:simple.field@example.com&quot; "><w:r><w:t>link</w:t></w:r></w:fldSimple></w:p>'
  '<w:p><w:r><w:drawing><wp:inline><wp:docPr id="1" name="Shape 1" descr="photo of jane.alt@example.com"/></wp:inline></w:drawing></w:r></w:p>'
  '<w:sectPr><w:headerReference w:type="default" r:id="rId3"/></w:sectPr>')
 doc=('<w:document xmlns:w="%s" xmlns:r="%s" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
      'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml" xmlns:wp14="http://schemas.microsoft.com/office/word/2010/wordprocessingDrawing" mc:Ignorable="%s"><w:body>%s</w:body></w:document>')%(W,R,ignorable,body)
 wt='application/vnd.openxmlformats-officedocument.wordprocessingml.'
 return package([('[Content_Types].xml',types([('word/document.xml',wt+'document.main+xml'),('word/comments.xml',wt+'comments+xml'),('word/header1.xml',wt+'header+xml'),('word/footnotes.xml',wt+'footnotes+xml'),('word/settings.xml',wt+'settings+xml')])),
  ('_rels/.rels',root_rels('word/document.xml')),
  ('word/document.xml',doc),
  ('word/_rels/document.xml.rels',rels([('comments','comments.xml'),('footnotes','footnotes.xml'),('header','header1.xml'),('settings','settings.xml')])),
  ('word/comments.xml','<w:comments xmlns:w="%s"><w:comment w:id="0" w:author="Jane Doe" w:initials="JD"><w:p><w:r><w:t>Reviewer: comment.user@example.com</w:t></w:r></w:p></w:comment></w:comments>'%W),
  ('word/footnotes.xml','<w:footnotes xmlns:w="%s"><w:footnote w:id="1"><w:p><w:r><w:t>Source: foot.user@example.com</w:t></w:r></w:p></w:footnote></w:footnotes>'%W),
  ('word/header1.xml','<w:hdr xmlns:w="%s"><w:p><w:r><w:t>Header head.user@</w:t></w:r><w:r><w:t>example.com</w:t></w:r></w:p></w:hdr>'%W),
  ('word/settings.xml','<w:settings xmlns:w="%s"><w:docVars><w:docVar w:name="owner" w:val="var.user@example.com"/></w:docVars></w:settings>'%W),
  ('docProps/core.xml',CORE),('docProps/app.xml',APP),('docProps/thumbnail.jpeg',b'\xff\xd8\xff\xe0thumb')]+(extra or []))

def xlsx(sheet_name='Data',sheet=None,extra_wb=''):
 sheet=sheet or ('<sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1"><v>4111111111111111</v></c>'
  '<c r="C1" t="str"><f>A1&amp;"!"</f><v>sheet.user@example.com!</v></c>'
  '<c r="D1" t="inlineStr"><is><t>inline.user@example.com</t></is></c><c r="E1"><v>42</v></c></row></sheetData>'
  '<headerFooter><oddHeader>&amp;LOwner foot.user@example.com</oddHeader></headerFooter>')
 st='application/vnd.openxmlformats-officedocument.spreadsheetml.'
 return package([('[Content_Types].xml',types([('xl/workbook.xml',st+'sheet.main+xml'),('xl/worksheets/sheet1.xml',st+'worksheet+xml'),('xl/sharedStrings.xml',st+'sharedStrings+xml')])),
  ('_rels/.rels',root_rels('xl/workbook.xml')),
  ('xl/workbook.xml','<workbook xmlns="%s" xmlns:r="%s"><sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets>%s</workbook>'%(S,R,sheet_name,extra_wb)),
  ('xl/_rels/workbook.xml.rels',rels([('worksheet','worksheets/sheet1.xml'),('sharedStrings','sharedStrings.xml')])),
  ('xl/sharedStrings.xml','<sst xmlns="%s" count="1" uniqueCount="1"><si><r><rPr><b/></rPr><t>shared.user@exa</t></r><r><t>mple.com</t></r></si></sst>'%S),
  ('xl/worksheets/sheet1.xml','<worksheet xmlns="%s">%s</worksheet>'%(S,sheet)),
  ('docProps/core.xml',CORE),('docProps/app.xml',APP),('docProps/thumbnail.jpeg',b'\xff\xd8\xff\xe0thumb')])

def pptx(cnvpr='<p:cNvPr id="2" name="Title" descr="alt slide.alt@example.com"/>',run='<a:rPr b="1"/>'):
 pt='application/vnd.openxmlformats-officedocument.presentationml.'
 ns='xmlns:a="%s" xmlns:p="%s" xmlns:r="%s"'%(A,P,R)
 return package([('[Content_Types].xml',types([('ppt/presentation.xml',pt+'presentation.main+xml'),('ppt/slides/slide1.xml',pt+'slide+xml'),('ppt/notesSlides/notesSlide1.xml',pt+'notesSlide+xml'),('ppt/commentAuthors.xml',pt+'commentAuthors+xml'),('ppt/comments/comment1.xml',pt+'comments+xml')])),
  ('_rels/.rels',root_rels('ppt/presentation.xml')),
  ('ppt/presentation.xml','<p:presentation %s><p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>'%ns),
  ('ppt/_rels/presentation.xml.rels',rels([('slide','slides/slide1.xml'),('commentAuthors','commentAuthors.xml')])),
  ('ppt/slides/slide1.xml','<p:sld %s><p:cSld><p:spTree><p:sp><p:nvSpPr>%s</p:nvSpPr><p:txBody><a:p><a:r>%s<a:t>Mail slide.user@exa</a:t></a:r><a:r><a:t>mple.com now</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>'%(ns,cnvpr,run)),
  ('ppt/slides/_rels/slide1.xml.rels',rels([('notesSlide','../notesSlides/notesSlide1.xml'),('comments','../comments/comment1.xml')])),
  ('ppt/notesSlides/notesSlide1.xml','<p:notes %s><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>Speaker notes.user@example.com</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>'%ns),
  ('ppt/notesSlides/_rels/notesSlide1.xml.rels',rels([('slide','../slides/slide1.xml')])),
  ('ppt/commentAuthors.xml','<p:cmAuthorLst %s><p:cmAuthor id="0" name="Jane Doe" initials="JD" lastIdx="1" clrIdx="0"/></p:cmAuthorLst>'%ns),
  ('ppt/comments/comment1.xml','<p:cmLst %s><p:cm authorId="0" idx="1"><p:pos x="0" y="0"/><p:text>ping comment.user@example.com</p:text></p:cm></p:cmLst>'%ns),
  ('docProps/core.xml',CORE),('docProps/app.xml',APP),('docProps/thumbnail.jpeg',b'\xff\xd8\xff\xe0thumb')])

def edits_for(units,rep=lambda s:'[CREDIT_CARD]' if s.isdigit() else '[EMAIL]'):
 out=[]
 for i,t in enumerate(units):
  for x in DETECT.finditer(t):out.append([i,x.start(),x.end(),rep(x.group())])
 return out
def attribute_units(d):
 """Texts of the protected units made only of attribute values (and virtual separators)."""
 return [u.text() for u in d.units if not u.editable and all(e is None or isinstance(w,tuple) for e,w in u.nodes)]
def entries(b):
 with zipfile.ZipFile(io.BytesIO(b)) as z:return {n:z.read(n) for n in z.namelist()}
def round_trip(b,kind):
 d=m.OfficeDoc(m.Parser(),b,kind);out=d.redact(edits_for(d.texts()));return d,out

class OfficeRedactionTests(unittest.TestCase):
 def assertClean(self,out,kind):
  # Same extractor re-scan: TXT segments and every unit of the re-parsed output must be clean.
  p=m.Parser();d=m.OfficeDoc(p,out,kind);d.check_package()
  for t in p.segments+d.texts():self.assertIsNone(DETECT.search(t),t)
  blob=b''.join(entries(out).values())
  self.assertNotIn(b'example.com',blob);self.assertNotIn(b'Jane Doe',blob);self.assertNotIn(b'4111111111111111',blob)
  self.assertFalse(any(n.startswith('docProps/') for n in entries(out)))

 def test_01_docx_split_run_tracked_changes_comments_header_footnote_metadata(self):
  d,out=round_trip(docx(),'docx');self.assertClean(out,'docx')
  doc=entries(out)['word/document.xml'].decode()
  # Split-run PII: the replacement lands in the first (bold) run, the italic run keeps its tail.
  self.assertIn('<w:b/></w:rPr><w:t xml:space="preserve">Contact: [EMAIL]</w:t>',doc)
  self.assertIn('<w:i/></w:rPr><w:t xml:space="preserve"> today</w:t>',doc)
  self.assertIn('<w:t>added [EMAIL]</w:t>',doc) # tracked insertion
  self.assertIn('<w:delText>[EMAIL]</w:delText>',doc) # tracked deletion is redacted, not left hidden
  self.assertIn('HYPERLINK "mailto:[EMAIL]" </w:instrText>',doc)
  self.assertIn('w:instr=" HYPERLINK &quot;mailto:[EMAIL]&quot; "',doc)
  self.assertIn('w:author="AIDR"',doc);self.assertNotIn('descr=',doc)
  # Unused-but-Ignorable prefix keeps its declaration and original prefix.
  self.assertIn('xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"',doc);self.assertIn('mc:Ignorable="w14"',doc)
  e=entries(out)
  self.assertIn(b'[EMAIL]',e['word/comments.xml']);self.assertIn(b'w:initials="A"',e['word/comments.xml'])
  self.assertIn(b'[EMAIL]',e['word/footnotes.xml']);self.assertIn(b'[EMAIL]',e['word/header1.xml'])
  self.assertNotIn(b'docVar',e['word/settings.xml'])
  self.assertNotIn(b'docProps',e['_rels/.rels']);self.assertNotIn(b'docProps',e['[Content_Types].xml'])

 def test_02_xlsx_shared_inline_numeric_header_and_formula_cache(self):
  d,out=round_trip(xlsx(),'xlsx');self.assertClean(out,'xlsx')
  e=entries(out);sheet=e['xl/worksheets/sheet1.xml'].decode();wb=e['xl/workbook.xml'].decode()
  self.assertIn('<si><r><rPr><b/></rPr><t>[EMAIL]</t></r><r><t/></r></si>',e['xl/sharedStrings.xml'].decode())
  self.assertIn('<c r="B1" t="inlineStr"><is><t>[CREDIT_CARD]</t></is></c>',sheet)
  self.assertIn('<c r="C1"><f>A1&amp;"!"</f></c>',sheet) # cached value blanked, formula kept
  self.assertIn('<c r="E1"><v>42</v></c>',sheet)
  self.assertIn('fullCalcOnLoad="1"',wb);self.assertIn('<sheets>',wb)
  self.assertLess(wb.index('</sheets>'),wb.index('calcPr'))

 def test_03_pptx_slide_notes_comments_authors_alt_text(self):
  d,out=round_trip(pptx(),'pptx');self.assertClean(out,'pptx')
  e=entries(out);slide=e['ppt/slides/slide1.xml'].decode()
  self.assertIn('<a:rPr b="1"/><a:t>Mail [EMAIL]</a:t>',slide);self.assertIn('<a:t> now</a:t>',slide);self.assertNotIn('descr',slide)
  self.assertIn(b'name="AIDR"',e['ppt/commentAuthors.xml']);self.assertIn(b'[EMAIL]',e['ppt/comments/comment1.xml']);self.assertIn(b'[EMAIL]',e['ppt/notesSlides/notesSlide1.xml'])

 def test_04_formula_text_with_pii_is_rejected_not_rewritten(self):
  b=xlsx(sheet='<sheetData><row r="1"><c r="A1"><f>"formula.user@example.com"</f><v>0</v></c></row></sheetData>')
  d=m.OfficeDoc(m.Parser(),b,'xlsx')
  with self.assertRaises(m.Rejected) as c:d.redact(edits_for(d.texts()))
  self.assertEqual(str(c.exception),'REDACT_PROTECTED_TEXT')

 def test_05_sheet_name_and_defined_name_are_protected(self):
  for b in (xlsx(sheet_name='owner.user@example.com'),xlsx(extra_wb='<definedNames><definedName name="x">"dn.user@example.com"</definedName></definedNames>')):
   d=m.OfficeDoc(m.Parser(),b,'xlsx')
   with self.assertRaises(m.Rejected) as c:d.redact(edits_for(d.texts()))
   self.assertEqual(str(c.exception),'REDACT_PROTECTED_TEXT')

 def test_06_existing_safety_checks_still_apply(self):
  for extra,reason in (([('word/vbaProject.bin',b'x')],'EMBEDDED'),([('word/media/image1.png',b'x')],'EMBEDDED'),([('customXml/item1.xml','<a/>')],'EMBEDDED')):
   with self.assertRaises(m.Rejected) as c:m.OfficeDoc(m.Parser(),docx(extra=extra),'docx')
   self.assertIn(reason,str(c.exception))
  b=docx(extra=[('word/_rels/header1.xml.rels',rels([('hyperlink','https://outside.example')]))])
  with self.assertRaises(m.Rejected) as c:m.OfficeDoc(m.Parser(),b,'docx')
  self.assertIn('EXTERNAL',str(c.exception))

 def test_07_unlisted_parts_rejected(self):
  for name in ('word/glossary/document.xml','xl/tables/table1.xml'):
   with self.assertRaises(m.Rejected) as c:m.OfficeDoc(m.Parser(),docx(extra=[(name,'<x/>')]),'docx')
   self.assertEqual(str(c.exception),'REDACT_UNSUPPORTED_PART')
  with self.assertRaises(m.Rejected):m.OfficeDoc(m.Parser(),docx(),'pdf')

 def test_08_invalid_edits_fail_closed(self):
  d=m.OfficeDoc(m.Parser(),docx(),'docx');n=len(d.texts()[0])
  for bad in ([[0,0,n+5,'[EMAIL]']],[[0,5,2,'[EMAIL]']],[[0,0,4,'x'],[0,2,6,'y']],[[0,0,1,'\x00']],[[0,0,1,'x'*201]],[[99999,0,1,'x']],[[-1,0,1,'x']],[[0,True,1,'x']],[[0,0,1]],'nope'):
   with self.assertRaises(m.Rejected):m.OfficeDoc(m.Parser(),docx(),'docx').redact(bad)

 def test_09_xml_markup_in_replacement_is_escaped_not_injected(self):
  d=m.OfficeDoc(m.Parser(),docx(),'docx');i=next(i for i,t in enumerate(d.texts()) if t.startswith('Contact'))
  out=d.redact([[i,0,1,'<w:t>&']])
  self.assertIn(b'&lt;w:t&gt;&amp;',entries(out)['word/document.xml'])

 def test_10_dangling_relationship_fails_validation(self):
  b=docx(extra=[('word/_rels/header1.xml.rels',rels([('footer','footer9.xml')]))])
  with self.assertRaises(m.Rejected) as c:m.OfficeDoc(m.Parser(),b,'docx').redact([])
  self.assertEqual(str(c.exception),'REDACT_VALIDATION')

 def test_11_namespace_prefix_conflict_rejected(self):
  body='<w:p><w:r><w:t>x</w:t></w:r><x:y xmlns:x="urn:a"><x:z xmlns:x="urn:b"/></x:y></w:p>'
  with self.assertRaises(m.Rejected) as c:m.OfficeDoc(m.Parser(),docx(body=body),'docx')
  self.assertEqual(str(c.exception),'REDACT_NAMESPACE_CONFLICT')

 def test_12_handle_protocol_round_trip_and_digest_binding(self):
  data=docx();units=m.handle({'kind':'docx','mode':'units'},data)
  self.assertEqual(units['format'],'aidr-office-units-v1')
  with self.assertRaises(m.Rejected) as c:m.handle({'kind':'docx','mode':'apply','edits':[],'unitsDigest':'0'*64},data)
  self.assertEqual(str(c.exception),'REDACT_UNITS_CHANGED')
  r=m.handle({'kind':'docx','mode':'apply','edits':edits_for(units['units']),'unitsDigest':units['unitsDigest']},data)
  out=base64.b64decode(r['data']);v=m.handle({'kind':'docx','mode':'verify'},out)
  for t in v['segments']+v['units']:self.assertIsNone(DETECT.search(t))
  with self.assertRaises(m.Rejected):m.handle({'kind':'docx','mode':'units','edits':[]},data)
  with self.assertRaises(m.Rejected):m.handle({'kind':'docx','mode':'bogus'},data)

 def test_13_missed_span_is_visible_to_verification(self):
  # If the detector misses something, the verify views still expose it so the caller fails closed.
  d=m.OfficeDoc(m.Parser(),docx(),'docx');out=d.redact([])
  v=m.handle({'kind':'docx','mode':'verify'},out)
  self.assertTrue(any(DETECT.search(t) for t in v['units']))
  self.assertTrue(any('jane.doe@exa' in t for t in v['segments']))

 def test_14_output_is_deterministic(self):
  self.assertEqual(round_trip(docx(),'docx')[1],round_trip(docx(),'docx')[1])

 # Attribute values are content: PII in a non-structural attribute must reject the file (it cannot
 # be rewritten safely) and must be visible to the verify views if it ever survives.
 ATTR_CASES={
  'docx':[(docx,'<w:p><w:hyperlink w:anchor="sec1" w:tooltip="tooltip.user@example.com"><w:r><w:t>link</w:t></w:r></w:hyperlink></w:p>'),
   (docx,'<w:sdt><w:sdtPr><w:alias w:val="alias.user@example.com"/></w:sdtPr><w:sdtContent><w:p><w:r><w:t>x</w:t></w:r></w:p></w:sdtContent></w:sdt>'),
   (docx,'<w:sdt><w:sdtPr><w:tag w:val="4111111111111111"/></w:sdtPr><w:sdtContent><w:p><w:r><w:t>x</w:t></w:r></w:p></w:sdtContent></w:sdt>'),
   (docx,'<w:sdt><w:sdtPr><w:date w:fullDate="dob.user@example.com"><w:dateFormat w:val="M/d/yyyy"/></w:date></w:sdtPr><w:sdtContent><w:p><w:r><w:t>x</w:t></w:r></w:p></w:sdtContent></w:sdt>'),
   (docx,'<w:p><w:bookmarkStart w:id="0" w:name="bm.user@example.com"/><w:r><w:t>plain</w:t></w:r><w:bookmarkEnd w:id="0"/></w:p>'),
   (docx,'<w:p><w:r><w:drawing><wp:inline><wp:docPr id="1" name="name.user@example.com"/></wp:inline></w:drawing></w:r></w:p>'),
   # Structural attribute names do not exempt a value that is not shaped like a structural token.
   (docx,'<w:p w:rsidR="rsid.user@example.com"><w:r><w:t>x</w:t></w:r></w:p>'),
   (docx,'<w:p><w:r><w:rPr><w:sz w:val="4111111111111111"/></w:rPr><w:t>x</w:t></w:r></w:p>'),
   (docx,'<w:p><w:r><w:rPr><w:unknownThing w:whatever="unknown.user@example.com"/></w:rPr><w:t>x</w:t></w:r></w:p>')],
  'xlsx':[(lambda b:xlsx(sheet=b),'<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>a</t></is></c></row></sheetData><hyperlinks><hyperlink ref="A1" location="Data!A1" display="disp.user@example.com"/></hyperlinks>'),
   (lambda b:xlsx(sheet=b),'<sheetData><row r="1"><c r="A1"><f ref="4111111111111111">1+1</f></c></row></sheetData>'),
   (lambda b:xlsx(extra_wb=b),'<definedNames><definedName name="x" comment="dn.comment@example.com">Data!$A$1</definedName></definedNames>')],
  'pptx':[(lambda b:pptx(cnvpr=b),'<p:cNvPr id="2" name="shape.user@example.com"/>'),
   (lambda b:pptx(run=b),'<a:rPr b="1"><a:hlinkClick r:id="" tooltip="tip.user@example.com"/></a:rPr>')],
 }
 def test_15_pii_in_non_structural_attribute_rejects(self):
  for kind,cases in self.ATTR_CASES.items():
   for build,markup in cases:
    with self.subTest(kind=kind,markup=markup):
     d=m.OfficeDoc(m.Parser(),build(markup),kind)
     self.assertTrue(any(DETECT.search(t) for t in d.texts()),'attribute value not offered for scanning')
     with self.assertRaises(m.Rejected) as c:d.redact(edits_for(d.texts()))
     self.assertEqual(str(c.exception),'REDACT_PROTECTED_TEXT')

 def test_16_residual_attribute_value_is_visible_to_verification(self):
  for kind,cases in self.ATTR_CASES.items():
   for build,markup in cases:
    with self.subTest(kind=kind,markup=markup):
     data=build(markup);d=m.OfficeDoc(m.Parser(),data,kind)
     # Redact only the editable units, so the attribute value survives into the output.
     edits=[x for x in edits_for(d.texts()) if d.units[x[0]].editable]
     out=m.OfficeDoc(m.Parser(),data,kind).redact(edits)
     v=m.handle({'kind':kind,'mode':'verify'},out)
     self.assertTrue(any(DETECT.search(t) for t in v['segments']+v['units']),'residual attribute value invisible to verify')

 def test_17_structural_attributes_do_not_create_units_or_false_rejects(self):
  body=('<w:p w:rsidR="00A1B2C3" w:rsidRDefault="00A1B2C3" w:rsidP="00123456" w14:paraId="1A2B3C4D" w14:textId="77777777">'
   '<w:pPr><w:pStyle w:val="Heading1"/><w:spacing w:before="240" w:after="120" w:line="276" w:lineRule="auto"/><w:jc w:val="center"/><w:ind w:left="720" w:hanging="360"/></w:pPr>'
   '<w:r w:rsidRPr="00FF00AA"><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:b/><w:color w:val="FF0000" w:themeColor="accent1"/><w:sz w:val="28"/><w:lang w:val="en-US" w:eastAsia="ja-JP"/></w:rPr><w:t>Hello jane.doe@example.com</w:t></w:r>'
   '<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:bookmarkStart w:id="0" w:name="_GoBack"/><w:bookmarkEnd w:id="0"/></w:p>'
   '<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/><w:tblLook w:val="04A0" w:firstRow="1"/></w:tblPr><w:tblGrid><w:gridCol w:w="4675"/></w:tblGrid>'
   '<w:tr w:rsidR="00A1B2C3"><w:tc><w:tcPr><w:tcW w:w="4675" w:type="dxa"/><w:vMerge w:val="restart"/></w:tcPr><w:p><w:r><w:t>cell</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
   '<w:p><w:r><w:drawing><wp:anchor distT="0" distB="0" distL="114300" distR="114300" simplePos="0" relativeHeight="251659264" behindDoc="0" locked="0" layoutInCell="1" allowOverlap="1" wp14:anchorId="0A1B2C3D" wp14:editId="4E5F6A7B">'
   '<wp:extent cx="5943600" cy="3962400"/><wp:docPr id="1" name="Picture 1"/></wp:anchor></w:drawing></w:r></w:p>'
   '<w:sectPr w:rsidR="00A1B2C3"><w:headerReference w:type="default" r:id="rId3"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>')
  d=m.OfficeDoc(m.Parser(),docx(body=body,ignorable='w14 wp14'),'docx')
  # Only free-text values (bookmark/shape names) and a 9-digit number (fails the structural shape
  # check, scanned clean) are offered; ids, rsids, formatting, fonts, sizes, borders, relationship
  # ids and declared mc prefix lists are not. Default header/comment/footnote parts add nothing.
  # All scanned values of one part share ONE protected unit, separated by virtual line breaks.
  self.assertEqual(attribute_units(d),['_GoBack\n251659264\nPicture 1'])
  out=d.redact(edits_for(d.texts()));self.assertClean(out,'docx')
  doc=entries(out)['word/document.xml'].decode()
  for kept in ('w:rsidR="00A1B2C3"','w14:paraId="1A2B3C4D"','<w:sz w:val="28"/>','r:id="rId3"','mc:Ignorable="w14 wp14"','wp14:anchorId="0A1B2C3D"','w:name="_GoBack"','w:ascii="Calibri"'):self.assertIn(kept,doc)
  # pptx/xlsx defaults are clean of attribute findings and round-trip without a protected reject.
  self.assertClean(round_trip(pptx(cnvpr='<p:cNvPr id="2" name="Title 1"/>',run='<a:rPr lang="en-US" sz="2400" b="1" dirty="0"><a:solidFill><a:srgbClr val="FF0000"/></a:solidFill><a:latin typeface="Calibri"/></a:rPr>'),'pptx')[1],'pptx')

 def test_18_mc_attribute_naming_undeclared_prefix_is_scanned(self):
  d=m.OfficeDoc(m.Parser(),docx(ignorable='w14 ign.user@example.com'),'docx')
  self.assertEqual(attribute_units(d),['w14 ign.user@example.com\nShape 1'])
  with self.assertRaises(m.Rejected) as c:d.redact(edits_for(d.texts()))
  self.assertEqual(str(c.exception),'REDACT_PROTECTED_TEXT')

if __name__=='__main__':unittest.main()
