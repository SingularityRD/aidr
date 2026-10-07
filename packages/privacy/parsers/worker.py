#!/usr/bin/env python3
"""One-shot, bounded CDR. By default it is text-only and never returns the original
document container. The opt-in OOXML modes (units/apply/verify) re-serialize a DOCX/XLSX/PPTX
package with detected spans redacted in place; see OfficeDoc below for the exact contract.
Linux seccomp denies network/process creation after importing parsers. This is not
filesystem virtualization: run inside the supplied read-only/no-network container.
"""
import base64, binascii, ctypes, ctypes.util, encodings.cp437, encodings.utf_8_sig, errno, hashlib, io, json, os, posixpath, re, socket, stat, struct, sys, zipfile
try:import resource
except ImportError:resource=None # non-Linux: sandbox() refuses to run, unit tests still import the parser
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import PurePosixPath
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as WriteET # element construction/serialization only; all parsing goes through defusedxml
from pypdf import PdfReader
MAX_INPUT=8*1024*1024; MAX_TEXT=512*1024; MAX_FILES=100; MAX_EXPANDED=16*1024*1024
class Rejected(Exception): pass

def sandbox():
    if sys.platform!='linux': raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
    resource.setrlimit(resource.RLIMIT_CPU,(8,8)); resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
    resource.setrlimit(resource.RLIMIT_FSIZE,(0,0)); resource.setrlimit(resource.RLIMIT_NOFILE,(32,32)); resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    libname=ctypes.util.find_library('seccomp')
    if not libname: raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
    lib=ctypes.CDLL(libname);lib.seccomp_init.argtypes=[ctypes.c_uint32];lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p];lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint];lib.seccomp_rule_add.restype=ctypes.c_int
    lib.seccomp_load.argtypes=[ctypes.c_void_p];lib.seccomp_load.restype=ctypes.c_int;lib.seccomp_release.argtypes=[ctypes.c_void_p]
    ctx=lib.seccomp_init(0x7fff0000)
    if not ctx: raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
    try:
        for name in ('socket','socketpair','connect','bind','listen','accept','accept4','sendto','sendmsg','recvfrom','recvmsg','execve','execveat','fork','vfork','clone','clone3','ptrace','mount','umount2','bpf','keyctl','io_uring_setup','open','openat','openat2','creat','unlink','unlinkat','rename','renameat','renameat2','mkdir','mkdirat','rmdir','link','linkat','symlink','symlinkat','chmod','fchmod','fchmodat','chown','fchown','lchown','fchownat','truncate','ftruncate','process_vm_readv','process_vm_writev','pidfd_open','pidfd_getfd','kill','tgkill','setns','unshare','chroot','pivot_root'):
            n=lib.seccomp_syscall_resolve_name(name.encode())
            if n>=0 and lib.seccomp_rule_add(ctx,0x00050000|errno.EPERM,n,0)!=0: raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
        if lib.seccomp_load(ctx)!=0: raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
    finally: lib.seccomp_release(ctx)

class TextHtml(HTMLParser):
    def __init__(self):super().__init__(convert_charrefs=True);self.text=[]
    def handle_data(self,d):self.text.append(d)
    def handle_starttag(self,tag,attrs):
        # Active/external content is blocked rather than silently ignored.
        if tag.lower() in ('script','style','iframe','object','embed','img','svg','link','base','form'): raise Rejected('HTML_ACTIVE_CONTENT')
        if any(k.lower().startswith('on') or k.lower() in ('src','href','action','style') for k,v in attrs):raise Rejected('HTML_ACTIVE_CONTENT')

class Parser:
    def __init__(self):self.files=0;self.expanded=0;self.segments=[];self.textbytes=0
    def add(self,text):
        if not isinstance(text,str) or '\0' in text:raise Rejected('TEXT_ENCODING')
        self.textbytes+=len(text.encode('utf8'))
        if self.textbytes>MAX_TEXT or len(self.segments)>=1000:raise Rejected('TEXT_LIMIT')
        if text.strip():self.segments.append(text)
    def xml(self,b):
        if len(b)>2*1024*1024:raise Rejected('XML_LIMIT')
        root=ET.fromstring(b);n=0
        for e in root.iter():
            n+=1
            if n>50000:raise Rejected('XML_LIMIT')
        return root
    def zip_entries(self,b):
        z=zipfile.ZipFile(io.BytesIO(b));infos=z.infolist();self.files+=len(infos)
        if self.files>MAX_FILES:raise Rejected('ARCHIVE_FILE_LIMIT')
        seen=set();out={}
        for i in infos:
            name=i.filename
            if not name or '\\' in name or '\0' in name or name.startswith('/') or ':' in name or any(p in ('.','..','') for p in name.rstrip('/').split('/')):raise Rejected('ARCHIVE_PATH')
            folded=name.casefold()
            if folded in seen:raise Rejected('ARCHIVE_DUPLICATE')
            seen.add(folded)
            if i.flag_bits&1 or stat.S_ISLNK(i.external_attr>>16):raise Rejected('ARCHIVE_ENCRYPTED_OR_LINK')
            if i.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise Rejected('ARCHIVE_COMPRESSION')
            self.expanded+=i.file_size
            if self.expanded>MAX_EXPANDED or i.file_size>MAX_INPUT or i.file_size>max(1,i.compress_size)*100:raise Rejected('ARCHIVE_EXPANSION')
            if i.is_dir():continue
            with z.open(i) as f:data=f.read(min(i.file_size+1,MAX_INPUT+1))
            if len(data)!=i.file_size:raise Rejected('ARCHIVE_LENGTH')
            out[name]=data
        return out
    def office(self,b,kind):
        entries=self.zip_entries(b)
        if '[Content_Types].xml' not in entries:raise Rejected('OFFICE_PACKAGE')
        for name,data in entries.items():
            low=name.lower()
            if any(x in low for x in ('vbaproject','embeddings/','activex/','customui/','externallinks/','oleobject','customxml/','_xmlsignatures/','media/')):raise Rejected('OFFICE_EMBEDDED_CONTENT')
            if low.endswith('.rels'):
                root=self.xml(data)
                for e in root.iter():
                    target=e.attrib.get('Target','');mode=e.attrib.get('TargetMode','')
                    if mode.lower()=='external' or re.match(r'^[a-z]+:',target,re.I):raise Rejected('OFFICE_EXTERNAL_RELATIONSHIP')
            elif low.endswith('.xml'):
                root=self.xml(data)
                if name=='[Content_Types].xml' and any('macroenabled' in str(v).lower() or 'oleobject' in str(v).lower() for e in root.iter() for v in e.attrib.values()):raise Rejected('OFFICE_MACRO')
                # Reconstruct semantic text only. Styles, metadata and thumbnails never leave.
                semantic=(re.match(r'^word/(document|comments|footnotes|endnotes|header[0-9]+|footer[0-9]+)\.xml$',name) or re.match(r'^ppt/(slides/slide[0-9]+|notesSlides/notesSlide[0-9]+|comments/comment[0-9]+)\.xml$',name) or re.match(r'^xl/(workbook|sharedStrings|worksheets/sheet[0-9]+|comments[0-9]+)\.xml$',name) or name=='ppt/presentation.xml')
                if semantic:
                    values=[]
                    for e in root.iter():
                        tag=e.tag.rsplit('}',1)[-1]
                        if tag in ('t','v','f','delText','instrText','text') and e.text:values.append(e.text)
                        if tag=='sheet' and e.attrib.get('name'):values.append(e.attrib['name'])
                    if values:self.add('\n'.join(values))
            elif low.startswith('docprops/thumbnail.') and low.rsplit('.',1)[-1] in ('jpeg','jpg','png','wmf'):continue
            else:raise Rejected('OFFICE_UNKNOWN_PART')
        expected={'docx':'word/document.xml','xlsx':'xl/workbook.xml','pptx':'ppt/presentation.xml'}[kind]
        if expected not in entries:raise Rejected('OFFICE_FORMAT_MISMATCH')
        return entries
    def pdf(self,b):
        r=PdfReader(io.BytesIO(b),strict=True)
        if r.is_encrypted:raise Rejected('PDF_ENCRYPTED')
        if len(r.pages)>50:raise Rejected('PDF_PAGE_LIMIT')
        blocked={'/JavaScript','/JS','/OpenAction','/AA','/EmbeddedFiles','/EmbeddedFile','/Filespec','/Launch','/RichMedia','/XFA','/AcroForm','/Collection','/URI','/SubmitForm','/ImportData','/GoToR','/Sound','/Movie','/3D','/ObjStm'}
        seen=set();budget=[0]
        def walk(obj,depth=0):
            if depth>40:raise Rejected('PDF_DEPTH')
            if hasattr(obj,'idnum'):
                key=(obj.idnum,obj.generation)
                if key in seen:return
                seen.add(key);obj=obj.get_object()
            budget[0]+=1
            if budget[0]>50000:raise Rejected('PDF_OBJECT_LIMIT')
            if isinstance(obj,dict):
                if any(str(k) in blocked for k in obj) or str(obj.get('/S','')) in blocked or str(obj.get('/Subtype','')) in ('/Image','/Widget'):raise Rejected('PDF_ACTIVE_OR_IMAGE')
                for k,v in obj.items():
                    if str(k) in ('/Parent','/Prev'):continue
                    walk(v,depth+1)
            elif isinstance(obj,(list,tuple)):
                for v in obj:walk(v,depth+1)
        walk(r.trailer)
        for page in r.pages:
            text=page.extract_text()
            if not text or not text.strip():raise Rejected('PDF_OCR_REQUIRED')
            self.add(text)
        if r.metadata:self.add('\n'.join(str(v) for v in r.metadata.values()))
    def parse(self,b,kind,depth=0):
        if depth>2:raise Rejected('ARCHIVE_DEPTH')
        if len(b)>MAX_INPUT:raise Rejected('INPUT_LIMIT')
        if kind=='pdf':
            if not b.startswith(b'%PDF-'):raise Rejected('FORMAT_MISMATCH')
            self.pdf(b)
        elif kind in ('docx','xlsx','pptx'):self.office(b,kind)
        elif kind=='zip':
            for name,data in self.zip_entries(b).items():
                self.add(name) # File names can themselves contain PII; never preserve originals unscanned.
                suffix=PurePosixPath(name).suffix.lower()[1:];self.parse(data,suffix,depth+1)
        elif kind=='eml':
            msg=BytesParser(policy=policy.default).parsebytes(b)
            parts=list(msg.walk())
            if len(parts)>50 or any(p.defects for p in parts):raise Rejected('MAIL_STRUCTURE')
            self.add('\n'.join(k+': '+str(v) for k,v in msg.items()))
            for p in parts:
                if p.is_multipart():continue
                c=p.get_content_type();payload=p.get_payload(decode=True)
                if payload is None:raise Rejected('MAIL_PAYLOAD')
                if p.get_filename():self.add(str(p.get_filename()))
                if c in ('text/plain','text/html'):
                    text=payload.decode(p.get_content_charset() or 'utf-8','strict')
                    if c=='text/html':h=TextHtml();h.feed(text);self.add('\n'.join(h.text))
                    else:self.add(text)
                else:raise Rejected('MAIL_ATTACHMENT_REQUIRES_SEPARATE_SCAN')
        elif kind in ('txt','md','csv','tsv','json','py','ts','js','rs','go','java','c','cpp','h','yaml','yml','xml','html'):
            text=b.decode('utf-8-sig','strict')
            if kind=='html':h=TextHtml();h.feed(text);text='\n'.join(h.text)
            if kind=='xml':self.xml(b)
            self.add(text)
        else:raise Rejected('UNSUPPORTED_DOCUMENT')

# ---------------------------------------------------------------------------------------------
# Format-preserving OOXML redaction (DOCX/XLSX/PPTX). PDF is deliberately NOT supported here.
#
# Protocol (three separate one-shot invocations, each sandboxed exactly like the text path):
#   units  -> every text-bearing node of the package grouped into "units" (a paragraph, a shared
#             string, a cell value, a formula...). The caller runs the SAME detector it uses for
#             the TXT path over the units and sends back edits.
#   apply  -> the original bytes plus [unit, start, end, replacement] edits (code point offsets in
#             the unit text). Spans may cross run boundaries: the unit keeps a run-offset map.
#   verify -> the redacted output, re-parsed by the unchanged TXT extractor AND the unit extractor,
#             so the caller can re-scan both views and fail closed on any remaining finding.
#
# Fail-closed decisions (documented in docs/PLATFORM_FEATURE_STATUS.md):
#   * only an allowlist of well-understood parts may be present; anything else is rejected;
#   * docProps core/app/custom metadata and thumbnails are dropped (with their relationships);
#   * author/initials/userId/displayName attributes, docVars and drawing alt-text are scrubbed;
#   * EVERY cached formula value <v> is removed and the workbook is marked fullCalcOnLoad, because
#     a formula may derive a value from redacted content; a finding inside formula text itself,
#     a defined name, a sheet name or any other text we cannot rewrite safely rejects the file;
#   * after writing, the package must pass the original safety checks, the allowlist, internal
#     relationship-target and content-type validation, or no output is produced.
# ---------------------------------------------------------------------------------------------
NS_W='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
NS_A='http://schemas.openxmlformats.org/drawingml/2006/main'
NS_S='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
NS_P='http://schemas.openxmlformats.org/presentationml/2006/main'
NS_TC='http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments'
NS_XML='http://www.w3.org/XML/1998/namespace'
NS_REL='http://schemas.openxmlformats.org/package/2006/relationships'
NS_CT='http://schemas.openxmlformats.org/package/2006/content-types'
MAX_UNITS=20000; MAX_EDITS=20000; MAX_XML_DEPTH=200
REDACT_PARTS={
 'docx':(r'word/(document|styles|stylesWithEffects|settings|webSettings|fontTable|numbering|comments|commentsExtended|commentsIds|commentsExtensible|people|footnotes|endnotes|header[0-9]+|footer[0-9]+)\.xml',r'word/theme/theme[0-9]+\.xml'),
 'xlsx':(r'xl/(workbook|styles|sharedStrings|calcChain|metadata|comments[0-9]+)\.xml',r'xl/(worksheets/sheet|theme/theme|threadedComments/threadedComment)[0-9]+\.xml',r'xl/persons/person\.xml'),
 'pptx':(r'ppt/(presentation|presProps|viewProps|tableStyles|commentAuthors|authors)\.xml',r'ppt/(slides/slide|slideLayouts/slideLayout|slideMasters/slideMaster|notesSlides/notesSlide|notesMasters/notesMaster|handoutMasters/handoutMaster|theme/theme|comments/comment)[0-9]+\.xml',r'ppt/comments/modernComment_[0-9A-Fa-f_]{1,80}\.xml')}
DROPPED=re.compile(r'^docProps/(core|app|custom)\.xml$|^docProps/thumbnail\.(jpeg|jpg|png|wmf)$')
RELS=re.compile(r'^(?:(.+)/)?_rels/([^/]+)\.rels$')
CONTAINERS={(NS_W,'p'),(NS_A,'p'),(NS_S,'si'),(NS_S,'is'),(NS_S,'text')}
RUN_TEXT={(NS_W,'t'),(NS_W,'delText'),(NS_A,'t'),(NS_S,'t')}
SELF_TEXT={(NS_TC,'text'),(NS_P,'text')}|{(NS_S,k) for k in ('oddHeader','oddFooter','evenHeader','evenFooter','firstHeader','firstFooter')}
BREAKS={(NS_W,'tab'),(NS_W,'br'),(NS_W,'cr'),(NS_A,'br')}
REVISIONS={(NS_W,k) for k in ('ins','del','moveFrom','moveTo')}
SKIP_TEXT={(NS_W,'docVars'),(NS_S,'author')} # overwritten/removed by scrub(), never emitted as-is
PRESERVE_SPACE={(NS_W,'t'),(NS_W,'delText'),(NS_W,'instrText'),(NS_S,'t')}
ANON={'author':'AIDR','initials':'A','userId':'AIDR','providerId':'None','displayName':'AIDR'}
REPLACEMENT=re.compile(r'^[\x20-\x7e]{0,200}$')

def qn(tag):
    if not isinstance(tag,str):raise Rejected('REDACT_XML_NODE')
    if tag.startswith('{'):u,l=tag[1:].split('}',1);return (u,l)
    return ('',tag)

def namespaces(b):
    """Every prefix declared anywhere in the part, so mc:Ignorable prefixes survive re-serialization."""
    decls=[];seen={}
    for _,(prefix,uri) in ET.iterparse(io.BytesIO(b),events=('start-ns',)):
        if seen.get(prefix,uri)!=uri:raise Rejected('REDACT_NAMESPACE_CONFLICT')
        if prefix not in seen:seen[prefix]=uri;decls.append((prefix,uri))
    return decls

def serialize(root,decls):
    """Deterministic writer that keeps the original prefixes (ElementTree would rename them to ns0...)."""
    pref={};apref={}
    for p,u in decls:
        pref.setdefault(u,p)
        if p:apref.setdefault(u,p)
    default=any(p=='' for p,_ in decls)
    def name(tag,attr):
        u,l=qn(tag)
        if not u:
            if default and not attr:raise Rejected('REDACT_NAMESPACE')
            return l
        if u==NS_XML:return 'xml:'+l
        p=(apref if attr else pref).get(u)
        if p is None:raise Rejected('REDACT_NAMESPACE')
        return p+':'+l if p else l
    def text(s):return s.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('\r','&#13;')
    def attr(s):return text(s).replace('"','&quot;').replace('\n','&#10;').replace('\t','&#9;')
    out=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n']
    def emit(e,depth):
        if depth>MAX_XML_DEPTH:raise Rejected('REDACT_XML_DEPTH')
        n=name(e.tag,False);out.append('<'+n)
        if depth==0:
            for p,u in decls:out.append(' xmlns'+(':'+p if p else '')+'="'+attr(u)+'"')
        for k,v in e.attrib.items():out.append(' '+name(k,True)+'="'+attr(v)+'"')
        if len(e)==0 and not e.text:out.append('/>');return
        out.append('>')
        if e.text:out.append(text(e.text))
        for c in e:
            emit(c,depth+1)
            if c.tail:out.append(text(c.tail))
        out.append('</'+n+'>')
    emit(root,0)
    return ''.join(out).encode('utf-8')

def resolve_target(source,target):
    if not target or '#' in target or '\\' in target:raise Rejected('REDACT_RELATIONSHIP')
    path=target[1:] if target.startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(source),target))
    if path.startswith('..') or path.startswith('/'):raise Rejected('REDACT_RELATIONSHIP')
    return path

class Unit:
    """Ordered text nodes forming one logical string (the run-offset map). A node is
    (element, 'text'|'tail'|('attr',key)) or (None, separator): a virtual tab/break separator that
    is scanned for context but never written back."""
    __slots__=('nodes','editable','cell','instr')
    def __init__(self,editable=True,cell=None):self.nodes=[];self.editable=editable;self.cell=cell;self.instr=None
    @staticmethod
    def get(n):
        e,w=n
        if e is None:return w
        if w=='text':return e.text or ''
        if w=='tail':return e.tail or ''
        return e.attrib.get(w[1],'')
    @staticmethod
    def put(n,v):
        e,w=n
        if w=='text':e.text=v
        elif w=='tail':e.tail=v
        else:e.attrib[w[1]]=v
    def text(self):return ''.join(self.get(n) for n in self.nodes)
    def real(self):return any(e is not None for e,_ in self.nodes)
    def apply(self,edits):
        """edits: sorted, non-overlapping (start,end,replacement) in code points of self.text().
        A span crossing runs is removed from every run it touches; the replacement lands in the
        first real run so formatting of the surrounding text is kept."""
        texts=[self.get(n) for n in self.nodes];total=sum(len(t) for t in texts);pos=0
        for s,e,_ in edits:
            if s<pos or s>=e or e>total:raise Rejected('REDACT_EDITS')
            pos=e
        per=[[] for _ in self.nodes];starts=[];o=0
        for t in texts:starts.append(o);o+=len(t)
        for s,e,rep in edits:
            placed=False
            for i,(node,t) in enumerate(zip(self.nodes,texts)):
                a,b=max(s,starts[i]),min(e,starts[i]+len(t))
                if a>=b or node[0] is None:continue
                per[i].append((a-starts[i],b-starts[i],'' if placed else rep));placed=True
            if not placed:raise Rejected('REDACT_EDITS') # a span made only of virtual separators
        for i,node in enumerate(self.nodes):
            if not per[i]:continue
            t=texts[i]
            for a,b,rep in sorted(per[i],reverse=True):t=t[:a]+rep+t[b:]
            self.put(node,t)
            e,w=node
            if w=='text' and qn(e.tag) in PRESERVE_SPACE and t!=t.strip():e.attrib['{%s}space'%NS_XML]='preserve'

class OfficeDoc:
    def __init__(self,parser,b,kind):
        if kind not in REDACT_PARTS:raise Rejected('REDACT_UNSUPPORTED_FORMAT')
        entries=parser.office(b,kind) # unchanged macro/OLE/external/media/customXML/unknown-part rejection
        allowed=[re.compile('^(?:'+p+')$') for p in REDACT_PARTS[kind]]
        self.kind=kind;self.order=[];self.parts={};self.decls={};self.units=[];self.formula_cells=[];self.dropped=set()
        def ok(name):return any(a.match(name) for a in allowed)
        for name,data in entries.items():
            if DROPPED.match(name):self.dropped.add(name);continue
            m=RELS.match(name)
            if name in ('[Content_Types].xml','_rels/.rels'):pass
            elif m:
                if not ok((m.group(1)+'/' if m.group(1) else '')+m.group(2)):raise Rejected('REDACT_UNSUPPORTED_PART')
            elif not ok(name):raise Rejected('REDACT_UNSUPPORTED_PART')
            self.order.append(name);self.decls[name]=namespaces(data);self.parts[name]=parser.xml(data)
        for name in sorted(self.parts):
            if name!='[Content_Types].xml' and not name.endswith('.rels'):self.collect(self.parts[name])
        self.units=[u for u in self.units if u.real()]
        if len(self.units)>MAX_UNITS:raise Rejected('REDACT_UNIT_LIMIT')
        if sum(len(t.encode('utf8')) for t in self.texts())>MAX_TEXT:raise Rejected('TEXT_LIMIT')
    def texts(self):return [u.text() for u in self.units]
    def digest(self):return hashlib.sha256(json.dumps(self.texts(),ensure_ascii=False).encode('utf8')).hexdigest()
    def collect(self,root):
        units=self.units
        def new(editable=True,cell=None):
            u=Unit(editable,cell);units.append(u);return u
        def walk(e,unit,depth):
            if depth>MAX_XML_DEPTH:raise Rejected('REDACT_XML_DEPTH')
            key=qn(e.tag)
            if key in SKIP_TEXT:return
            if key in CONTAINERS:unit=new()
            if key==(NS_S,'sheet') and e.attrib.get('name'):new(False).nodes.append((e,('attr','name')))
            if key==(NS_W,'fldSimple') and ('{%s}instr'%NS_W) in e.attrib:new().nodes.append((e,('attr','{%s}instr'%NS_W)))
            if key==(NS_S,'c'):
                f=e.find('{%s}f'%NS_S)
                if f is not None:
                    # Cached <v> is always removed (scrub), so it is not offered for editing.
                    self.formula_cells.append(e)
                    if f.text and f.text.strip():new(False).nodes.append((f,'text'))
                    for c in e:
                        if qn(c.tag) not in ((NS_S,'f'),(NS_S,'v')):walk(c,unit,depth+1)
                    return
                v=e.find('{%s}v'%NS_S)
                if v is not None and v.text and e.attrib.get('t')!='s':new(True,e).nodes.append((v,'text'))
                for c in e:
                    if qn(c.tag)!=(NS_S,'v'):walk(c,unit,depth+1)
                return
            if e.text:
                if key in RUN_TEXT:(unit if unit is not None else new()).nodes.append((e,'text'))
                elif key==(NS_W,'instrText'):
                    owner=unit if unit is not None else new()
                    if owner.instr is None:owner.instr=new()
                    owner.instr.nodes.append((e,'text'))
                elif key in SELF_TEXT:new().nodes.append((e,'text'))
                elif e.text.strip():new(False).nodes.append((e,'text')) # opaque text: any finding rejects
            elif key in BREAKS and unit is not None:unit.nodes.append((None,' '))
            # Inserted and deleted revision text never coexist in one rendering: separate them so
            # detection does not glue the end of an insertion to the start of a deletion.
            boundary=key in REVISIONS and unit is not None
            if boundary:unit.nodes.append((None,' '))
            for c in e:
                walk(c,unit,depth+1)
                if c.tail and c.tail.strip():new(False).nodes.append((c,'tail'))
            if boundary:unit.nodes.append((None,' '))
        walk(root,None,0)
    def scrub(self):
        for name,root in self.parts.items():
            if name=='[Content_Types].xml':
                for o in list(root):
                    if qn(o.tag)==(NS_CT,'Override') and o.attrib.get('PartName','').lstrip('/') in self.dropped:root.remove(o)
                continue
            if name.endswith('.rels'):
                for r in list(root):
                    if r.attrib.get('TargetMode','').lower()!='external' and resolve_target(self.source(name),r.attrib.get('Target','')) in self.dropped:root.remove(r)
                continue
            for e in root.iter():
                key=qn(e.tag)
                for k in list(e.attrib):
                    u,l=qn(k)
                    if l in ANON and u!=NS_XML:e.attrib[k]=ANON[l]
                    elif l=='name' and key[1] in ('cmAuthor','author'):e.attrib[k]='AIDR'
                    elif l in ('descr','title') and key[1] in ('docPr','cNvPr'):del e.attrib[k]
                if key==(NS_S,'author'):e.text='AIDR'
                for c in list(e):
                    if qn(c.tag)==(NS_W,'docVars'):e.remove(c)
        for cell in self.formula_cells:
            for v in cell.findall('{%s}v'%NS_S):cell.remove(v)
            cell.attrib.pop('t',None)
        if self.kind=='xlsx' and self.formula_cells:
            wb=self.parts['xl/workbook.xml'];calc=wb.find('{%s}calcPr'%NS_S)
            if calc is None:
                calc=WriteET.Element('{%s}calcPr'%NS_S);at=0
                for i,c in enumerate(wb):
                    if qn(c.tag)[1] in ('sheets','functionGroups','externalReferences','definedNames'):at=i+1
                wb.insert(at,calc)
            calc.attrib['fullCalcOnLoad']='1'
    @staticmethod
    def source(rels):
        if rels=='_rels/.rels':return ''
        m=RELS.match(rels);return (m.group(1)+'/' if m.group(1) else '')+m.group(2)
    def check_package(self):
        """Output validation: nothing dropped may remain, every internal relationship resolves to a
        part in the package, every part has a content type and no Override dangles."""
        if self.dropped:raise Rejected('REDACT_VALIDATION')
        present=set(self.order)
        for name,root in self.parts.items():
            if name.endswith('.rels'):
                for r in root:
                    if qn(r.tag)!=(NS_REL,'Relationship'):raise Rejected('REDACT_VALIDATION')
                    if resolve_target(self.source(name),r.attrib.get('Target','')) not in present:raise Rejected('REDACT_VALIDATION')
        defaults=set();overrides=set()
        for e in self.parts['[Content_Types].xml']:
            k=qn(e.tag)
            if k==(NS_CT,'Default'):defaults.add(e.attrib.get('Extension','').lower())
            elif k==(NS_CT,'Override'):
                part=e.attrib.get('PartName','').lstrip('/')
                if part not in present:raise Rejected('REDACT_VALIDATION')
                overrides.add(part)
        for name in present:
            if name!='[Content_Types].xml' and name not in overrides and name.rsplit('.',1)[-1].lower() not in defaults:raise Rejected('REDACT_VALIDATION')
    def redact(self,edits):
        if not isinstance(edits,list) or len(edits)>MAX_EDITS:raise Rejected('REDACT_EDITS')
        grouped={}
        for x in edits:
            if not isinstance(x,list) or len(x)!=4 or any(type(v) is not int for v in x[:3]) or not isinstance(x[3],str) or not REPLACEMENT.match(x[3]):raise Rejected('REDACT_EDITS')
            if not 0<=x[0]<len(self.units):raise Rejected('REDACT_EDITS')
            if not self.units[x[0]].editable:raise Rejected('REDACT_PROTECTED_TEXT')
            grouped.setdefault(x[0],[]).append((x[1],x[2],x[3]))
        for i,group in grouped.items():
            u=self.units[i];u.apply(sorted(group))
            if u.cell is not None:
                # A redacted literal cell (e.g. a number that is a card/ID) becomes an inline string.
                cell=u.cell;v=u.nodes[0][0];at=list(cell).index(v);value=v.text or ''
                cell.remove(v);cell.attrib['t']='inlineStr'
                inline=WriteET.Element('{%s}is'%NS_S);t=WriteET.SubElement(inline,'{%s}t'%NS_S);t.text=value
                if value!=value.strip():t.attrib['{%s}space'%NS_XML]='preserve'
                cell.insert(at,inline)
        self.scrub()
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w',compression=zipfile.ZIP_DEFLATED) as z:
            for name in sorted(self.order,key=lambda n:n!='[Content_Types].xml'):
                info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;info.external_attr=0o600<<16
                z.writestr(info,serialize(self.parts[name],self.decls[name]))
        out=b.getvalue()
        if len(out)>MAX_INPUT:raise Rejected('REDACT_OUTPUT_LIMIT')
        OfficeDoc(Parser(),out,self.kind).check_package() # re-parse with the unchanged safety checks before release
        return out

def handle(req,data):
    """Dispatch one request after the sandbox is in place."""
    mode=req.get('mode','text');sandbox_id='linux-seccomp-no-network-filesystem-open-exec'
    if mode=='text':
        if set(req)-{'kind','data','sandboxProbe','mode'}:raise Rejected('REQUEST_SCHEMA')
        p=Parser();p.parse(data,req['kind']);return {'ok':True,'format':'aidr-text-cdr-v1','segments':p.segments,'sandbox':sandbox_id,'inputBytes':len(data)}
    if mode=='units':
        if set(req)-{'kind','data','mode'}:raise Rejected('REQUEST_SCHEMA')
        d=OfficeDoc(Parser(),data,req['kind']);return {'ok':True,'format':'aidr-office-units-v1','units':d.texts(),'unitsDigest':d.digest(),'sandbox':sandbox_id,'inputBytes':len(data)}
    if mode=='apply':
        if set(req)-{'kind','data','mode','edits','unitsDigest'}:raise Rejected('REQUEST_SCHEMA')
        d=OfficeDoc(Parser(),data,req['kind'])
        if req.get('unitsDigest')!=d.digest():raise Rejected('REDACT_UNITS_CHANGED')
        out=d.redact(req.get('edits'));return {'ok':True,'format':'aidr-office-redacted-v1','data':base64.b64encode(out).decode('ascii'),'sandbox':sandbox_id,'inputBytes':len(data)}
    if mode=='verify':
        if set(req)-{'kind','data','mode'}:raise Rejected('REQUEST_SCHEMA')
        p=Parser();d=OfficeDoc(p,data,req['kind']);d.check_package()
        return {'ok':True,'format':'aidr-office-verify-v1','segments':p.segments,'units':d.texts(),'sandbox':sandbox_id,'inputBytes':len(data)}
    raise Rejected('REQUEST_SCHEMA')

def main():
    try:
        limit=(MAX_INPUT*4//3)+2048+MAX_EDITS*256 # base64 document plus the bounded apply edits
        raw=sys.stdin.buffer.read(limit+1)
        if len(raw)>limit:raise Rejected('INPUT_LIMIT')
        req=json.loads(raw)
        if not isinstance(req,dict) or set(req)-{'kind','data','sandboxProbe','mode','edits','unitsDigest'}:raise Rejected('REQUEST_SCHEMA')
        sandbox()
        if req.get('sandboxProbe'):
            denied=False
            try:socket.socket()
            except PermissionError:denied=True
            if not denied:raise Rejected('PARSER_SANDBOX_UNAVAILABLE')
            file_denied=False
            try:open('/etc/passwd','rb')
            except PermissionError:file_denied=True
            if not file_denied:raise Rejected('PARSER_FILESYSTEM_NOT_ISOLATED')
            print(json.dumps({'ok':True,'networkDenied':True,'filesystemOpenDenied':True}));return
        data=base64.b64decode(req['data'],validate=True)
        if len(data)>MAX_INPUT:raise Rejected('INPUT_LIMIT')
        print(json.dumps(handle(req,data),ensure_ascii=False))
    except Rejected as e:print(json.dumps({'ok':False,'reason':str(e)}))
    except Exception:print(json.dumps({'ok':False,'reason':'PARSER_REJECTED'}))
if __name__=='__main__':main()
