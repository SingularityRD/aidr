#!/usr/bin/env python3
"""One-shot, bounded text-only CDR. Never returns the original document container.
Linux seccomp denies network/process creation after importing parsers. This is not
filesystem virtualization: run inside the supplied read-only/no-network container.
"""
import base64, binascii, ctypes, ctypes.util, encodings.cp437, encodings.utf_8_sig, errno, io, json, os, re, resource, socket, stat, struct, sys, zipfile
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import PurePosixPath
import defusedxml.ElementTree as ET
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

def main():
    try:
        raw=sys.stdin.buffer.read((MAX_INPUT*4//3)+4096)
        if len(raw)>(MAX_INPUT*4//3)+2048:raise Rejected('INPUT_LIMIT')
        req=json.loads(raw)
        if set(req)-{'kind','data','sandboxProbe'}:raise Rejected('REQUEST_SCHEMA')
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
        p=Parser();p.parse(data,req['kind']);print(json.dumps({'ok':True,'format':'aidr-text-cdr-v1','segments':p.segments,'sandbox':'linux-seccomp-no-network-filesystem-open-exec','inputBytes':len(data)},ensure_ascii=False))
    except Rejected as e:print(json.dumps({'ok':False,'reason':str(e)}))
    except Exception:print(json.dumps({'ok':False,'reason':'PARSER_REJECTED'}))
if __name__=='__main__':main()
