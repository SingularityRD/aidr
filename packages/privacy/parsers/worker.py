#!/usr/bin/env python3
"""One-shot, bounded CDR. By default it is text-only and never returns the original
document container. The opt-in OOXML modes (units/apply/verify) re-serialize a DOCX/XLSX/PPTX
package with detected spans redacted in place; see OfficeDoc below for the exact contract. The same
modes with kind 'pdf' produce an image-only PDF with the spans painted over; see PdfDoc.
Linux seccomp denies network/process creation after importing parsers. This is not
filesystem virtualization: run inside the supplied read-only/no-network container.
"""
import base64, binascii, ctypes, ctypes.util, encodings.cp437, encodings.utf_8_sig, encodings.utf_16_le, errno, hashlib, io, json, os, posixpath, re, socket, stat, struct, sys, zipfile
try:import resource
except ImportError:resource=None # non-Linux: sandbox() refuses to run, unit tests still import the parser
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import PurePosixPath
import defusedxml.ElementTree as ET
import xml.etree.ElementTree as WriteET # element construction/serialization only; all parsing goes through defusedxml
import zlib
from pypdf import PdfReader
# Imported eagerly: after sandbox() no module (or plugin) file can be opened. Only Image.frombuffer/
# tobytes and ImageDraw are used, which need no Pillow format plugin; ImageFile is otherwise imported
# lazily by Image.frombuffer/tobytes.
import pypdfium2 as pdfium
import pypdfium2.raw as pdfium_c
from PIL import Image, ImageDraw, ImageFile
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
        """Safety checks + per-page text. Returns the page texts (metadata is appended to segments only)."""
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
        walk(r.trailer);pages=[]
        for page in r.pages:
            text=page.extract_text()
            if not text or not text.strip():raise Rejected('PDF_OCR_REQUIRED')
            self.add(text);pages.append(text)
        if r.metadata:self.add('\n'.join(str(v) for v in r.metadata.values()))
        return pages
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
# Format-preserving OOXML redaction (DOCX/XLSX/PPTX). PDF has its own raster path (PdfDoc below).
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
#   * attribute values are content too (w:tooltip, w:alias, w:tag, bookmark/shape names, number
#     formats, sdt dates...): every attribute value that is not on the structural allowlist below
#     (and not rewritten by scrub) becomes a protected unit, so a finding in it rejects the file
#     and a residual one is visible to verify. Unknown attributes are scanned, never skipped;
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
# Attribute values. Every value is scanned, all values of one part together forming ONE protected
# (non-editable) unit, UNLESS it is structural: an attribute whose local name is on STRUCT_ATTR (ids,
# revision ids, geometry, styles, numbering, enumerations, booleans, timestamps), an r: relationship
# id, xml:space, an mc: list naming only prefixes declared in the part, or a `val` on an element in
# STRUCT_VAL (formatting enumerations/numbers; `val` on w:alias, w:tag, w:name, w:docPart,
# w:lvlText, w:dateFormat... is free text and scanned). Attributes that scrub() rewrites or removes
# (ANON, comment author names, drawing alt text) are not scanned: their values never leave.
# Even a structural attribute is only skipped when its value has a structural SHAPE (a short token
# without whitespace and without a run of 9+ digits, see STRUCT_VALUE), so free text, e-mail
# addresses, card/phone/ID numbers can never ride in an allowlisted attribute unscanned.
# Booleans and short numbers are skipped cheaply (TRIVIAL_VALUE). The allowlist is only a unit-count
# optimisation: an attribute missing from it is scanned, and a clean scan simply passes.
NS_R='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
NS_MC='http://schemas.openxmlformats.org/markup-compatibility/2006'
STRUCT_VALUE=re.compile(r'(?!.*[0-9]{9})[A-Za-z0-9_.:+#%{}()\-]{0,64}')
TRIVIAL_VALUE=re.compile(r'\s*|[01]|true|false|on|off|-?[0-9]{1,4}(?:\.[0-9]{1,4})?')
STRUCT_ATTR=frozenset((
 # identifiers and revision bookkeeping
 'id','idx','rsid','rsidR','rsidRPr','rsidRDefault','rsidP','rsidDel','rsidSect','rsidTr','paraId','textId','paraIdParent',
 'anchorId','editId','durableId','authorId','personId','parentId','threadId','numId','abstractNumId','ilvl','lvl','styleId',
 'xfId','fontId','fillId','borderId','numFmtId','dxfId','builtinId','sheetId','localSheetId','workbookViewId','iLevel','spid',
 'colFirst','colLast','displacedByCustomXml','lastIdx','clrIdx','lastIndex','count','uniqueCount','docId','storeItemID',
 # types and enumerations
 'type','fldCharType','lineRule','hRule','vAlign','textDirection','orient','relativeFrom','prst','algn','fontAlgn','vert',
 'horzOverflow','vertOverflow','wrap','wrapText','anchorCtr','cap','cmpd','pattern','pitchFamily','charset','panose',
 'cs','ascii','hAnsi','eastAsia','asciiTheme','hAnsiTheme','eastAsiaTheme','cstheme','hint','bidi','lang','altLang',
 'themeColor','themeShade','themeTint','themeFill','themeFillShade','themeFillTint','fill','color','rgb','theme','indexed',
 'tint','lastClr','mod','state','view','mode','dirty','err','smtClean','noProof','sz','szCs','b','i','u','strike',
 'baseline','kern','spc','typeface','script','sym','fmt','layout','placement','fixed','defaultRowHeight','defaultColWidth',
 'shapeId','presetClass','presetID','presetSubtype','nodeType','grpId','dur','delay','accel','decel','autoRev','fill',
 'restart','evtFilter','calcmode','valueType','additive','accumulate','transition','advTm','advClick','spd','dir',
 # geometry, spacing and page layout
 'w','h','x','y','cx','cy','l','t','r','s','left','right','top','bottom','header','footer','gutter','start','end','before',
 'after','line','firstLine','hanging','beforeLines','afterLines','beforeAutospacing','afterAutospacing','pos','leader',
 'linePitch','charSpace','num','space','distT','distB','distL','distR','relativeHeight','rot','flipH','flipV','ht',
 'customHeight','width','customWidth','bestFit','min','max','spans','outlineLevel','outlineLevelRow','outlineLevelCol',
 'dyDescent','zoomScale','zoomScaleNormal','xWindow','yWindow','windowWidth','windowHeight','firstSheet','activeTab',
 'tabRatio','activeCell','sqref','ref','topLeftCell','xSplit','ySplit','activePane','pane','marL','marR','indent',
 'defTabSz','lIns','tIns','rIns','bIns','numCol','spcCol','n','d','behindDoc','locked','layoutInCell','allowOverlap',
 'simplePos','hidden','tabSelected','showGridLines','rtl','eaLnBrk','latinLnBrk','hangingPunct','noChangeAspect',
 'noGrp','noRot','noSelect','noMove','noResize','noTextEdit','noChangeArrowheads','txBox','userDrawn','preserve',
 'showMasterSp','showMasterPhAnim','hasCustomPrompt','orient','firstSlideNum','saveSubsetFonts','autoCompressPictures',
 'gridSpacing','showSpecialPlsOnTitleSld','r1','r2','si','ca','aca','bx','dt2D','dtr','del1','del2','cm','vm','ph',
 'ht','thickTop','thickBot','collapsed','customFormat','applyFont','applyFill','applyBorder','applyAlignment',
 'applyNumberFormat','applyProtection','quotePrefix','pivotButton','horizontal','vertical','textRotation','shrinkToFit',
 'readingOrder','relativeIndent','justifyLastLine','date1904','defaultThemeVersion','filterPrivacy','codeName',
 'appName','lastEdited','lowestEdited','rupBuild','calcId','fullCalcOnLoad','iterate','iterateCount','iterateDelta',
 # font signatures, colour mapping, effects and drawing geometry
 'usb0','usb1','usb2','usb3','csb0','csb1','bg1','bg2','t1','t2','tx1','tx2','accent1','accent2','accent3','accent4',
 'accent5','accent6','hyperlink','followedHyperlink','blurRad','dist','dir','rotWithShape','ang','scaled','path','sx','sy',
 'kx','ky','stA','stPos','endA','endPos','fadeDir','rad','prstMaterial','contourW','extrusionH','lat','lon','rev','lim',
 'spelling','grammar','uri','pitch','dpi','cstate','imgW','imgH','chOff','chExt','fov','zoom','showGuides',
 'snapToGrid','snapToObjects','showFormatting','showSpecialPlsOnTitleSld','autoAdjust','tblStyleId','bandRow','firstRow',
 'firstColumn','lastRow','lastColumn','noHBand','noVBand','bandCol','mainSeqNum','patternType','style','diagonalUp',
 'diagonalDown','auto','defaultTableStyle','defaultPivotStyle','defaultSlicerStyle','defaultTimelineStyle','mruColors',
 # timestamps (comment/revision dates are metadata of the edit, not document content)
 'date','dT','dt','created',
))
STRUCT_VAL=frozenset((
 'pStyle','rStyle','tblStyle','numId','ilvl','jc','sz','szCs','color','highlight','u','vertAlign','lang','b','bCs','i',
 'iCs','strike','dstrike','caps','smallCaps','vanish','specVanish','webHidden','outline','shadow','emboss','imprint',
 'spacing','w','kern','position','shd','outlineLvl','keepNext','keepLines','pageBreakBefore','widowControl',
 'suppressAutoHyphens','suppressLineNumbers','snapToGrid','contextualSpacing','mirrorIndents','rtl','bidi',
 'textAlignment','textboxTightWrap','gridSpan','vMerge','hMerge','tblLayout','tblLook','vAlign','textDirection',
 'cnfStyle','tblStyleRowBandSize','tblStyleColBandSize','cantSplit','tblHeader','numFmt','start','lvlJc','nsid',
 'multiLevelType','tmpl','lvlRestart','isLgl','suff','type','titlePg','formProt','noProof','em','effect','zoom',
 'proofState','defaultTabStop','characterSpacingControl','evenAndOddHeaders','mirrorMargins','autoHyphenation',
 'trackRevisions','doNotTrackMoves','doNotTrackFormatting','rsidRoot','rsid','themeFontLang','decimalSymbol',
 'listSeparator','family','pitch','charset','notTrueType','divId','uiPriority','semiHidden','unhideWhenUsed','qFormat',
 'basedOn','next','link','autoRedefine','locked','id','showingPlcHdr','temporary','lock','calendar','storeMappedDataAs',
 'docPartUnique','ligatures','numForm','numSpacing','cntxtAlts','checked','checkedState','uncheckedState','appearance',
 'collapsed','docId','chartTrackingRefBased','creationId','modId','compatSetting','scheme','condense','extend','tab',
 'srgbClr','schemeClr','sysClr','prstClr','lumMod','lumOff','tint','shade','alpha','alphaModFix','satMod','sat','hueMod',
 'hue','lum','spcPct','spcPts','buSzPct','buSzPts','prstDash','numRestart','pos','bookFoldPrinting','doNotDisplayPageBoundaries','displayBackgroundShape',
 'embedTrueTypeFonts','saveSubsetFonts','alwaysShowPlaceholderText','hideSpellingErrors','hideGrammaticalErrors',
 'clickAndTypeStyle','defaultTableStyle','drawingGridHorizontalSpacing','drawingGridVerticalSpacing',
 'displayHorizontalDrawingGridEvery','displayVerticalDrawingGridEvery','doNotUseMarginsForDrawingGridOrigin',
 'noPunctuationKerning','optimizeForBrowser','allowPNG','pixelsPerInch','relyOnVML','doNotSaveAsSingleFile',
 'kinsoku','overflowPunct','topLinePunct','autoSpaceDE','autoSpaceDN','adjustRightInd','wordWrap','fitText',
 'percent','dropCap','lines','hyphenationZone','consecutiveHyphenLimit','doNotHyphenateCaps','gutterAtTop',
 'printTwoOnOne','updateFields','doNotShadeFormData','strictFirstAndLastChars','noLineBreaksAfter','noLineBreaksBefore',
 # borders (style enumeration) and math properties
 'top','bottom','left','right','start','end','insideH','insideV','tl2br','tr2bl','between','bar','mathFont','brkBin',
 'brkBinSub','smallFrac','dispDef','lMargin','rMargin','defJc','wrapIndent','intLim','naryLim','panose1','tblInd',
 'tblCellSpacing','tblW','tcW','wAfter','wBefore','gridAfter','gridBefore','trHeight','noWrap','tcFitText','hideMark',
 'shapeLayoutLikeWW8','doNotExpandShiftReturn','useFELayout',
))
ATTR_SEPARATOR='\n'
MC_TOKEN=re.compile(r'(?:([A-Za-z_][A-Za-z0-9_.-]{0,31}):)?[A-Za-z_*][A-Za-z0-9_.*-]{0,63}')

def scanned_attributes(e,key,prefixes):
    """The attribute keys of element e whose values must be scanned (see STRUCT_ATTR above)."""
    out=[]
    for k,v in e.attrib.items():
        u,l=qn(k)
        if u==NS_XML and l=='space':continue
        if u==NS_MC:
            # Markup-compatibility lists name namespace prefixes: structural only if every token
            # is (a qualified name in) a prefix actually declared in this part.
            tokens=v.split()
            if tokens and all((mt:=MC_TOKEN.fullmatch(x)) and ((mt.group(1) or x) in prefixes) for x in tokens):continue
            out.append(k);continue
        # Rewritten or removed by scrub(), so never written back with the original value.
        if u!=NS_XML and l in ANON:continue
        if l=='name' and key[1] in ('cmAuthor','author'):continue
        if l in ('descr','title') and key[1] in ('docPr','cNvPr'):continue
        # Already their own units (protected sheet name, editable field instruction).
        if key==(NS_S,'sheet') and k=='name':continue
        if key==(NS_W,'fldSimple') and k=='{%s}instr'%NS_W:continue
        if TRIVIAL_VALUE.fullmatch(v):continue
        structural=u==NS_R or (key[1] in STRUCT_VAL if l=='val' else l in STRUCT_ATTR)
        if structural and STRUCT_VALUE.fullmatch(v):continue
        out.append(k)
    return out

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
            if name!='[Content_Types].xml' and not name.endswith('.rels'):self.collect(self.parts[name],{p for p,_ in self.decls[name]})
        self.units=[u for u in self.units if u.real()]
        if len(self.units)>MAX_UNITS:raise Rejected('REDACT_UNIT_LIMIT')
        if sum(len(t.encode('utf8')) for t in self.texts())>MAX_TEXT:raise Rejected('TEXT_LIMIT')
    def texts(self):return [u.text() for u in self.units]
    def digest(self):return hashlib.sha256(json.dumps(self.texts(),ensure_ascii=False).encode('utf8')).hexdigest()
    def collect(self,root,prefixes):
        units=self.units
        def new(editable=True,cell=None):
            u=Unit(editable,cell);units.append(u);return u
        attr_unit=[]
        def attributes(e,key):
            # Every non-structural attribute value of the part goes into ONE protected unit (any
            # finding rejects the file), separated by virtual line breaks. One unit per part keeps
            # the unit count bounded on style-heavy packages.
            for k in scanned_attributes(e,key,prefixes):
                if attr_unit:attr_unit[0].nodes.append((None,ATTR_SEPARATOR))
                else:attr_unit.append(new(False))
                attr_unit[0].nodes.append((e,('attr',k)))
        def walk(e,unit,depth):
            if depth>MAX_XML_DEPTH:raise Rejected('REDACT_XML_DEPTH')
            key=qn(e.tag)
            if key in SKIP_TEXT:return
            attributes(e,key)
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
                        else:attributes(c,qn(c.tag))
                    return
                v=e.find('{%s}v'%NS_S)
                if v is not None and v.text and e.attrib.get('t')!='s':new(True,e).nodes.append((v,'text'))
                for c in e:
                    if qn(c.tag)!=(NS_S,'v'):walk(c,unit,depth+1)
                    else:attributes(c,qn(c.tag))
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
            if not isinstance(x,list) or len(x)!=4 or any(type(v) is not int for v in x[:3]) or not isinstance(x[3],str) or not REPLACEMENT.fullmatch(x[3]):raise Rejected('REDACT_EDITS')
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

# ---------------------------------------------------------------------------------------------
# Format-preserving PDF redaction (kind 'pdf', same units/apply/verify protocol as OOXML).
#
# The output is an IMAGE-ONLY PDF: each page is rasterized by PDFium at PDF_DPI, opaque black boxes
# are painted over the characters of every redaction span, and the pages are re-assembled into a new
# minimal PDF written here (one Flate RGB image per page, original page size, no text layer, no
# /Info, no XMP, no /ID, no annotations, forms, outlines or any other original object).
#
# Mapping strategy: the spans must address exactly the characters whose boxes are painted, so the
# units ARE PDFium's own per-page text (one unit per page, one code point per PDFium character index,
# a UTF-16 surrogate pair counted as one code point). The independent pypdf extraction that the TXT
# path uses must contain the same whitespace-separated tokens as PDFium's text (reading order may
# differ, e.g. on rotated pages), otherwise the document is rejected (PDF_TEXT_MISMATCH): a
# disagreement means the two views could detect different PII.
#
# Fail-closed decisions:
#   * the unchanged Parser.pdf safety checks (encryption, JavaScript/actions/embedded files/forms,
#     image XObjects, object/page limits, OCR-required blank pages) run first;
#   * inline images and any other PDFium image object reject the file (they would be reproduced
#     unscanned in the raster), annotations are never rendered;
#   * a character PDFium cannot map to Unicode, a lone surrogate, a page larger than PDF_MAX_PIXELS,
#     a span whose visible characters have no box, or a units digest change rejects the file;
#   * the output is re-opened with pypdf AND PDFium and must have the same page count, no extractable
#     text, no metadata and only the objects this writer creates, or no output is produced.
# ---------------------------------------------------------------------------------------------
PDF_DPI=150; PDF_SCALE=PDF_DPI/72; PDF_PAD=2; PDF_MAX_PIXELS=4096*4096
PDF_CONTENT=re.compile(rb'q [0-9.]+ 0 0 [0-9.]+ 0 0 cm /Im0 Do Q')

def pdf_number(v):
    s=('%.4f'%v).rstrip('0').rstrip('.');return (s if s not in ('','-0') else '0').encode('ascii')

def pdf_tokens(t):
    """Order-insensitive token multiset: pypdf and PDFium may order lines differently (e.g. rotated
    pages), but every token one extractor sees must be seen by the other."""
    return sorted(t.split())

class PdfDoc:
    def __init__(self,parser,b):
        if not b.startswith(b'%PDF-'):raise Rejected('FORMAT_MISMATCH')
        reference=parser.pdf(b) # unchanged TXT-path safety checks and pypdf page text
        self.doc=pdfium.PdfDocument(b)
        if len(self.doc)!=len(reference):raise Rejected('PDF_PAGE_MISMATCH')
        self.pages=[];self.index=[];texts=[]
        for n in range(len(self.doc)):
            page=self.doc[n];tp=page.get_textpage()
            for obj in page.get_objects(max_depth=15):
                if obj.type==pdfium_c.FPDF_PAGEOBJ_IMAGE:raise Rejected('PDF_ACTIVE_OR_IMAGE')
            text,index=self.page_text(tp)
            if pdf_tokens(text)!=pdf_tokens(reference[n]):raise Rejected('PDF_TEXT_MISMATCH')
            self.pages.append((page,tp));self.index.append(index);texts.append(text)
        self.units=texts
        if sum(len(t.encode('utf8')) for t in texts)>MAX_TEXT:raise Rejected('TEXT_LIMIT')
    @staticmethod
    def page_text(tp):
        """PDFium text with a code point -> character index map (surrogate pairs collapse to one code point)."""
        n=tp.count_chars();chars=[];index=[];i=0
        if n<0:raise Rejected('PDF_TEXT_UNMAPPABLE')
        get=lambda k:pdfium_c.FPDFText_GetUnicode(tp,k)
        while i<n:
            if pdfium_c.FPDFText_HasUnicodeMapError(tp,i)!=0:raise Rejected('PDF_TEXT_UNMAPPABLE')
            u=get(i)
            if 0xD800<=u<=0xDBFF and i+1<n and 0xDC00<=get(i+1)<=0xDFFF and pdfium_c.FPDFText_HasUnicodeMapError(tp,i+1)==0:
                chars.append(chr(0x10000+((u-0xD800)<<10)+(get(i+1)-0xDC00)));index.append((i,i+1));i+=2;continue
            if u==0 or 0xD800<=u<=0xDFFF or u in (0xFFFE,0xFFFF) or u>0x10FFFF:raise Rejected('PDF_TEXT_UNMAPPABLE')
            chars.append(chr(u));index.append((i,));i+=1
        return ''.join(chars),index
    def texts(self):return list(self.units)
    def digest(self):return hashlib.sha256(json.dumps(self.units,ensure_ascii=False).encode('utf8')).hexdigest()
    def close(self):
        for page,tp in self.pages:tp.close();page.close()
        self.doc.close()
    def boxes(self,edits):
        """[page, start, end, replacement] code point edits -> per-page lists of PDF-space char boxes."""
        if not isinstance(edits,list) or len(edits)>MAX_EDITS:raise Rejected('REDACT_EDITS')
        grouped={}
        for x in edits:
            if not isinstance(x,list) or len(x)!=4 or any(type(v) is not int for v in x[:3]) or not isinstance(x[3],str) or not REPLACEMENT.fullmatch(x[3]):raise Rejected('REDACT_EDITS')
            if not 0<=x[0]<len(self.units) or not 0<=x[1]<x[2]<=len(self.units[x[0]]):raise Rejected('REDACT_EDITS')
            grouped.setdefault(x[0],[]).append((x[1],x[2]))
        out={}
        for p,spans in grouped.items():
            spans.sort();pos=0;tp=self.pages[p][1];text=self.units[p]
            for s,e in spans:
                if s<pos:raise Rejected('REDACT_EDITS')
                pos=e;painted=0
                for k in range(s,e):
                    for ci in self.index[p][k]:
                        if pdfium_c.FPDFText_IsGenerated(tp,ci)==1:continue # synthesized space/line break: no glyph
                        l,bottom,r,top=tp.get_charbox(ci,loose=True)
                        if not (r>l and top>bottom):
                            if text[k].isspace():continue
                            raise Rejected('PDF_REDACT_UNMAPPED')
                        out.setdefault(p,[]).append((l,bottom,r,top));painted+=1
                if not painted:raise Rejected('PDF_REDACT_UNMAPPED')
        return out
    def raster(self,p,boxes):
        page=self.pages[p][0];w,h=page.get_size()
        if not (w>0 and h>0) or (w*PDF_SCALE+1)*(h*PDF_SCALE+1)>PDF_MAX_PIXELS:raise Rejected('PDF_PAGE_TOO_LARGE')
        bitmap=page.render(scale=PDF_SCALE,rotation=0,may_draw_forms=False,draw_annots=False,fill_color=(255,255,255,255),rev_byteorder=True)
        try:
            img=bitmap.to_pil()
            img=img if img.mode=='RGB' else img.convert('RGB')
            img.load()
        finally:bitmap.close()
        bw,bh=img.size;draw=ImageDraw.Draw(img);dx=ctypes.c_int();dy=ctypes.c_int()
        for l,bottom,r,top in boxes:
            xs=[];ys=[]
            for x,y in ((l,bottom),(l,top),(r,bottom),(r,top)):
                # Same device mapping PDFium's renderer uses (honours /Rotate and the crop box).
                if not pdfium_c.FPDF_PageToDevice(page,0,0,bw,bh,0,ctypes.c_double(x),ctypes.c_double(y),ctypes.byref(dx),ctypes.byref(dy)):raise Rejected('PDF_REDACT_UNMAPPED')
                xs.append(dx.value);ys.append(dy.value)
            draw.rectangle((min(xs)-PDF_PAD,min(ys)-PDF_PAD,max(xs)+PDF_PAD,max(ys)+PDF_PAD),fill=(0,0,0))
        return img,w,h
    def redact(self,edits):
        boxes=self.boxes(edits);objects=[];kids=[]
        n=len(self.pages);first=3 # 1 catalog, 2 page tree, then 3 objects per page
        for p in range(n):
            img,w,h=self.raster(p,boxes.get(p,[]));raw=zlib.compress(img.tobytes(),6);img.close()
            if len(raw)>MAX_INPUT:raise Rejected('REDACT_OUTPUT_LIMIT')
            pid,cid,iid=first+3*p,first+3*p+1,first+3*p+2;kids.append(pid)
            content=b'q '+pdf_number(w)+b' 0 0 '+pdf_number(h)+b' 0 0 cm /Im0 Do Q'
            objects.append((pid,b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 '+pdf_number(w)+b' '+pdf_number(h)+b'] /Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>'%(iid,cid)))
            objects.append((cid,b'<< /Length %d >>\nstream\n'%len(content)+content+b'\nendstream'))
            objects.append((iid,b'<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n'%(img.size[0],img.size[1],len(raw))+raw+b'\nendstream'))
        objects[:0]=[(1,b'<< /Type /Catalog /Pages 2 0 R >>'),(2,b'<< /Type /Pages /Kids ['+b' '.join(b'%d 0 R'%k for k in kids)+b'] /Count %d >>'%n)]
        out=io.BytesIO();out.write(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n');offsets={}
        for oid,body in objects:
            offsets[oid]=out.tell();out.write(b'%d 0 obj\n'%oid+body+b'\nendobj\n')
            if out.tell()>MAX_INPUT:raise Rejected('REDACT_OUTPUT_LIMIT')
        xref=out.tell();out.write(b'xref\n0 %d\n0000000000 65535 f \n'%(len(objects)+1))
        for oid in range(1,len(objects)+1):out.write(b'%010d 00000 n \n'%offsets[oid])
        out.write(b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n'%(len(objects)+1,xref))
        b=out.getvalue()
        if len(b)>MAX_INPUT:raise Rejected('REDACT_OUTPUT_LIMIT')
        segments,units=verify_pdf_output(b) # independent re-parse before release
        if len(units)!=n or any(t.strip() for t in segments+units):raise Rejected('REDACTION_RESIDUAL')
        return b

def verify_pdf_output(b):
    """Re-opens a redacted PDF with pypdf and PDFium. Its structure must be exactly what PdfDoc.redact
    writes (image-only pages, no metadata). Returns both extractors' page texts for the caller to check."""
    if len(b)>MAX_INPUT or not b.startswith(b'%PDF-1.4\n'):raise Rejected('REDACT_VALIDATION')
    r=PdfReader(io.BytesIO(b),strict=True)
    if r.is_encrypted or set(r.trailer.keys())!={'/Size','/Root'} or r.metadata is not None or r.xmp_metadata is not None:raise Rejected('REDACT_VALIDATION')
    root=r.trailer['/Root'].get_object()
    if set(root.keys())!={'/Type','/Pages'} or set(root['/Pages'].get_object().keys())!={'/Type','/Kids','/Count'}:raise Rejected('REDACT_VALIDATION')
    n=len(r.pages);segments=[];units=[]
    if not 0<n<=50:raise Rejected('REDACT_VALIDATION')
    for page in r.pages:
        if set(page.keys())!={'/Type','/Parent','/MediaBox','/Resources','/Contents'}:raise Rejected('REDACT_VALIDATION')
        res=page['/Resources'].get_object()
        if set(res.keys())!={'/XObject'} or set(res['/XObject'].get_object().keys())!={'/Im0'}:raise Rejected('REDACT_VALIDATION')
        im=res['/XObject']['/Im0'].get_object()
        # pypdf drops /Length from parsed stream dictionaries.
        if im.get('/Subtype')!='/Image' or set(im.keys())!={'/Type','/Subtype','/Width','/Height','/ColorSpace','/BitsPerComponent','/Filter'}:raise Rejected('REDACT_VALIDATION')
        if not PDF_CONTENT.fullmatch(page.get_contents().get_data()):raise Rejected('REDACT_VALIDATION')
        segments.append(page.extract_text())
    doc=pdfium.PdfDocument(b)
    try:
        if len(doc)!=n or any(v for v in doc.get_metadata_dict().values()):raise Rejected('REDACT_VALIDATION')
        for i in range(n):
            page=doc[i];tp=page.get_textpage()
            try:
                count=tp.count_chars()
                if count<0:raise Rejected('REDACT_VALIDATION')
                units.append(tp.get_text_range(0,count) if count else '')
            finally:tp.close();page.close()
    finally:doc.close()
    return segments,units

def handle(req,data):
    """Dispatch one request after the sandbox is in place."""
    mode=req.get('mode','text');sandbox_id='linux-seccomp-no-network-filesystem-open-exec'
    if mode=='text':
        if set(req)-{'kind','data','sandboxProbe','mode'}:raise Rejected('REQUEST_SCHEMA')
        p=Parser();p.parse(data,req['kind']);return {'ok':True,'format':'aidr-text-cdr-v1','segments':p.segments,'sandbox':sandbox_id,'inputBytes':len(data)}
    pdf=req.get('kind')=='pdf'
    if mode=='units':
        if set(req)-{'kind','data','mode'}:raise Rejected('REQUEST_SCHEMA')
        if pdf:
            d=PdfDoc(Parser(),data)
            try:return {'ok':True,'format':'aidr-pdf-units-v1','units':d.texts(),'unitsDigest':d.digest(),'pages':len(d.units),'sandbox':sandbox_id,'inputBytes':len(data)}
            finally:d.close()
        d=OfficeDoc(Parser(),data,req['kind']);return {'ok':True,'format':'aidr-office-units-v1','units':d.texts(),'unitsDigest':d.digest(),'sandbox':sandbox_id,'inputBytes':len(data)}
    if mode=='apply':
        if set(req)-{'kind','data','mode','edits','unitsDigest'}:raise Rejected('REQUEST_SCHEMA')
        if pdf:
            d=PdfDoc(Parser(),data)
            try:
                if req.get('unitsDigest')!=d.digest():raise Rejected('REDACT_UNITS_CHANGED')
                out=d.redact(req.get('edits'))
            finally:d.close()
            return {'ok':True,'format':'aidr-pdf-redacted-v1','data':base64.b64encode(out).decode('ascii'),'sandbox':sandbox_id,'inputBytes':len(data)}
        d=OfficeDoc(Parser(),data,req['kind'])
        if req.get('unitsDigest')!=d.digest():raise Rejected('REDACT_UNITS_CHANGED')
        out=d.redact(req.get('edits'));return {'ok':True,'format':'aidr-office-redacted-v1','data':base64.b64encode(out).decode('ascii'),'sandbox':sandbox_id,'inputBytes':len(data)}
    if mode=='verify':
        if set(req)-{'kind','data','mode'}:raise Rejected('REQUEST_SCHEMA')
        if pdf:
            # Only the image-only shape PdfDoc.redact writes is accepted; the caller requires both views empty.
            segments,units=verify_pdf_output(data);return {'ok':True,'format':'aidr-pdf-verify-v1','pages':len(units),'segments':segments,'units':units,'sandbox':sandbox_id,'inputBytes':len(data)}
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
