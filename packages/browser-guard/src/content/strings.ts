/**
 * User-facing strings for the in-page guard (toast, bubble, restored-value tooltip).
 *
 * Only counts, entity type names, placeholder labels (such as `[EMAIL_1]`), file names and
 * the site's display name are ever interpolated; raw prompt text, placeholder originals and
 * file contents never appear in these messages.
 *
 * Wording rules: plain words ("message", "mesaj"; "label", "etiket"), data named the way the
 * popup names it (ENTITY_NAMES mirrors the `entity_*` messages in _locales, checked by
 * ui-i18n.test.ts), and the brand is always "Singularity AIDR".
 */
import {
	ENTITY_TYPES,
	type EntityType,
	type FileBlockReason,
	PLACEHOLDER_PREFIX,
} from "../types.js";

export type Lang = "en" | "tr";

/** Sentence for a blocked upload: `name` is the file name, `found` the count summary or "". */
type FileReasonMessage = (name: string, found: string) => string;

export interface Strings {
	/** Language of this table (for formatCounts). */
	readonly lang: Lang;
	readonly brand: string;
	/** Tooltip of a value restored in an answer; `label` is what the AI service received. */
	restoredTitle(label: string): string;
	/** Shown once per page when the first value is restored in an answer. */
	restoredLegend(label: string): string;
	readonly sendMasked: string;
	readonly sendOriginal: string;
	readonly sendAnyway: string;
	readonly edit: string;
	readonly close: string;
	maskedToast(summary: string): string;
	pasteMaskedToast(summary: string): string;
	fileMaskedToast(files: number, summary: string): string;
	fileUnscannedToast(name: string): string;
	/** A legacy .doc/.xls/.ppt upload passed through without a complete check. */
	legacyOfficeToast(name: string): string;
	/** An image passed through without OCR (no native host, or it could not read it fully). */
	imageUnscannedToast(name: string): string;
	/** A document was checked, but pictures inside it were not inspected. */
	documentImagesToast(name: string): string;
	/** A PDF passed through although its embedded images were not inspected (no/failed OCR). */
	pdfImagesUnscannedToast(name: string): string;
	readonly confirmTitle: string;
	/**
	 * What was found and what "Send masked" does. `label` is an example placeholder such as
	 * `[TCKN_1]`; `restores` says whether answers show the original values again.
	 */
	confirmBody(summary: string, label: string, restores: boolean): string;
	/** Small print under the buttons when "Send original" is offered; `site` null = unknown. */
	sendOriginalNote(site: string | null): string;
	/** Native NER was off for this check, so person names were not looked for. */
	readonly namesNotChecked: string;
	readonly warnTitle: string;
	readonly blockedTitle: string;
	blockedBody(summary: string): string;
	readonly blockedCoaching: string;
	readonly pasteBlocked: string;
	readonly pasteScanFailed: string;
	readonly scanFailed: string;
	readonly policyMissing: string;
	readonly siteBlocked: string;
	readonly editorMissing: string;
	readonly editorAmbiguous: string;
	readonly rewriteFailed: string;
	readonly textChanged: string;
	readonly pressSendAgain: string;
	readonly busy: string;
	readonly fileBlockedTitle: string;
	/**
	 * Why an upload was blocked and what to do, one entry per reason code (types.ts
	 * FILE_BLOCK_REASONS). `found` is the plain count summary ("1 email address") or "".
	 * Reason codes themselves never appear in these sentences.
	 */
	readonly fileReasons: Readonly<Record<FileBlockReason, FileReasonMessage>>;
	/** An upload blocked by a risk signal; `coaching` is the signal's coaching sentence. */
	fileBlockedSignal(name: string, coaching: string): string;
	/** An upload blocked for a reason without its own sentence (never shows the code). */
	fileBlockedGeneric(name: string, found: string): string;
	readonly fileBlockedByPolicy: string;
	/** documentHandling "block": Office/PDF uploads are not allowed. */
	readonly documentBlockedByPolicy: string;
	readonly fileScanFailed: string;
	readonly fileReplaceUnsupported: string;
	readonly fileInputUnguarded: string;
	/** Native NER was enabled but gave no usable answer: this check was rules-only. */
	readonly nativeUnavailable: string;
	/** policy.requireNativeNer: native NER gave no usable answer, so the send/paste was blocked. */
	readonly nativeRequired: string;
	/** Acceptable-use notice (administrator text is shown verbatim; these are the controls). */
	readonly aupAcknowledge: string;
	readonly aupLater: string;
	readonly aupPolicyLink: string;
	readonly aupRecorded: string;
	readonly aupRecordFailed: string;
	aupVersion(version: number): string;
	/**
	 * Personal vs company account (managed `workAccounts`). `site` is the site's display name;
	 * no workspace id, email or domain is ever shown.
	 */
	readonly accountTitle: string;
	/** Why the account is not confirmed as the organisation's. */
	accountReason(type: "personal" | "other" | "unverified", site: string): string;
	/** warn: what to do; the bubble offers Continue / Cancel. */
	readonly accountWarn: string;
	/** block: nothing was sent. */
	accountBlocked(site: string): string;
	/** block: an upload was refused. */
	accountUploadBlocked(site: string): string;
	/** warn: shown for an upload (it continues with the usual checks). */
	readonly accountUploadWarn: string;
	/** mask-only: shown once per page. */
	readonly accountMaskOnly: string;
	readonly accountContinue: string;
	readonly accountCancel: string;
	/** warn: after Continue (the held message was not sent). */
	readonly accountSendAgain: string;
}

/** Brand name; never translated or upper-cased (the UI marks it lang="en"). */
const BRAND = "Singularity AIDR";

/** " (1 email address)" after a sentence's data, or "" when nothing was counted. */
const paren = (found: string): string => (found ? ` (${found})` : "");

const EN_NOT_FULLY_CHECKED = "and your organisation only allows files that can be fully checked";
const EN_PASTE_INSTEAD =
	"Copy the text you need into the message instead (pasted text is masked), or ask your IT team.";
const EN_SAVE_MODERN = "Save it as .docx/.xlsx/.pptx and upload that instead.";
const EN_SAVE_AGAIN =
	'Open the file, save it again (for example with "Save as") and try again, or ask your IT team.';

const EN_FILE_REASONS: Readonly<Record<FileBlockReason, FileReasonMessage>> = {
	FILE_BLOCKED_BY_POLICY: (name) =>
		`"${name}" was not uploaded: your organisation does not allow file uploads to AI services. Ask your IT team if you need to share files.`,
	DOCUMENT_BLOCKED_BY_POLICY: (name) =>
		`"${name}" was not uploaded: your organisation does not allow Office or PDF documents to be uploaded to AI services. ${EN_PASTE_INSTEAD}`,
	NATIVE_NER_UNAVAILABLE: (name) =>
		`"${name}" was not uploaded: your organisation requires the AIDR Privacy helper app to check uploads, and it could not check this file. Try again in a moment, or ask your IT team.`,
	FILE_TOO_LARGE: (name) =>
		`"${name}" was not uploaded: it is larger than your organisation allows for AI services. Upload a smaller file or only the part you need.`,
	SENSITIVE_DATA_IN_PDF: (name, found) =>
		`"${name}" contains personal or confidential data${paren(found)}, so it was not uploaded. PDFs cannot be masked: copy the text you need and paste it into the message instead (pasted text is masked), or ask your IT team.`,
	SENSITIVE_DATA_IN_LEGACY_OFFICE: (name, found) =>
		`"${name}" contains personal or confidential data${paren(found)}, so it was not uploaded. Old Office files (.doc/.xls/.ppt) cannot be masked: save it as .docx/.xlsx/.pptx and upload that instead (those are masked), or ask your IT team.`,
	SENSITIVE_DATA_IN_IMAGE: (name, found) =>
		`A picture shows personal or confidential data${paren(found)}, so "${name}" was not uploaded. Pictures cannot be masked: crop or black out that part before uploading, or ask your IT team.`,
	DOCUMENT_ENCRYPTED: (name) =>
		`"${name}" is password-protected, so it could not be checked and was not uploaded. Save a copy without the password and upload that, or ask your IT team.`,
	PDF_ENCRYPTED: (name) =>
		`"${name}" is a password-protected PDF, so it could not be checked and was not uploaded. Save a copy without the password and upload that, or ask your IT team.`,
	DOCUMENT_MACROS: (name) =>
		`"${name}" contains macros, which are not allowed in uploads to AI services, so it was not uploaded. Save a copy without macros (for example as .docx or .xlsx) and upload that, or ask your IT team.`,
	DOCUMENT_EMBEDDED_OBJECT: (name) =>
		`"${name}" has another file embedded in it that cannot be checked, so it was not uploaded. Remove the embedded file and try again, or ask your IT team.`,
	DOCUMENT_EXTERNAL_LINKS: (name) =>
		`"${name}" links to content outside the file (such as other workbooks or web pages) that cannot be checked, so it was not uploaded. Remove the links (for example by pasting values only) and try again, or ask your IT team.`,
	DOCUMENT_LIMIT_EXCEEDED: (name) =>
		`"${name}" is too large or complex to check, so it was not uploaded. Split it into smaller files or upload only the part you need.`,
	DOCUMENT_MALFORMED: (name) =>
		`"${name}" seems to be damaged or in an unusual format and could not be checked, so it was not uploaded. ${EN_SAVE_AGAIN}`,
	TEXT_FILE_NOT_DECODABLE: (name) =>
		`"${name}" looks like a text file, but its contents could not be read, so it was not uploaded. Save it again as UTF-8 text and try again, or ask your IT team.`,
	SCAN_INCOMPLETE: (name) =>
		`Checking "${name}" took too long and could not be finished, so it was not uploaded. Try a smaller file or only the part you need.`,
	FILE_SCAN_ERROR: (name) =>
		`Singularity AIDR could not check "${name}", so it was not uploaded. Try again; if it keeps happening, ask your IT team.`,
	PDF_IMAGE_OCR_UNAVAILABLE: (name) =>
		`Pictures in "${name}" could not be checked because the AIDR Privacy helper app is not available, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_IMAGES_NOT_INSPECTED: (name) =>
		`Pictures in "${name}" could not be fully checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_IMAGE_LIMIT: (name) =>
		`"${name}" has too many pictures to check, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. Upload only the pages you need, or ask your IT team.`,
	PDF_IMAGE_UNSUPPORTED: (name) =>
		`A picture in "${name}" is in a format that cannot be checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_IMAGE_UNDECODABLE: (name) =>
		`A picture in "${name}" could not be read, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_IMAGE_OCR_INCOMPLETE: (name) =>
		`The text in a picture in "${name}" could not be read reliably, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_NO_TEXT: (name) =>
		`"${name}" has no readable text (it may be a scanned document), ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. Type or paste the text you need into the message instead, or ask your IT team.`,
	PDF_PARTIAL: (name) =>
		`Part of the text in "${name}" could not be read, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
	PDF_EMBEDDED_FILES_NOT_INSPECTED: (name) =>
		`"${name}" has files attached inside it that cannot be checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. Remove the attachments and try again, or ask your IT team.`,
	PDF_UNPARSEABLE: (name) =>
		`"${name}" could not be opened as a PDF (it may be damaged), so it could not be checked and was not uploaded. ${EN_SAVE_AGAIN}`,
	LEGACY_OFFICE_PARTIAL: (name) =>
		`Part of the text in "${name}" (old .doc/.xls/.ppt format) could not be read, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_SAVE_MODERN}`,
	LEGACY_OFFICE_UNSUPPORTED: (name) =>
		`"${name}" uses a part of the old .doc/.xls/.ppt format that cannot be checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_SAVE_MODERN}`,
	LEGACY_OFFICE_FORMAT: (name) =>
		`"${name}" (old .doc/.xls/.ppt format) could not be fully checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_SAVE_MODERN}`,
	DOCUMENT_UNPARSEABLE: (name) =>
		`"${name}" could not be opened (it may be damaged or in an unusual format), so it could not be checked and was not uploaded. ${EN_SAVE_AGAIN}`,
	IMAGE_NOT_INSPECTED: (name) =>
		`The picture "${name}" could not be checked (pictures need the AIDR Privacy helper app), ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. Describe what you need in the message instead, or ask your IT team.`,
	BINARY_FILE_UNSCANNABLE: (name) =>
		`"${name}" is a type of file that cannot be checked, ${EN_NOT_FULLY_CHECKED}, so it was not uploaded. ${EN_PASTE_INSTEAD}`,
};

const TR_NOT_FULLY_CHECKED =
	"kurumunuz yalnızca tamamen denetlenebilen dosyalara izin verdiği için dosya yüklenmedi";
const TR_PASTE_INSTEAD =
	"Gereken metni kopyalayıp mesaja yapıştırın (yapıştırılan metin maskelenir) ya da BT ekibinize başvurun.";
const TR_SAVE_MODERN = "Dosyayı .docx/.xlsx/.pptx olarak kaydedip onu yükleyin.";
const TR_SAVE_AGAIN =
	'Dosyayı açıp yeniden kaydedin (ör. "Farklı kaydet" ile) ve yeniden deneyin ya da BT ekibinize başvurun.';

const TR_FILE_REASONS: Readonly<Record<FileBlockReason, FileReasonMessage>> = {
	FILE_BLOCKED_BY_POLICY: (name) =>
		`"${name}" yüklenmedi: kurumunuz yapay zekâ hizmetlerine dosya yüklenmesine izin vermiyor. Dosya paylaşmanız gerekiyorsa BT ekibinize başvurun.`,
	DOCUMENT_BLOCKED_BY_POLICY: (name) =>
		`"${name}" yüklenmedi: kurumunuz yapay zekâ hizmetlerine Office veya PDF belgesi yüklenmesine izin vermiyor. ${TR_PASTE_INSTEAD}`,
	NATIVE_NER_UNAVAILABLE: (name) =>
		`"${name}" yüklenmedi: kurumunuz yüklemelerin AIDR Privacy yardımcı uygulamasıyla denetlenmesini zorunlu tutuyor ve bu dosya denetlenemedi. Biraz sonra yeniden deneyin ya da BT ekibinize başvurun.`,
	FILE_TOO_LARGE: (name) =>
		`"${name}" yüklenmedi: dosya, kurumunuzun yapay zekâ hizmetleri için izin verdiği boyuttan büyük. Daha küçük bir dosya ya da yalnızca gereken bölümü yükleyin.`,
	SENSITIVE_DATA_IN_PDF: (name, found) =>
		`"${name}" kişisel veya gizli bilgi içeriyor${paren(found)}, bu yüzden yüklenmedi. PDF dosyaları maskelenemez: gereken metni kopyalayıp mesaja yapıştırın (yapıştırılan metin maskelenir) ya da BT ekibinize başvurun.`,
	SENSITIVE_DATA_IN_LEGACY_OFFICE: (name, found) =>
		`"${name}" kişisel veya gizli bilgi içeriyor${paren(found)}, bu yüzden yüklenmedi. Eski Office dosyaları (.doc/.xls/.ppt) maskelenemez: dosyayı .docx/.xlsx/.pptx olarak kaydedip onu yükleyin (bu biçimler maskelenir) ya da BT ekibinize başvurun.`,
	SENSITIVE_DATA_IN_IMAGE: (name, found) =>
		`Bir görselde kişisel veya gizli bilgi görünüyor${paren(found)}, bu yüzden "${name}" yüklenmedi. Görseller maskelenemez: yüklemeden önce o bölümü kırpın ya da karartın veya BT ekibinize başvurun.`,
	DOCUMENT_ENCRYPTED: (name) =>
		`"${name}" parolayla korunuyor; denetlenemediği için yüklenmedi. Parolasız bir kopyasını kaydedip onu yükleyin ya da BT ekibinize başvurun.`,
	PDF_ENCRYPTED: (name) =>
		`"${name}" parolayla korunan bir PDF; denetlenemediği için yüklenmedi. Parolasız bir kopyasını kaydedip onu yükleyin ya da BT ekibinize başvurun.`,
	DOCUMENT_MACROS: (name) =>
		`"${name}" makro içeriyor; yapay zekâ hizmetlerine makrolu dosya yüklenmesine izin verilmediği için yüklenmedi. Makrosuz bir kopyasını (ör. .docx veya .xlsx olarak) kaydedip onu yükleyin ya da BT ekibinize başvurun.`,
	DOCUMENT_EMBEDDED_OBJECT: (name) =>
		`"${name}" içine denetlenemeyen başka bir dosya gömülü; bu yüzden yüklenmedi. Gömülü dosyayı kaldırıp yeniden deneyin ya da BT ekibinize başvurun.`,
	DOCUMENT_EXTERNAL_LINKS: (name) =>
		`"${name}" dosya dışındaki içeriğe (başka çalışma kitapları veya web sayfaları gibi) bağlantı veriyor ve bu içerik denetlenemiyor; bu yüzden yüklenmedi. Bağlantıları kaldırıp (ör. yalnızca değerleri yapıştırarak) yeniden deneyin ya da BT ekibinize başvurun.`,
	DOCUMENT_LIMIT_EXCEEDED: (name) =>
		`"${name}" denetlenemeyecek kadar büyük veya karmaşık; bu yüzden yüklenmedi. Dosyayı daha küçük parçalara bölün ya da yalnızca gereken bölümü yükleyin.`,
	DOCUMENT_MALFORMED: (name) =>
		`"${name}" bozuk ya da alışılmadık bir biçimde görünüyor ve denetlenemedi; bu yüzden yüklenmedi. ${TR_SAVE_AGAIN}`,
	TEXT_FILE_NOT_DECODABLE: (name) =>
		`"${name}" bir metin dosyasına benziyor ama içeriği okunamadı; bu yüzden yüklenmedi. Dosyayı UTF-8 metin olarak yeniden kaydedip deneyin ya da BT ekibinize başvurun.`,
	SCAN_INCOMPLETE: (name) =>
		`"${name}" denetimi çok uzun sürdü ve tamamlanamadı; bu yüzden dosya yüklenmedi. Daha küçük bir dosya ya da yalnızca gereken bölümü deneyin.`,
	FILE_SCAN_ERROR: (name) =>
		`Singularity AIDR "${name}" dosyasını denetleyemedi; bu yüzden dosya yüklenmedi. Yeniden deneyin; sorun sürerse BT ekibinize başvurun.`,
	PDF_IMAGE_OCR_UNAVAILABLE: (name) =>
		`"${name}" içindeki görseller, AIDR Privacy yardımcı uygulaması kullanılamadığı için denetlenemedi; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_IMAGES_NOT_INSPECTED: (name) =>
		`"${name}" içindeki görseller tam olarak denetlenemedi; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_IMAGE_LIMIT: (name) =>
		`"${name}" denetlenemeyecek kadar çok görsel içeriyor; ${TR_NOT_FULLY_CHECKED}. Yalnızca gereken sayfaları yükleyin ya da BT ekibinize başvurun.`,
	PDF_IMAGE_UNSUPPORTED: (name) =>
		`"${name}" içindeki bir görsel denetlenemeyen bir biçimde; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_IMAGE_UNDECODABLE: (name) =>
		`"${name}" içindeki bir görsel okunamadı; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_IMAGE_OCR_INCOMPLETE: (name) =>
		`"${name}" içindeki bir görseldeki yazı güvenilir biçimde okunamadı; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_NO_TEXT: (name) =>
		`"${name}" okunabilir metin içermiyor (taranmış bir belge olabilir); ${TR_NOT_FULLY_CHECKED}. Gereken metni mesaja yazın ya da yapıştırın veya BT ekibinize başvurun.`,
	PDF_PARTIAL: (name) =>
		`"${name}" içindeki metnin bir bölümü okunamadı; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
	PDF_EMBEDDED_FILES_NOT_INSPECTED: (name) =>
		`"${name}" içinde denetlenemeyen ekli dosyalar var; ${TR_NOT_FULLY_CHECKED}. Ekleri kaldırıp yeniden deneyin ya da BT ekibinize başvurun.`,
	PDF_UNPARSEABLE: (name) =>
		`"${name}" PDF olarak açılamadı (bozuk olabilir); denetlenemediği için yüklenmedi. ${TR_SAVE_AGAIN}`,
	LEGACY_OFFICE_PARTIAL: (name) =>
		`"${name}" (eski .doc/.xls/.ppt biçimi) içindeki metnin bir bölümü okunamadı; ${TR_NOT_FULLY_CHECKED}. ${TR_SAVE_MODERN}`,
	LEGACY_OFFICE_UNSUPPORTED: (name) =>
		`"${name}", eski .doc/.xls/.ppt biçiminin denetlenemeyen bir bölümünü kullanıyor; ${TR_NOT_FULLY_CHECKED}. ${TR_SAVE_MODERN}`,
	LEGACY_OFFICE_FORMAT: (name) =>
		`"${name}" (eski .doc/.xls/.ppt biçimi) tam olarak denetlenemedi; ${TR_NOT_FULLY_CHECKED}. ${TR_SAVE_MODERN}`,
	DOCUMENT_UNPARSEABLE: (name) =>
		`"${name}" açılamadı (bozuk ya da alışılmadık bir biçimde olabilir); denetlenemediği için yüklenmedi. ${TR_SAVE_AGAIN}`,
	IMAGE_NOT_INSPECTED: (name) =>
		`"${name}" görseli denetlenemedi (görseller için AIDR Privacy yardımcı uygulaması gerekir); ${TR_NOT_FULLY_CHECKED}. Gerekeni mesajda anlatın ya da BT ekibinize başvurun.`,
	BINARY_FILE_UNSCANNABLE: (name) =>
		`"${name}" denetlenemeyen bir dosya türünde; ${TR_NOT_FULLY_CHECKED}. ${TR_PASTE_INSTEAD}`,
};

const EN: Strings = {
	lang: "en",
	brand: BRAND,
	restoredTitle: (label) => `Shown only on this computer. The AI service received ${label}.`,
	restoredLegend: (label) =>
		`Highlighted values in answers are your original data, shown only on this computer. The AI service received labels such as ${label}.`,
	sendMasked: "Send masked",
	sendOriginal: "Send original",
	sendAnyway: "Send anyway",
	edit: "Edit",
	close: "Close",
	maskedToast: (summary) => `Masked before sending: ${summary}.`,
	pasteMaskedToast: (summary) => `Pasted text masked: ${summary}.`,
	fileMaskedToast: (files, summary) =>
		`${files} ${files === 1 ? "file" : "files"} masked before upload: ${summary}.`,
	fileUnscannedToast: (name) =>
		`"${name}" could not be checked (binary file). Check it before sending.`,
	legacyOfficeToast: (name) =>
		`"${name}" (old .doc/.xls/.ppt format) could not be fully checked. Save it as .docx/.xlsx/.pptx, or check it before sending.`,
	imageUnscannedToast: (name) =>
		`"${name}" was not checked: images need the AIDR Privacy helper app. Check it before sending.`,
	documentImagesToast: (name) =>
		`Pictures inside "${name}" were not checked. Check them before sending.`,
	pdfImagesUnscannedToast: (name) =>
		`Images in "${name}" were not checked: they need the AIDR Privacy helper app. Check the PDF before sending.`,
	confirmTitle: "Your message contains personal or confidential data",
	confirmBody: (summary, label, restores) =>
		`Found: ${summary}. "Send masked" replaces them with labels such as ${label} before the message leaves your computer` +
		(restores ? "; the answer shows your original values again, only on this computer." : "."),
	sendOriginalNote: (site) =>
		`"Send original" sends the real values to ${site ?? "this AI service"}. This choice is counted; the message itself is never reported.`,
	namesNotChecked: "Person names were not checked: advanced name detection is off.",
	warnTitle: "Check your message before sending",
	blockedTitle: "Sending blocked",
	blockedBody: (summary) => `Found: ${summary}.`,
	blockedCoaching:
		"Your organisation does not allow this data to be sent to AI services. " +
		"Remove it or describe it in general terms, then try again.",
	pasteBlocked: "The pasted text contains sensitive data and was not inserted.",
	pasteScanFailed: "Singularity AIDR could not check the pasted text, so it was not inserted.",
	scanFailed: "Singularity AIDR could not finish checking this message, so it was not sent.",
	policyMissing: "Protection is still loading. Nothing was sent; try again in a moment.",
	siteBlocked: "Your organisation has blocked this AI service. Nothing was sent.",
	editorMissing: "The message box on this page could not be found, so nothing was sent.",
	editorAmbiguous:
		"Several text boxes hold text and it is unclear which one is being sent, so nothing was sent.",
	rewriteFailed: "The message could not be masked safely. Nothing was sent.",
	textChanged: "The message changed while it was being checked. Press send again.",
	pressSendAgain: "The message was masked. Press send to continue.",
	busy: "Still checking the previous action.",
	fileBlockedTitle: "Upload blocked",
	fileReasons: EN_FILE_REASONS,
	fileBlockedSignal: (name, coaching) => `"${name}" was not uploaded. ${coaching}`,
	fileBlockedGeneric: (name, found) =>
		`"${name}" was not uploaded because it could not be safely checked${paren(found)}. Ask your IT team if you need to share it.`,
	fileBlockedByPolicy: "Your organisation does not allow file uploads to AI services.",
	documentBlockedByPolicy:
		"Your organisation does not allow Office or PDF documents to be uploaded to AI services.",
	fileScanFailed: "The file could not be checked, so it was not uploaded.",
	fileReplaceUnsupported:
		"This browser cannot replace the file with a masked copy, so it was not uploaded.",
	fileInputUnguarded:
		"Files chosen through this upload button cannot be checked on this page, so the selection was blocked.",
	nativeUnavailable:
		"Names and addresses were checked with built-in rules only: the AIDR Privacy helper app could not be used.",
	nativeRequired:
		"Nothing was sent. Your organisation requires the AIDR Privacy helper app to check names and addresses, and it could not (not installed, not responding, no name detection, or the text is too long). Try again, shorten the text, or contact your IT team.",
	aupAcknowledge: "I understand",
	aupLater: "Remind me later",
	aupPolicyLink: "Read the full policy",
	aupRecorded: "Thank you. Your acknowledgement was recorded.",
	aupRecordFailed: "Your acknowledgement could not be saved; the notice will be shown again.",
	aupVersion: (version) => `Acceptable-use notice, version ${version}`,
	accountTitle: "Company account not confirmed",
	accountReason: (type, site) =>
		type === "personal"
			? `You appear to be signed in to ${site} with a personal account.`
			: type === "other"
				? `This ${site} account is not one of your organisation's approved accounts.`
				: `${BRAND} could not confirm that you are signed in to ${site} with your organisation's account.`,
	accountWarn:
		"Share company data only through your organisation's account. Switch accounts, or press Continue if this is intended.",
	accountBlocked: (site) =>
		`Nothing was sent. Your organisation allows ${site} only with its company account. Switch to your company account and try again.`,
	accountUploadBlocked: (site) =>
		`The file was not uploaded. Your organisation allows ${site} only with its company account. Switch to your company account and try again.`,
	accountUploadWarn:
		"This does not look like your organisation's account. Share company files only through your organisation's account.",
	accountMaskOnly:
		"This is not your organisation's account, so sensitive data is always masked here and the original cannot be sent.",
	accountContinue: "Continue",
	accountCancel: "Cancel",
	accountSendAgain: "Press send again to send your message.",
};

const TR: Strings = {
	lang: "tr",
	brand: BRAND,
	restoredTitle: (label) =>
		`Yalnızca bu bilgisayarda gösteriliyor. Yapay zekâ hizmetine ${label} gitti.`,
	restoredLegend: (label) =>
		`Yanıtlarda vurgulanan değerler orijinal verilerinizdir ve yalnızca bu bilgisayarda gösterilir. Yapay zekâ hizmetine ${label} gibi etiketler gitti.`,
	sendMasked: "Maskeli gönder",
	sendOriginal: "Orijinali gönder",
	sendAnyway: "Yine de gönder",
	edit: "Düzenle",
	close: "Kapat",
	maskedToast: (summary) => `Gönderilmeden önce maskelendi: ${summary}.`,
	pasteMaskedToast: (summary) => `Yapıştırılan metin maskelendi: ${summary}.`,
	fileMaskedToast: (files, summary) => `${files} dosya yüklenmeden önce maskelendi: ${summary}.`,
	fileUnscannedToast: (name) =>
		`"${name}" denetlenemedi (ikili dosya). Göndermeden önce kontrol edin.`,
	legacyOfficeToast: (name) =>
		`"${name}" (eski .doc/.xls/.ppt biçimi) tam olarak denetlenemedi. .docx/.xlsx/.pptx olarak kaydedin ya da göndermeden önce kontrol edin.`,
	imageUnscannedToast: (name) =>
		`"${name}" denetlenmedi: görseller için AIDR Privacy yardımcı uygulaması gerekir. Göndermeden önce kontrol edin.`,
	documentImagesToast: (name) =>
		`"${name}" içindeki görseller denetlenmedi. Göndermeden önce kontrol edin.`,
	pdfImagesUnscannedToast: (name) =>
		`"${name}" içindeki görseller denetlenmedi: görseller için AIDR Privacy yardımcı uygulaması gerekir. Göndermeden önce PDF'i kontrol edin.`,
	confirmTitle: "Mesajınızda kişisel veya gizli bilgi var",
	confirmBody: (summary, label, restores) =>
		`Bulunanlar: ${summary}. "Maskeli gönder" bunları, mesaj bilgisayarınızdan çıkmadan önce ${label} gibi etiketlerle değiştirir` +
		(restores ? "; yanıtta gerçek değerler yalnızca bu bilgisayarda yeniden gösterilir." : "."),
	sendOriginalNote: (site) =>
		`"Orijinali gönder" gerçek değerleri ${site ? `${site} hizmetine` : "bu yapay zekâ hizmetine"} gönderir. Bu seçim sayılır; mesajın kendisi hiçbir zaman raporlanmaz.`,
	namesNotChecked: "Kişi adları denetlenmedi: gelişmiş ad algılama kapalı.",
	warnTitle: "Göndermeden önce mesajınızı kontrol edin",
	blockedTitle: "Gönderim engellendi",
	blockedBody: (summary) => `Bulunanlar: ${summary}.`,
	blockedCoaching:
		"Kurumunuz bu verinin yapay zekâ hizmetlerine gönderilmesine izin vermiyor. " +
		"Veriyi çıkarın veya genel ifadelerle anlatıp yeniden deneyin.",
	pasteBlocked: "Yapıştırılan metin hassas veri içerdiği için eklenmedi.",
	pasteScanFailed: "Singularity AIDR yapıştırılan metni kontrol edemedi; metin eklenmedi.",
	scanFailed: "Singularity AIDR bu mesajı kontrol etmeyi tamamlayamadı; mesaj gönderilmedi.",
	policyMissing: "Koruma henüz yükleniyor. Hiçbir şey gönderilmedi; birazdan tekrar deneyin.",
	siteBlocked: "Kurumunuz bu yapay zekâ hizmetini engelledi. Hiçbir şey gönderilmedi.",
	editorMissing: "Bu sayfadaki mesaj alanı bulunamadı; hiçbir şey gönderilmedi.",
	editorAmbiguous:
		"Birden fazla metin alanında yazı var ve hangisinin gönderildiği anlaşılamadı; hiçbir şey gönderilmedi.",
	rewriteFailed: "Mesaj güvenli biçimde maskelenemedi. Hiçbir şey gönderilmedi.",
	textChanged: "Mesaj kontrol edilirken değişti. Yeniden gönderin.",
	pressSendAgain: "Mesaj maskelendi. Devam etmek için gönder düğmesine basın.",
	busy: "Önceki işlem hâlâ kontrol ediliyor.",
	fileBlockedTitle: "Yükleme engellendi",
	fileReasons: TR_FILE_REASONS,
	fileBlockedSignal: (name, coaching) => `"${name}" yüklenmedi. ${coaching}`,
	fileBlockedGeneric: (name, found) =>
		`"${name}" güvenli biçimde denetlenemediği için yüklenmedi${paren(found)}. Paylaşmanız gerekiyorsa BT ekibinize başvurun.`,
	fileBlockedByPolicy: "Kurumunuz yapay zekâ hizmetlerine dosya yüklenmesine izin vermiyor.",
	documentBlockedByPolicy:
		"Kurumunuz yapay zekâ hizmetlerine Office veya PDF belgesi yüklenmesine izin vermiyor.",
	fileScanFailed: "Dosya kontrol edilemedi; yüklenmedi.",
	fileReplaceUnsupported:
		"Bu tarayıcı dosyayı maskelenmiş kopyasıyla değiştiremiyor; dosya yüklenmedi.",
	fileInputUnguarded:
		"Bu sayfada bu yükleme düğmesiyle seçilen dosyalar denetlenemiyor; seçim engellendi.",
	nativeUnavailable:
		"Ad ve adresler yalnızca yerleşik kurallarla denetlendi: AIDR Privacy yardımcı uygulaması kullanılamadı.",
	nativeRequired:
		"Hiçbir şey gönderilmedi. Kurumunuz ad ve adres denetimi için AIDR Privacy yardımcı uygulamasını zorunlu tutuyor ve denetim yapılamadı (kurulu değil, yanıt vermiyor, ad algılaması yok ya da metin çok uzun). Yeniden deneyin, metni kısaltın ya da BT ekibinize başvurun.",
	aupAcknowledge: "Anladım",
	aupLater: "Daha sonra hatırlat",
	aupPolicyLink: "Politikanın tamamını okuyun",
	aupRecorded: "Teşekkürler. Onayınız kaydedildi.",
	aupRecordFailed: "Onayınız kaydedilemedi; bildirim yeniden gösterilecek.",
	aupVersion: (version) => `Kabul edilebilir kullanım bildirimi, sürüm ${version}`,
	accountTitle: "Kurum hesabı doğrulanamadı",
	accountReason: (type, site) =>
		type === "personal"
			? `${site} hizmetine kişisel bir hesapla girmiş görünüyorsunuz.`
			: type === "other"
				? `Bu ${site} hesabı, kurumunuzun onayladığı hesaplardan biri değil.`
				: `${BRAND}, ${site} hizmetine kurumunuzun hesabıyla girdiğinizi doğrulayamadı.`,
	accountWarn:
		"Kurum verilerini yalnızca kurumunuzun hesabıyla paylaşın. Hesabınızı değiştirin; bilerek devam ediyorsanız «Devam et» düğmesine basın.",
	accountBlocked: (site) =>
		`Hiçbir şey gönderilmedi. Kurumunuz ${site} hizmetini yalnızca kurum hesabıyla kullanmaya izin veriyor. Kurum hesabınıza geçip yeniden deneyin.`,
	accountUploadBlocked: (site) =>
		`Dosya yüklenmedi. Kurumunuz ${site} hizmetini yalnızca kurum hesabıyla kullanmaya izin veriyor. Kurum hesabınıza geçip yeniden deneyin.`,
	accountUploadWarn:
		"Bu, kurumunuzun hesabı gibi görünmüyor. Kurum dosyalarını yalnızca kurumunuzun hesabıyla paylaşın.",
	accountMaskOnly:
		"Bu, kurumunuzun hesabı değil; bu nedenle burada hassas veriler her zaman maskelenir ve asıl hâli gönderilemez.",
	accountContinue: "Devam et",
	accountCancel: "Vazgeç",
	accountSendAgain: "Mesajınızı göndermek için gönder düğmesine yeniden basın.",
};

export const STRINGS: Readonly<Record<Lang, Strings>> = { en: EN, tr: TR };

/** Singular and plural name of a data type ("1 email address", "2 email addresses"). */
interface EntityName {
	readonly one: string;
	readonly other: string;
}

const same = (name: string): EntityName => ({ one: name, other: name });

/**
 * Plain names of the data types, in sentence case. The singular form is the popup's
 * `entity_*` message (first letter lower-cased unless it starts an acronym or a proper
 * noun); ui-i18n.test.ts keeps the two in step. Turkish uses the singular after a number.
 */
export const ENTITY_NAMES: Readonly<Record<Lang, Readonly<Record<EntityType, EntityName>>>> = {
	en: {
		PERSON: { one: "person name", other: "person names" },
		EMAIL: { one: "email address", other: "email addresses" },
		PHONE: { one: "phone number", other: "phone numbers" },
		TC_KIMLIK: { one: "Turkish ID number (TCKN)", other: "Turkish ID numbers (TCKN)" },
		IBAN: { one: "IBAN", other: "IBANs" },
		CREDIT_CARD: { one: "credit card number", other: "credit card numbers" },
		ADDRESS: { one: "postal address", other: "postal addresses" },
		US_SSN: { one: "US Social Security number", other: "US Social Security numbers" },
		DATE_OF_BIRTH: { one: "date of birth", other: "dates of birth" },
		PASSPORT: { one: "passport number", other: "passport numbers" },
		NATIONAL_ID: { one: "national ID number", other: "national ID numbers" },
		TAX_ID: { one: "tax ID", other: "tax IDs" },
		BANK_ACCOUNT: { one: "bank account number", other: "bank account numbers" },
		IP_ADDRESS: { one: "IP address", other: "IP addresses" },
		MAC_ADDRESS: { one: "MAC address", other: "MAC addresses" },
		SECRET: { one: "API key, token or password", other: "API keys, tokens or passwords" },
		PRIVATE_KEY: { one: "private key", other: "private keys" },
		INTERNAL: { one: "internal information", other: "pieces of internal information" },
		CLASSIFIED: { one: "classification marking", other: "classification markings" },
		LOCATION: { one: "location", other: "locations" },
		USERNAME: { one: "username", other: "usernames" },
		HEALTH_ID: { one: "health record number", other: "health record numbers" },
		LICENSE_PLATE: { one: "vehicle license plate", other: "vehicle license plates" },
	},
	tr: {
		PERSON: same("kişi adı"),
		EMAIL: same("e-posta adresi"),
		PHONE: same("telefon numarası"),
		TC_KIMLIK: same("T.C. kimlik numarası"),
		IBAN: same("IBAN"),
		CREDIT_CARD: same("kredi kartı numarası"),
		ADDRESS: same("posta adresi"),
		US_SSN: same("ABD sosyal güvenlik numarası"),
		DATE_OF_BIRTH: same("doğum tarihi"),
		PASSPORT: same("pasaport numarası"),
		NATIONAL_ID: same("ulusal kimlik numarası"),
		TAX_ID: same("vergi kimlik numarası"),
		BANK_ACCOUNT: same("banka hesap numarası"),
		IP_ADDRESS: same("IP adresi"),
		MAC_ADDRESS: same("MAC adresi"),
		SECRET: same("API anahtarı, belirteç veya parola"),
		PRIVATE_KEY: same("özel anahtar"),
		INTERNAL: same("şirket içi bilgi"),
		CLASSIFIED: same("gizlilik derecesi işareti"),
		LOCATION: same("konum"),
		USERNAME: same("kullanıcı adı"),
		HEALTH_ID: same("sağlık kayıt numarası"),
		LICENSE_PLATE: same("araç plakası"),
	},
};

/** Resolves the UI language from policy preference, falling back to the browser language. */
export function resolveLanguage(
	preference: "auto" | "en" | "tr" | undefined,
	navigatorLanguage: string | undefined,
): Lang {
	if (preference === "en" || preference === "tr") return preference;
	return (navigatorLanguage ?? "").toLowerCase().startsWith("tr") ? "tr" : "en";
}

/** Total of all per-type counts. */
export function totalCount(counts: Readonly<Partial<Record<EntityType, number>>>): number {
	let total = 0;
	for (const type of ENTITY_TYPES) total += counts[type] ?? 0;
	return total;
}

/**
 * "1 Turkish ID number (TCKN), 2 email addresses" (TR: "1 T.C. kimlik numarası, 2 e-posta
 * adresi") in canonical entity order, using the plain data names the popup uses.
 */
export function formatCounts(
	counts: Readonly<Partial<Record<EntityType, number>>>,
	lang: Lang,
): string {
	const parts: string[] = [];
	for (const type of ENTITY_TYPES) {
		const n = counts[type] ?? 0;
		if (n <= 0) continue;
		const name = ENTITY_NAMES[lang][type];
		parts.push(`${n} ${n === 1 ? name.one : name.other}`);
	}
	return parts.join(", ");
}

/** An example label for the first type found, e.g. `[TCKN_1]` (`[EMAIL_1]` when none). */
export function exampleLabel(counts: Readonly<Partial<Record<EntityType, number>>>): string {
	const first = ENTITY_TYPES.find((type) => (counts[type] ?? 0) > 0) ?? "EMAIL";
	return `[${PLACEHOLDER_PREFIX[first]}_1]`;
}
