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
import { ENTITY_TYPES, type EntityType, PLACEHOLDER_PREFIX } from "../types.js";

export type Lang = "en" | "tr";

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
	fileBlockedBody(name: string, reasons: string): string;
	readonly fileBlockedByPolicy: string;
	/** documentHandling "block": Office/PDF uploads are not allowed. */
	readonly documentBlockedByPolicy: string;
	/** Appended when a PDF was blocked for sensitive data (PDFs cannot be masked in place). */
	readonly pdfPasteHint: string;
	/** Appended when an image (or a picture in a document) was blocked for sensitive text. */
	readonly imageBlockedHint: string;
	/** Appended when a legacy Office file was blocked because it could not be fully checked. */
	readonly legacyOfficeHint: string;
	/** Appended when a legacy Office file was blocked for sensitive data (it cannot be masked). */
	readonly legacyOfficeSensitiveHint: string;
	readonly fileScanFailed: string;
	readonly fileReplaceUnsupported: string;
	readonly fileInputUnguarded: string;
	/** Native NER was enabled but gave no usable answer: this check was rules-only. */
	readonly nativeUnavailable: string;
	/** policy.requireNativeNer: native NER gave no usable answer, so the send/paste was blocked. */
	readonly nativeRequired: string;
	/** Appended to a blocked upload whose text (or images) the required native NER did not check. */
	readonly nativeRequiredFileHint: string;
	/** Acceptable-use notice (administrator text is shown verbatim; these are the controls). */
	readonly aupAcknowledge: string;
	readonly aupLater: string;
	readonly aupPolicyLink: string;
	readonly aupRecorded: string;
	readonly aupRecordFailed: string;
	aupVersion(version: number): string;
}

/** Brand name; never translated or upper-cased (the UI marks it lang="en"). */
const BRAND = "Singularity AIDR";

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
	fileBlockedBody: (name, reasons) => `"${name}" was not uploaded (${reasons}).`,
	fileBlockedByPolicy: "Your organisation does not allow file uploads to AI services.",
	documentBlockedByPolicy:
		"Your organisation does not allow Office or PDF documents to be uploaded to AI services.",
	pdfPasteHint:
		"PDFs cannot be masked. Copy the text you need and paste it instead: pasted text is masked.",
	imageBlockedHint:
		"The image shows sensitive data and images cannot be masked. Crop or redact it before uploading.",
	legacyOfficeHint:
		"This old Office file could not be fully checked. Save the file as .docx/.xlsx/.pptx and upload that instead.",
	legacyOfficeSensitiveHint:
		"Old Office files (.doc/.xls/.ppt) cannot be masked. Save the file as .docx/.xlsx/.pptx and upload that instead: those are masked.",
	fileScanFailed: "The file could not be checked, so it was not uploaded.",
	fileReplaceUnsupported:
		"This browser cannot replace the file with a masked copy, so it was not uploaded.",
	fileInputUnguarded:
		"Files chosen through this upload button cannot be checked on this page, so the selection was blocked.",
	nativeUnavailable:
		"Names and addresses were checked with built-in rules only: the AIDR Privacy helper app could not be used.",
	nativeRequired:
		"Nothing was sent. Your organisation requires the AIDR Privacy helper app to check names and addresses, and it could not (not installed, not responding, no name detection, or the text is too long). Try again, shorten the text, or contact your IT team.",
	nativeRequiredFileHint:
		"Your organisation requires the AIDR Privacy helper app to check uploads, and it could not check this file. Try again in a moment or contact your IT team.",
	aupAcknowledge: "I understand",
	aupLater: "Remind me later",
	aupPolicyLink: "Read the full policy",
	aupRecorded: "Thank you. Your acknowledgement was recorded.",
	aupRecordFailed: "Your acknowledgement could not be saved; the notice will be shown again.",
	aupVersion: (version) => `Acceptable-use notice, version ${version}`,
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
	fileBlockedBody: (name, reasons) => `"${name}" yüklenmedi (${reasons}).`,
	fileBlockedByPolicy: "Kurumunuz yapay zekâ hizmetlerine dosya yüklenmesine izin vermiyor.",
	documentBlockedByPolicy:
		"Kurumunuz yapay zekâ hizmetlerine Office veya PDF belgesi yüklenmesine izin vermiyor.",
	pdfPasteHint:
		"PDF dosyaları maskelenemez. Gereken metni kopyalayıp yapıştırın: yapıştırılan metin maskelenir.",
	imageBlockedHint:
		"Görselde hassas veri görünüyor ve görseller maskelenemez. Yüklemeden önce kırpın ya da karartın.",
	legacyOfficeHint:
		"Bu eski Office dosyası tam olarak denetlenemedi. Dosyayı .docx/.xlsx/.pptx olarak kaydedip onu yükleyin.",
	legacyOfficeSensitiveHint:
		"Eski Office dosyaları (.doc/.xls/.ppt) maskelenemez. Dosyayı .docx/.xlsx/.pptx olarak kaydedip onu yükleyin: bu biçimler maskelenir.",
	fileScanFailed: "Dosya kontrol edilemedi; yüklenmedi.",
	fileReplaceUnsupported:
		"Bu tarayıcı dosyayı maskelenmiş kopyasıyla değiştiremiyor; dosya yüklenmedi.",
	fileInputUnguarded:
		"Bu sayfada bu yükleme düğmesiyle seçilen dosyalar denetlenemiyor; seçim engellendi.",
	nativeUnavailable:
		"Ad ve adresler yalnızca yerleşik kurallarla denetlendi: AIDR Privacy yardımcı uygulaması kullanılamadı.",
	nativeRequired:
		"Hiçbir şey gönderilmedi. Kurumunuz ad ve adres denetimi için AIDR Privacy yardımcı uygulamasını zorunlu tutuyor ve denetim yapılamadı (kurulu değil, yanıt vermiyor, ad algılaması yok ya da metin çok uzun). Yeniden deneyin, metni kısaltın ya da BT ekibinize başvurun.",
	nativeRequiredFileHint:
		"Kurumunuz yüklemelerin AIDR Privacy yardımcı uygulamasıyla denetlenmesini zorunlu tutuyor ve bu dosya denetlenemedi. Biraz sonra yeniden deneyin ya da BT ekibinize başvurun.",
	aupAcknowledge: "Anladım",
	aupLater: "Daha sonra hatırlat",
	aupPolicyLink: "Politikanın tamamını okuyun",
	aupRecorded: "Teşekkürler. Onayınız kaydedildi.",
	aupRecordFailed: "Onayınız kaydedilemedi; bildirim yeniden gösterilecek.",
	aupVersion: (version) => `Kabul edilebilir kullanım bildirimi, sürüm ${version}`,
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
