/**
 * User-facing strings for the in-page guard (toast, bubble, restored-value tooltip).
 *
 * Only counts and entity type codes are ever interpolated; raw prompt text,
 * placeholder originals and file contents never appear in these messages.
 */
import { ENTITY_TYPES, type EntityType, PLACEHOLDER_PREFIX } from "../types.js";

export type Lang = "en" | "tr";

export interface Strings {
	readonly brand: string;
	readonly restoredTitle: string;
	readonly sendMasked: string;
	readonly sendOriginal: string;
	readonly sendAnyway: string;
	readonly edit: string;
	readonly close: string;
	maskedToast(total: number, summary: string): string;
	pasteMaskedToast(total: number, summary: string): string;
	fileMaskedToast(files: number, summary: string): string;
	fileUnscannedToast(name: string): string;
	/** A legacy .doc/.xls/.ppt upload passed through unchecked (it cannot be parsed). */
	legacyOfficeToast(name: string): string;
	/** An image passed through without OCR (no native host, or it could not read it fully). */
	imageUnscannedToast(name: string): string;
	/** A document was checked, but pictures inside it were not inspected. */
	documentImagesToast(name: string): string;
	readonly confirmTitle: string;
	confirmBody(total: number, summary: string): string;
	readonly warnTitle: string;
	readonly blockedTitle: string;
	blockedBody(total: number, summary: string): string;
	readonly blockedCoaching: string;
	readonly pasteBlocked: string;
	readonly pasteScanFailed: string;
	readonly scanFailed: string;
	readonly policyMissing: string;
	readonly siteBlocked: string;
	readonly editorMissing: string;
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
	/** Appended when a legacy Office file was blocked because it cannot be checked. */
	readonly legacyOfficeHint: string;
	readonly fileScanFailed: string;
	readonly fileReplaceUnsupported: string;
	/** Native NER was enabled but gave no usable answer: this check was rules-only. */
	readonly nativeUnavailable: string;
	/** Acceptable-use notice (administrator text is shown verbatim; these are the controls). */
	readonly aupAcknowledge: string;
	readonly aupLater: string;
	readonly aupPolicyLink: string;
	readonly aupRecorded: string;
	readonly aupRecordFailed: string;
	aupVersion(version: number): string;
}

const EN: Strings = {
	brand: "AIDR",
	restoredTitle: "Restored locally by AIDR",
	sendMasked: "Send masked",
	sendOriginal: "Send original",
	sendAnyway: "Send anyway",
	edit: "Edit",
	close: "Close",
	maskedToast: (total, summary) => `${total} ${total === 1 ? "item" : "items"} masked: ${summary}`,
	pasteMaskedToast: (total, summary) =>
		`Pasted text masked (${total} ${total === 1 ? "item" : "items"}): ${summary}`,
	fileMaskedToast: (files, summary) =>
		`${files} ${files === 1 ? "file" : "files"} sanitized before upload: ${summary}`,
	fileUnscannedToast: (name) =>
		`"${name}" could not be scanned (binary file). Check it before sending.`,
	legacyOfficeToast: (name) =>
		`"${name}" is a legacy Office file (.doc/.xls/.ppt) that AIDR cannot check. Save it as .docx/.xlsx/.pptx to have it masked, or check it before sending.`,
	imageUnscannedToast: (name) =>
		`"${name}" is an image and its content was not inspected (the local OCR helper is not available or could not read it). Check it before sending.`,
	documentImagesToast: (name) =>
		`Pictures inside "${name}" were not inspected. Check them before sending.`,
	confirmTitle: "Sensitive data in your prompt",
	confirmBody: (total, summary) =>
		`${total} sensitive ${total === 1 ? "item was" : "items were"} found: ${summary}. ` +
		"They can be replaced with placeholders and restored locally in the answer.",
	warnTitle: "Check your prompt before sending",
	blockedTitle: "Sending blocked",
	blockedBody: (total, summary) =>
		`${total} sensitive ${total === 1 ? "item was" : "items were"} found: ${summary}.`,
	blockedCoaching:
		"Your organisation does not allow this data to be sent to AI services. " +
		"Remove it or describe it in general terms, then try again.",
	pasteBlocked: "The pasted text contains sensitive data and was not inserted.",
	pasteScanFailed: "AIDR could not check the pasted text, so it was not inserted.",
	scanFailed: "AIDR could not finish checking this prompt, so it was not sent.",
	policyMissing: "AIDR protection is still loading. Nothing was sent; try again in a moment.",
	siteBlocked: "Your organisation has blocked this AI service. Nothing was sent.",
	editorMissing: "AIDR could not find the prompt box on this page, so nothing was sent.",
	rewriteFailed: "AIDR could not safely rewrite the prompt. Nothing was sent.",
	textChanged: "The prompt changed while it was being checked. Press send again.",
	pressSendAgain: "The prompt was masked. Press send to continue.",
	busy: "AIDR is still checking the previous action.",
	fileBlockedTitle: "Upload blocked",
	fileBlockedBody: (name, reasons) => `"${name}" was not uploaded (${reasons}).`,
	fileBlockedByPolicy: "Your organisation does not allow file uploads to AI services.",
	documentBlockedByPolicy:
		"Your organisation does not allow Office or PDF documents to be uploaded to AI services.",
	pdfPasteHint:
		"PDFs cannot be masked. Copy the text you need and paste it instead: AIDR masks pasted text.",
	imageBlockedHint:
		"The image shows sensitive data and images cannot be masked. Crop or redact it before uploading.",
	legacyOfficeHint:
		"Legacy Office formats cannot be checked. Save the file as .docx/.xlsx/.pptx and upload that instead.",
	fileScanFailed: "AIDR could not check the file, so it was not uploaded.",
	fileReplaceUnsupported:
		"This browser cannot replace the file with a sanitized copy, so it was not uploaded.",
	nativeUnavailable:
		"Advanced name and address detection (native host) is unavailable: checked with built-in rules only.",
	aupAcknowledge: "I understand",
	aupLater: "Remind me later",
	aupPolicyLink: "Read the full policy",
	aupRecorded: "Thank you. Your acknowledgement was recorded.",
	aupRecordFailed: "Your acknowledgement could not be saved; the notice will be shown again.",
	aupVersion: (version) => `Acceptable-use notice, version ${version}`,
};

const TR: Strings = {
	brand: "AIDR",
	restoredTitle: "AIDR tarafından yerel olarak geri yüklendi",
	sendMasked: "Maskeli gönder",
	sendOriginal: "Orijinali gönder",
	sendAnyway: "Yine de gönder",
	edit: "Düzenle",
	close: "Kapat",
	maskedToast: (total, summary) => `${total} öğe maskelendi: ${summary}`,
	pasteMaskedToast: (total, summary) => `Yapıştırılan metin maskelendi (${total} öğe): ${summary}`,
	fileMaskedToast: (files, summary) => `${files} dosya yüklenmeden önce temizlendi: ${summary}`,
	fileUnscannedToast: (name) =>
		`"${name}" taranamadı (ikili dosya). Göndermeden önce kontrol edin.`,
	legacyOfficeToast: (name) =>
		`"${name}" eski bir Office dosyası (.doc/.xls/.ppt); AIDR bu biçimi denetleyemez. Maskelenmesi için .docx/.xlsx/.pptx olarak kaydedin ya da göndermeden önce kontrol edin.`,
	imageUnscannedToast: (name) =>
		`"${name}" bir görsel ve içeriği denetlenmedi (yerel OCR yardımcısı yok ya da görseli okuyamadı). Göndermeden önce kontrol edin.`,
	documentImagesToast: (name) =>
		`"${name}" içindeki görseller denetlenmedi. Göndermeden önce kontrol edin.`,
	confirmTitle: "İsteminizde hassas veri var",
	confirmBody: (total, summary) =>
		`${total} hassas öğe bulundu: ${summary}. ` +
		"Bunlar yer tutucularla değiştirilip yanıtta yerel olarak geri yüklenebilir.",
	warnTitle: "Göndermeden önce isteminizi kontrol edin",
	blockedTitle: "Gönderim engellendi",
	blockedBody: (total, summary) => `${total} hassas öğe bulundu: ${summary}.`,
	blockedCoaching:
		"Kurumunuz bu verinin yapay zekâ hizmetlerine gönderilmesine izin vermiyor. " +
		"Veriyi çıkarın veya genel ifadelerle anlatıp yeniden deneyin.",
	pasteBlocked: "Yapıştırılan metin hassas veri içerdiği için eklenmedi.",
	pasteScanFailed: "AIDR yapıştırılan metni kontrol edemedi; metin eklenmedi.",
	scanFailed: "AIDR bu istemi kontrol etmeyi tamamlayamadı; gönderilmedi.",
	policyMissing:
		"AIDR koruması henüz yükleniyor. Hiçbir şey gönderilmedi; birazdan tekrar deneyin.",
	siteBlocked: "Kurumunuz bu yapay zekâ hizmetini engelledi. Hiçbir şey gönderilmedi.",
	editorMissing: "AIDR bu sayfadaki istem alanını bulamadı; hiçbir şey gönderilmedi.",
	rewriteFailed: "AIDR istemi güvenli biçimde yeniden yazamadı. Hiçbir şey gönderilmedi.",
	textChanged: "İstem kontrol edilirken değişti. Yeniden gönderin.",
	pressSendAgain: "İstem maskelendi. Devam etmek için gönderin.",
	busy: "AIDR önceki işlemi kontrol etmeye devam ediyor.",
	fileBlockedTitle: "Yükleme engellendi",
	fileBlockedBody: (name, reasons) => `"${name}" yüklenmedi (${reasons}).`,
	fileBlockedByPolicy: "Kurumunuz yapay zekâ hizmetlerine dosya yüklenmesine izin vermiyor.",
	documentBlockedByPolicy:
		"Kurumunuz yapay zekâ hizmetlerine Office veya PDF belgesi yüklenmesine izin vermiyor.",
	pdfPasteHint:
		"PDF dosyaları maskelenemez. Gereken metni kopyalayıp yapıştırın: AIDR yapıştırılan metni maskeler.",
	imageBlockedHint:
		"Görselde hassas veri görünüyor ve görseller maskelenemez. Yüklemeden önce kırpın ya da karartın.",
	legacyOfficeHint:
		"Eski Office biçimleri denetlenemez. Dosyayı .docx/.xlsx/.pptx olarak kaydedip onu yükleyin.",
	fileScanFailed: "AIDR dosyayı kontrol edemedi; dosya yüklenmedi.",
	fileReplaceUnsupported:
		"Bu tarayıcı dosyayı temizlenmiş kopyasıyla değiştiremiyor; dosya yüklenmedi.",
	nativeUnavailable:
		"Gelişmiş ad ve adres algılama (yerel yardımcı uygulama) kullanılamıyor: yalnızca yerleşik kurallarla kontrol edildi.",
	aupAcknowledge: "Anladım",
	aupLater: "Daha sonra hatırlat",
	aupPolicyLink: "Politikanın tamamını okuyun",
	aupRecorded: "Teşekkürler. Onayınız kaydedildi.",
	aupRecordFailed: "Onayınız kaydedilemedi; bildirim yeniden gösterilecek.",
	aupVersion: (version) => `Kabul edilebilir kullanım bildirimi, sürüm ${version}`,
};

export const STRINGS: Readonly<Record<Lang, Strings>> = { en: EN, tr: TR };

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

/** "2 EMAIL, 1 TCKN" in canonical entity order, using the short placeholder prefixes. */
export function formatCounts(counts: Readonly<Partial<Record<EntityType, number>>>): string {
	const parts: string[] = [];
	for (const type of ENTITY_TYPES) {
		const n = counts[type] ?? 0;
		if (n > 0) parts.push(`${n} ${PLACEHOLDER_PREFIX[type]}`);
	}
	return parts.join(", ");
}
