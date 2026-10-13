/**
 * User-facing coaching text for risk signals, in English and Turkish.
 * Turkish wording reuses AIDR Privacy's COACHING_TR where it exists.
 */
import { COACHING_TR } from "../../../privacy/src/enterprise/signals.js";
import type { SignalCode } from "../types.js";

const EN: Readonly<Record<SignalCode, string>> = Object.freeze({
	INSTRUCTION_OVERRIDE:
		"This text contains a pattern that tries to override the assistant's instructions. It may be a quotation or a security example; if you need to share it, use the approved review route.",
	PROMPT_EXTRACTION:
		"This text contains a pattern that asks the assistant to reveal its system instructions.",
	ROLE_DELIMITER:
		"This text contains chat-template role markers (such as <|im_start|> or [INST]) that can be used to smuggle instructions into the conversation.",
	ROLE_SPOOF:
		"This text contains a line that poses as a system or developer message. Remove it unless you are quoting it on purpose.",
	ACTIVE_CONTENT:
		"This text contains markup that can load external resources (script, iframe or image tags, Markdown images, CSS url()). Treat any output only as plain text.",
	SOURCE_CODE_HINT:
		"This text looks like source code. Company code should only be sent to approved destinations.",
	EXACT_DATA_MATCH:
		"This text matches records from a protected company dataset. Remove them before sending, or use an approved channel.",
});

const TR: Readonly<Record<SignalCode, string>> = Object.freeze({
	INSTRUCTION_OVERRIDE:
		COACHING_TR.INSTRUCTION_OVERRIDE ??
		"Metinde talimatları değiştirmeye yönelik bir kalıp bulundu.",
	PROMPT_EXTRACTION:
		COACHING_TR.PROMPT_EXTRACTION ??
		"Sistem talimatlarının açığa çıkarılmasına yönelik bir kalıp bulundu.",
	ROLE_DELIMITER:
		"Metinde sohbet şablonu rol işaretleri (ör. <|im_start|> veya [INST]) bulundu. Bu işaretler konuşmaya gizli talimat sokmak için kullanılabilir.",
	ROLE_SPOOF:
		"Metinde sistem veya geliştirici mesajı gibi görünen bir satır bulundu. Bilinçli bir alıntı değilse kaldırın.",
	ACTIVE_CONTENT: COACHING_TR.ACTIVE_CONTENT ?? "Harici kaynak yükleyebilen işaretleme bulundu.",
	SOURCE_CODE_HINT: COACHING_TR.SOURCE_CODE_HINT ?? "Kaynak kodu olabilecek içerik bulundu.",
	EXACT_DATA_MATCH:
		"Metin, korunan bir kurum veri kümesindeki kayıtlarla eşleşiyor. Göndermeden önce bu verileri çıkarın veya onaylı bir kanal kullanın.",
});

/** Coaching sentence for a signal; unknown languages fall back to English. */
export function coachingFor(code: SignalCode, lang: "en" | "tr"): string {
	const table = lang === "tr" ? TR : EN;
	return table[code] ?? EN[code] ?? "";
}

/** True for a known risk-signal code (e.g. the part after `SIGNAL_` in a file reason). */
export function isSignalCode(code: string): code is SignalCode {
	return Object.hasOwn(EN, code);
}
