import type { MessagePairs } from "./define";

/** Compliance report, SIEM syslog form and session messages from shared helpers. */
export const helperErrorsMessages = {
	"ce.mfa": [
		"Compliance reports need a multi-factor (AAL2) session. Sign in again with your second factor and retry.",
		"Uyum raporları çok adımlı doğrulanmış (AAL2) bir oturum gerektirir. İkinci doğrulama adımınızla yeniden oturum açıp tekrar deneyin.",
	],
	"ce.revoked": [
		"Your session was revoked. Sign in again.",
		"Oturumunuz kapatıldı. Yeniden oturum açın.",
	],
	"ce.forbidden": [
		"Only active owners and admins of this workspace can generate compliance reports.",
		"Uyum raporlarını yalnızca bu çalışma alanının etkin sahipleri ve yöneticileri oluşturabilir.",
	],
	"ce.inactive": [
		"Reports can only be generated for an active workspace.",
		"Raporlar yalnızca etkin bir çalışma alanı için oluşturulabilir.",
	],
	"ce.rateLimited": [
		"Too many reports were requested. Wait a minute and try again.",
		"Çok fazla rapor istendi. Bir dakika bekleyip yeniden deneyin.",
	],
	"ce.invalidPeriod": [
		"Choose a valid period: the end must be after the start and not in the future.",
		"Geçerli bir dönem seçin: bitiş, başlangıçtan sonra olmalı ve gelecekte olmamalıdır.",
	],
	"ce.tooLong": [
		"A report can cover at most 366 days.",
		"Bir rapor en fazla 366 günü kapsayabilir.",
	],
	"ce.future": ["The period cannot end in the future.", "Dönem gelecekte bitemez."],
	"ce.hash": [
		"The report received does not match its own SHA-256, so it is not shown. Generate it again.",
		"Alınan rapor kendi SHA-256 değeriyle eşleşmiyor; bu yüzden gösterilmiyor. Yeniden oluşturun.",
	],
	"ce.malformed": [
		"The report received is incomplete, so it is not shown. Generate it again.",
		"Alınan rapor eksik; bu yüzden gösterilmiyor. Yeniden oluşturun.",
	],
	"ce.unavailable": [
		"The compliance report could not be generated. No partial report was produced; try again later.",
		"Uyum raporu oluşturulamadı. Yarım bir rapor üretilmedi; daha sonra yeniden deneyin.",
	],
} as const satisfies MessagePairs<string>;
