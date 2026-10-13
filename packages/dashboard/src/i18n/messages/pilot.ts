import type { MessagePairs } from "./define";

/** Public pilot and workspace access page. */
export const pilotMessages = {
	"pl.workspaceUnverified": [
		"Unable to verify an active workspace.",
		"Etkin bir çalışma alanı doğrulanamadı.",
	],
	"pl.workspaceInvalid": [
		"The active workspace response is invalid.",
		"Etkin çalışma alanı yanıtı geçersiz.",
	],
	"pl.statusInvalid": ["Pilot status response is invalid.", "Pilot durum yanıtı geçersiz."],
	"pl.notConfirmed": [
		"The pilot service did not confirm the application.",
		"Pilot hizmeti başvuruyu onaylamadı.",
	],
	"pl.noWorkspace": [
		"No active workspace is available for this account.",
		"Bu hesap için etkin bir çalışma alanı yok.",
	],
	"pl.loadFailed": ["Unable to load pilot status.", "Pilot durumu yüklenemedi."],
	"pl.accessInvalid": [
		"Workspace access response is invalid.",
		"Çalışma alanı erişim yanıtı geçersiz.",
	],
	"pl.titlePilot": ["Pilot program", "Pilot programı"],
	"pl.titleAccess": ["Workspace access", "Çalışma alanı erişimi"],
	"pl.leadPilot": [
		"Pilot access is approval-gated. Scope, pricing, support, and data-retention terms are confirmed in writing before enrollment. An application requests review; it does not grant access or authorize production use.",
		"Pilot erişimi onaya bağlıdır. Kapsam, fiyatlandırma, destek ve veri saklama koşulları kayıttan önce yazılı olarak doğrulanır. Başvuru yalnızca inceleme ister; erişim vermez ve üretim kullanımına izin vermez.",
	],
	"pl.leadAccess": [
		"Sign in to check your workspace access and available setup options.",
		"Çalışma alanı erişiminizi ve kullanılabilir kurulum seçeneklerini görmek için oturum açın.",
	],
	"pl.signIn": ["Sign in to check access", "Erişimi görmek için oturum açın"],
	"pl.contactSales": ["Contact sales", "Satışla iletişime geçin"],
	"pl.noSales": [
		"A sales contact route is not configured.",
		"Satış iletişim yolu yapılandırılmamış.",
	],
	"pl.workspace": ["Workspace", "Çalışma alanı"],
	"pl.teamWorkspace": ["Team workspace · {id}", "Ekip çalışma alanı · {id}"],
	"pl.personalWorkspace": ["Personal workspace · {id}", "Kişisel çalışma alanı · {id}"],
	"pl.yourStatus": ["Your status", "Durumunuz"],
	"pl.status.none": ["none", "yok"],
	"pl.status.pending": ["pending", "bekliyor"],
	"pl.status.approved": ["approved", "onaylandı"],
	"pl.status.denied": ["denied", "reddedildi"],
	"pl.checking": ["checking", "denetleniyor"],
	"pl.setUpTrial": ["Set up 14-day trial", "14 günlük denemeyi kur"],
	"pl.startOnboarding": ["Start onboarding", "Kuruluma başla"],
	"pl.needTeam": [
		"Agent enrollment requires a team workspace. Select an approved team workspace above.",
		"Yapay zekâ aracı kaydı bir ekip çalışma alanı gerektirir. Yukarıdan onaylı bir ekip çalışma alanı seçin.",
	],
	"pl.trial": [
		"Trial: {count} agent; ends {time}.",
		"Deneme: {count} yapay zekâ aracı; bitiş {time}.",
	],
	"pl.legalPending": [
		"Trial setup awaits published Terms and Privacy. Contact your administrator.",
		"Deneme kurulumu, Koşullar ve Gizlilik belgelerinin yayımlanmasını bekliyor. Yöneticinize başvurun.",
	],
	"pl.noTrial": [
		"No self-service trial is available for this workspace. Contact your administrator or sales.",
		"Bu çalışma alanı için kendi kendine deneme yok. Yöneticinize ya da satış ekibine başvurun.",
	],
	"pl.inactive": [
		"Workspace access is not active. Contact your deployment administrator.",
		"Çalışma alanı erişimi etkin değil. Kurulum yöneticinize başvurun.",
	],
	"pl.apply": ["Apply", "Başvurun"],
	"pl.applyLead": [
		"Describe the runtime and tools you want to protect. Do not include credentials, tokens, customer content, or other sensitive data.",
		"Korumak istediğiniz yapay zekâ aracını ve araçları anlatın. Kimlik bilgisi, belirteç, müşteri içeriği ya da başka hassas veri eklemeyin.",
	],
	"pl.useCase": ["Use case", "Kullanım senaryosu"],
	"pl.reviewed": [
		"I have reviewed the {privacy} and {terms}.",
		"{privacy} ve {terms} metinlerini inceledim.",
	],
	"pl.privacy": ["privacy notice", "gizlilik bildirimi"],
	"pl.terms": ["pilot terms", "pilot koşulları"],
	"pl.legalMissing": [
		"Pilot applications are disabled until safe HTTPS privacy and terms documents are configured.",
		"Güvenli HTTPS gizlilik ve koşullar belgeleri yapılandırılana kadar pilot başvuruları kapalıdır.",
	],
	"pl.submitFailed": ["Failed to submit", "Gönderilemedi"],
	"pl.submit": ["Submit application", "Başvuruyu gönder"],
} as const satisfies MessagePairs<string>;
