import type { MessagePairs } from "./define";

/** Device authorization page (`/verify`). */
export const verifyMessages = {
	"vf.failed": ["Verification failed.", "Doğrulama başarısız oldu."],
	"vf.noExpiry": [
		"The authorization service did not report a usable code expiry. Retry.",
		"Yetkilendirme hizmeti kullanılabilir bir kod bitiş süresi bildirmedi. Yeniden deneyin.",
	],
	"vf.justNow": ["less than a minute ago", "bir dakikadan kısa süre önce"],
	"vf.minuteAgo": ["1 minute ago", "1 dakika önce"],
	"vf.minutesAgo": ["{count} minutes ago", "{count} dakika önce"],
	"vf.scopeTenant": [
		"Enroll this device as an agent and issue it a tenant API key (tenant scope)",
		"Bu cihazı bir yapay zekâ aracı olarak kaydet ve ona bir çalışma alanı API anahtarı ver (çalışma alanı kapsamı)",
	],
	"vf.host": ["host {name}", "sunucu {name}"],
	"vf.os": ["OS {name}", "işletim sistemi {name}"],
	"vf.notReported": ["not reported", "bildirilmedi"],
	"vf.warning": [
		"{lead} If someone sent you this link or code, asked you to approve it, or you do not recognise the device below, stop: approving gives that device an API key for {team}.",
		"{lead} Bu bağlantıyı ya da kodu size biri gönderdiyse, onaylamanızı istediyse ya da aşağıdaki cihazı tanımıyorsanız durun: onaylamak, o cihaza {team} için bir API anahtarı verir.",
	],
	"vf.warningLead": [
		"Only approve a code you started on your own device.",
		"Yalnızca kendi cihazınızda başlattığınız bir kodu onaylayın.",
	],
	"vf.thisTeam": ["this team", "bu ekip"],
	"vf.codeMismatch": [
		"The code you typed differs from the code in the link. Only the code you typed will be authorized.",
		"Yazdığınız kod bağlantıdaki koddan farklı. Yalnızca yazdığınız kod yetkilendirilir.",
	],
	"vf.code": ["Code", "Kod"],
	"vf.requested": ["Requested", "İstenme"],
	"vf.ip": ["Requested from IP address", "İsteğin geldiği IP adresi"],
	"vf.notRecorded": ["not recorded", "kaydedilmedi"],
	"vf.device": ["Device (as reported by the device)", "Cihaz (cihazın bildirdiği şekilde)"],
	"vf.access": ["Access requested", "İstenen erişim"],
	"vf.team": ["Team", "Ekip"],
	"vf.confirm": [
		"I started this request on my own device and these details match it.",
		"Bu isteği kendi cihazımda başlattım ve bu ayrıntılar onunla eşleşiyor.",
	],
	"vf.authorize": ["Authorize device", "Cihazı yetkilendir"],
	"vf.sessionUnverified": ["Your session could not be verified.", "Oturumunuz doğrulanamadı."],
	"vf.teamsFailed": [
		"Your teams could not be loaded. Refresh to retry.",
		"Ekipleriniz yüklenemedi. Yeniden denemek için sayfayı yenileyin.",
	],
	"vf.sessionCheckFailed": ["Unable to check your session.", "Oturumunuz denetlenemedi."],
	"vf.selectTeamError": ["Select the team receiving this device.", "Bu cihazı alacak ekibi seçin."],
	"vf.notChecked": ["This code could not be checked.", "Bu kod denetlenemedi."],
	"vf.notDescribed": [
		"The authorization service did not describe this device. Nothing was authorized.",
		"Yetkilendirme hizmeti bu cihazı tanımlamadı. Hiçbir şey yetkilendirilmedi.",
	],
	"vf.unavailable": ["Device authorization is unavailable.", "Cihaz yetkilendirme kullanılamıyor."],
	"vf.lead": [
		"Type the short code your agent runtime shows on your own device. Approving links that device to your team and gives it an API key.",
		"Yapay zekâ aracınızın kendi cihazınızda gösterdiği kısa kodu yazın. Onaylamak o cihazı ekibinize bağlar ve ona bir API anahtarı verir.",
	],
	"vf.linkNotice": [
		"This page was opened from a link that carries a code. Do not copy the code from the link: type the code shown on the device you are setting up. If you did not start a sign-in on your own device in the last few minutes, close this page.",
		"Bu sayfa, kod içeren bir bağlantıdan açıldı. Kodu bağlantıdan kopyalamayın: kurduğunuz cihazda gösterilen kodu yazın. Son birkaç dakikada kendi cihazınızda bir oturum açma başlatmadıysanız bu sayfayı kapatın.",
	],
	"vf.teamReceiving": ["Team receiving this device", "Bu cihazı alacak ekip"],
	"vf.selectTeam": ["Select a team", "Bir ekip seçin"],
	"vf.continue": ["Continue", "Devam et"],
	"vf.signIn": ["Sign in", "Oturum aç"],
	"vf.authorized": [
		"{lead} Return to your agent. It should complete enrollment automatically.",
		"{lead} Yapay zekâ aracınıza dönün. Kaydı kendiliğinden tamamlaması gerekir.",
	],
	"vf.authorizedLead": ["Authorized.", "Yetkilendirildi."],
	"vf.expiresIn": ["Code expires in {time}", "Kodun süresi {time} içinde doluyor"],
	"vf.expired": [
		"This code expired before enrollment finished. Start authorization again in your agent and enter its new code.",
		"Bu kodun süresi kayıt bitmeden doldu. Yapay zekâ aracınızda yetkilendirmeyi yeniden başlatın ve yeni kodunu girin.",
	],
	"vf.help": [
		"Need help? Start again in your agent or contact support.",
		"Yardım mı gerekiyor? Yapay zekâ aracınızda yeniden başlayın ya da destekle iletişime geçin.",
	],
	"vf.returnOnboarding": ["Return to onboarding", "Kuruluma dön"],
	"vf.contactSupport": ["Contact support", "Destekle iletişime geç"],
} as const satisfies MessagePairs<string>;
