import type { MessagePairs } from "./define";

/** Public editions page and plan feature labels. */
export const pricingMessages = {
	"feature.localDetection": ["Local detection engine", "Yerel tespit motoru"],
	"feature.dashboard": ["Control-plane dashboard", "Yönetim paneli"],
	"feature.entraSso": [
		"Microsoft Entra ID single sign-on",
		"Microsoft Entra ID ile tek oturum açma",
	],
	"feature.siem": ["SIEM export", "SIEM dışa aktarımı"],
	"feature.scim": ["SCIM provisioning", "SCIM ile kullanıcı sağlama"],
	"feature.posture": ["AI security posture", "Yapay zekâ güvenlik durumu"],
	"feature.airGapped": ["Air-gapped deployment", "İnternetten yalıtılmış kurulum"],
	"feature.support": ["Dedicated support", "Özel destek"],
	"deploy.cloud": ["Cloud", "Bulut"],
	"deploy.onprem": ["On-premises", "Şirket içi"],
	"deploy.airGapped": ["Air-gapped", "İnternetten yalıtılmış"],
	"pr.contactAbout": ["Contact sales about {edition}", "{edition} için satışla iletişime geçin"],
	"pr.contact": ["Contact sales", "Satışla iletişime geçin"],
	"pr.startFree": ["Start with Free", "Ücretsiz sürümle başlayın"],
	"pr.choose": ["Choose {plan}", "{plan} seçin"],
	"pr.scopeReview": ["Request scope review", "Kapsam incelemesi isteyin"],
	"pr.title": ["Editions", "Paketler"],
	"pr.lead": [
		"Paid editions are licensed per developer seat, and each seat admits one protected agent installation ({iid}). Local detection runs on the developer machine in every edition. {orders} The cloud trial is 14 days for one agent.",
		"Ücretli paketler geliştirici lisansıyla verilir ve her lisans bir korunan yapay zekâ aracı kurulumuna ({iid}) izin verir. Yerel tespit her pakette geliştiricinin bilgisayarında çalışır. {orders} Bulut denemesi tek yapay zekâ aracı için 14 gündür.",
	],
	"pr.ordersCheckout": [
		"Orders are placed through checkout or an approved written quote.",
		"Siparişler ödeme sayfasından ya da onaylı yazılı bir teklifle verilir.",
	],
	"pr.ordersQuote": [
		"Orders require an approved written quote; self-service checkout is not offered.",
		"Siparişler onaylı yazılı bir teklif gerektirir; kendi kendine ödeme sunulmaz.",
	],
	"pr.requestQuote": [
		"{note} Request a quote from {email}.",
		"{note} Teklif için {email} adresine yazın.",
	],
	"pr.editionsLabel": ["Editions", "Paketler"],
	"pr.selfServe": ["Self-serve", "Kendi kendine"],
	"pr.salesAssisted": ["Sales-assisted", "Satış destekli"],
	"pr.freeNote": ["No account needed for local detection", "Yerel tespit için hesap gerekmez"],
	"pr.quoteBased": ["Quote-based", "Teklifle"],
	"pr.or": [" or ", " ya da "],
	"pr.deployment": ["{list} deployment", "{list} kurulum"],
	"pr.pilot": ["Pilot", "Pilot"],
	"pr.reviewRequired": ["Review required", "İnceleme gerekli"],
	"pr.pilot1": [
		"Agent count and deployment scope agreed in writing",
		"Yapay zekâ aracı sayısı ve kurulum kapsamı yazılı olarak kararlaştırılır",
	],
	"pr.pilot2": [
		"Dashboard access only within an accepted evaluation scope",
		"Panel erişimi yalnızca kabul edilmiş değerlendirme kapsamında",
	],
	"pr.pilot3": [
		"Support and data-retention terms agreed before enrollment",
		"Destek ve veri saklama koşulları kayıttan önce kararlaştırılır",
	],
	"pr.pilotNote": [
		"Paid plans become active only after verified payment or an approved order, and seat limits are enforced by the control plane.",
		"Ücretli planlar yalnızca doğrulanmış ödeme ya da onaylı bir siparişten sonra etkinleşir ve lisans sınırlarını yönetim paneli uygular.",
	],
	"pr.pilotReview": ["Request pilot review", "Pilot incelemesi isteyin"],
	"pr.enterprise": ["Enterprise and on-premises", "Kurumsal ve şirket içi"],
	"pr.enterpriseLead": [
		"On-premises, Kubernetes and air-gapped deployments require an agreed scope, Finance-approved quote, and written support terms before a paid order.",
		"Şirket içi, Kubernetes ve internetten yalıtılmış kurulumlar, ücretli siparişten önce kararlaştırılmış bir kapsam, Finans onaylı bir teklif ve yazılı destek koşulları gerektirir.",
	],
} as const satisfies MessagePairs<string>;
