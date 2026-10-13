import type { MessagePairs } from "./define";

/** Plan card (current plan, usage and plan picker) and shared plan terms. */
export const billingPlanMessages = {
	"plan.source.stripe": ["Verified card subscription", "Doğrulanmış kart aboneliği"],
	"plan.source.record": ["Billing record", "Faturalandırma kaydı"],
	"plan.source.default": ["Default plan", "Varsayılan plan"],
	"plan.quoteNotice": [
		"Prices are not published. Paid editions are quoted for your seats and deployment; a written quote or order governs.",
		"Fiyatlar yayımlanmaz. Ücretli sürümler için lisans sayınıza ve kurulumunuza göre teklif verilir; yazılı teklif ya da sipariş geçerlidir.",
	],
	"plan.terms.freeAgents": ["{count} protected agent", "{count} korunan yapay zekâ aracı"],
	"plan.terms.minDevelopers": ["Minimum {count} developers", "En az {count} geliştirici"],
	"plan.terms.agreement": ["Scoped per agreement", "Sözleşmeye göre belirlenir"],
	"plan.terms.contractual": ["Contractual retention", "Sözleşmeye bağlı saklama"],
	"plan.terms.retention": ["{days}-day event retention", "{days} gün etkinlik saklama"],
	"plan.working": ["Working…", "İşleniyor…"],
	"plan.checkout": ["Continue to checkout", "Ödemeye geç"],
	"plan.requestUpgrade": ["Request upgrade", "Yükseltme iste"],
	"plan.loading": ["Loading plan…", "Plan yükleniyor…"],
	"plan.loadFailed": [
		"Plan information could not be loaded for this tenant. No plan or usage figure is shown until it can be read.",
		"Bu çalışma alanının plan bilgisi yüklenemedi. Okunabilene kadar plan ya da kullanım bilgisi gösterilmez.",
	],
	"plan.billing": ["Billing", "Faturalandırma"],
	"plan.monthly": ["Monthly", "Aylık"],
	"plan.annual": ["Annual", "Yıllık"],
	"plan.current": ["Current plan", "Geçerli plan"],
	"plan.inUse": ["Protected agents in use", "Kullanılan korunan yapay zekâ araçları"],
	"plan.perSeat": [
		"{count} agent per seat on this plan",
		"Bu planda lisans başına {count} yapay zekâ aracı",
	],
	"plan.admission": ["Admission", "Kabul durumu"],
	"plan.termEnds": ["Term ends {date}", "Süre bitişi {date}"],
	"plan.usage": ["Protected agent usage", "Korunan yapay zekâ aracı kullanımı"],
	"plan.noCapacity": [
		"This tenant has no admitted protected-agent capacity. New agents are rejected by the control plane until a trial, licence or paid plan is active.",
		"Bu çalışma alanının kabul edilmiş korunan yapay zekâ aracı kapasitesi yok. Deneme, lisans ya da ücretli plan etkinleşene kadar yeni yapay zekâ araçları kontrol düzlemi tarafından reddedilir.",
	],
	"plan.overCapacity": [
		"More agents are connected than the plan admits; additional agents may be rejected.",
		"Planın izin verdiğinden fazla yapay zekâ aracı bağlı; ek yapay zekâ araçları reddedilebilir.",
	],
	"plan.cardLine": [
		"Card subscription: {plan} · {seats} seats · {interval} · {status}",
		"Kart aboneliği: {plan} · {seats} lisans · {interval} · {status}",
	],
	"plan.paidThrough": [" · paid through {date}", " · {date} tarihine kadar ödendi"],
	"plan.planFallback": ["Plan", "Plan"],
	"plan.openCheckout": ["Open secure checkout", "Güvenli ödeme sayfasını aç"],
	"plan.checkoutReady": [
		"Checkout is ready. The plan changes only after the payment provider confirms an active subscription.",
		"Ödeme sayfası hazır. Plan, yalnızca ödeme sağlayıcısı etkin bir aboneliği doğruladıktan sonra değişir.",
	],
	"plan.upgradeSent": [
		"Upgrade request for {plan} ({seats} developer seats) was sent to Finance review as {status}. Your plan is unchanged until an approved order is applied.",
		"{plan} için yükseltme isteği ({seats} geliştirici lisansı) {status} durumuyla Finans incelemesine gönderildi. Onaylı bir sipariş uygulanana kadar planınız değişmez.",
	],
	"plan.checkoutFailed": [
		"Checkout could not be prepared. Retry, or request the upgrade through Finance.",
		"Ödeme sayfası hazırlanamadı. Yeniden deneyin ya da yükseltmeyi Finans üzerinden isteyin.",
	],
	"plan.upgradeRejected": [
		"The upgrade request was not accepted. Retry or contact the approved sales channel.",
		"Yükseltme isteği kabul edilmedi. Yeniden deneyin ya da onaylı satış kanalıyla iletişime geçin.",
	],
	"plan.cardLabel": ["Current plan", "Geçerli plan"],
	"plan.title": ["Plan", "Plan"],
	"plan.change": ["Change plan", "Planı değiştir"],
	"plan.quoteContact": ["For a quote, contact {email}", "Teklif için {email} adresine yazın"],
	"plan.checkoutAmount": [
		"; a card checkout shows the amount on the payment provider's page before you pay.",
		"; kartla ödemede tutar, ödemeden önce ödeme sağlayıcısının sayfasında gösterilir.",
	],
	"plan.ownerOnly": [
		"Plan changes are limited to tenant owners and admins.",
		"Plan değişiklikleri yalnızca çalışma alanı sahipleri ve yöneticileri içindir.",
	],
	"plan.picker": ["Plan picker", "Plan seçici"],
	"plan.developerSeats": ["Developer seats", "Geliştirici lisansları"],
	"plan.minSeats": [
		"{plan} requires at least {count} developer seats.",
		"{plan} en az {count} geliştirici lisansı gerektirir.",
	],
	"plan.financeNote": [
		"This request is reviewed by Finance and invoiced; it does not change the plan until an approved order is applied.",
		"Bu istek Finans tarafından incelenir ve faturalanır; onaylı bir sipariş uygulanana kadar planı değiştirmez.",
	],
} as const satisfies MessagePairs<string>;
