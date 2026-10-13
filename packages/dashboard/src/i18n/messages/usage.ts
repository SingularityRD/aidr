import type { MessagePairs } from "./define";

/** Usage metering widget on the dashboard. */
export const usageMessages = {
	"usage.status.active": ["Active", "Etkin"],
	"usage.status.paused": ["Paused", "Duraklatıldı"],
	"usage.status.cancelled": ["Cancelled", "İptal edildi"],
	"usage.status.pastDue": ["Past due", "Ödemesi gecikmiş"],
	"usage.status.expired": ["Expired", "Süresi doldu"],
	"usage.status.unverified": ["Term expired or unverified", "Süre doldu ya da doğrulanamadı"],
	"usage.barLabel": ["{value} of {max} agents used", "{max} ajanın {value} tanesi kullanılıyor"],
	"usage.trendLabel": [
		"Agent creation trend over the last 7 days",
		"Son 7 gündeki yeni ajan eğilimi",
	],
	"usage.dayAgents": ["{day}: {count} agents", "{day}: {count} ajan"],
	"usage.dayAgent": ["{day}: 1 agent", "{day}: 1 ajan"],
	"usage.unavailable": [
		"Seat entitlement data is unavailable.",
		"Lisans hakkı verileri alınamıyor.",
	],
	"usage.loadFailed": ["Failed to load usage data", "Kullanım verileri yüklenemedi"],
	"usage.noAccess": ["No active access", "Etkin erişim yok"],
	"usage.noSubscription": ["No subscription record", "Abonelik kaydı yok"],
	"usage.currentPeriodEnds": ["Current period ends", "Geçerli dönem bitişi"],
	"usage.noAllocation": ["No active agent allocation", "Etkin ajan tahsisi yok"],
	"usage.allocation": [
		"Effective allocation — {allowed} agents ({included} included)",
		"Geçerli tahsis — {allowed} ajan ({included} dahil)",
	],
	"usage.allocationOne": [
		"Effective allocation — 1 agent ({included} included)",
		"Geçerli tahsis — 1 ajan ({included} dahil)",
	],
	"usage.overLimit": ["Over limit.", "Sınır aşıldı."],
	"usage.mayReject": ["New agents may be rejected.", "Yeni ajanlar reddedilebilir."],
	"usage.addSeats": ["Add extra seats to continue.", "Devam etmek için ek lisans ekleyin."],
	"usage.upgrade": ["Upgrade", "Yükselt"],
	"usage.approaching": ["Approaching limit.", "Sınıra yaklaşıldı."],
	"usage.used": [
		"You've used {percent}% of your agent allowance.",
		"Ajan hakkınızın %{percent} kadarını kullandınız.",
	],
	"usage.title": ["Usage Metering", "Kullanım ölçümü"],
	"usage.noTeam": ["Select a team to view usage.", "Kullanımı görmek için bir ekip seçin."],
	"usage.subtitle": ["Agent consumption vs your plan allowance", "Ajan kullanımı ve plan hakkınız"],
	"usage.agentUsage": ["Agent usage", "Ajan kullanımı"],
	"usage.newAgents": ["New agents (last {days} days)", "Yeni ajanlar (son {days} gün)"],
} as const satisfies MessagePairs<string>;
