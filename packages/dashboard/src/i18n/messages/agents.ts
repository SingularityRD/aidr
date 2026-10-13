import type { MessagePairs } from "./define";

/** Agents list and agent detail pages. */
export const agentsMessages = {
	"agents.loadFailed": ["Failed to load agents", "Ajanlar yüklenemedi"],
	"agents.unavailable": ["Agent data is unavailable.", "Ajan verileri kullanılamıyor."],
	"agents.seatsLoadFailed": ["Failed to load seat usage", "Lisans kullanımı yüklenemedi"],
	"agents.seatsUnavailable": [
		"Seat usage data is unavailable.",
		"Lisans kullanım verileri kullanılamıyor.",
	],
	"agents.noTeam": ["Select a team to view its agents.", "Ajanlarını görmek için bir ekip seçin."],
	"agents.summary": [
		"Known installations (unique {iid}). Allowed: {allowed}. Recorded: {recorded}.",
		"Bilinen kurulumlar (benzersiz {iid}). İzin verilen: {allowed}. Kayıtlı: {recorded}.",
	],
	"agents.badge.recorded": ["agents recorded", "kayıtlı ajan var"],
	"agents.badge.none": ["no agents", "ajan yok"],
	"agents.seatsWarning": [
		"Seat usage data is unavailable; do not infer the allowed-agent limit.",
		"Lisans kullanım verileri alınamadı; izin verilen ajan sınırını tahmin etmeyin.",
	],
	"agents.runtime": ["Runtime", "Yapay zekâ aracı"],
	"agents.lastSeen": ["Last seen", "Son görülme"],
	"agents.view": ["View", "Görüntüle"],
	"agents.empty": [
		"No agents yet. Go to {link} to connect your first agent.",
		"Henüz ajan yok. İlk ajanınızı bağlamak için {link} sayfasına gidin.",
	],

	"agent.missingId": ["Agent identifier is missing.", "Ajan kimliği eksik."],
	"agent.noTeam": ["Select a team to view this agent.", "Bu ajanı görmek için bir ekip seçin."],
	"agent.loadFailed": ["Failed to load agent", "Ajan yüklenemedi"],
	"agent.entitlementFailed": [
		"Failed to load agent entitlement",
		"Ajanın lisans bilgisi yüklenemedi",
	],
	"agent.eventsFailed": ["Failed to load agent events", "Ajan olayları yüklenemedi"],
	"agent.back": ["← Agents", "← Ajanlar"],
	"agent.title": ["Agent", "Ajan"],
	"agent.entitlement": ["Entitlement snapshot", "Lisans anlık görüntüsü"],
	"agent.entitlementLine": [
		"{tier} | allowed: {allowed} | expires: {expires}",
		"{tier} | izin verilen: {allowed} | bitiş: {expires}",
	],
	"agent.updated": ["Updated: {time}", "Güncellendi: {time}"],
	"agent.noEntitlement": ["No entitlement snapshot yet.", "Henüz lisans anlık görüntüsü yok."],
	"agent.unavailableNow": [
		"Agent data is unavailable right now.",
		"Ajan verileri şu anda kullanılamıyor.",
	],
	"agent.notFound": ["Agent not found.", "Ajan bulunamadı."],
	"agent.recentEvents": ["Recent events", "Son olaylar"],
	"agent.time": ["Time", "Zaman"],
	"agent.summary": ["Summary", "Özet"],
	"agent.noDetails": [
		"Additional event details are not shown.",
		"Ek olay ayrıntıları gösterilmez.",
	],
	"agent.eventsUnavailable": [
		"Event data is unavailable right now.",
		"Olay verileri şu anda kullanılamıyor.",
	],
	"agent.loadingEvents": ["Loading events…", "Olaylar yükleniyor…"],
	"agent.noEvents": ["No events yet.", "Henüz olay yok."],
} as const satisfies MessagePairs<string>;
