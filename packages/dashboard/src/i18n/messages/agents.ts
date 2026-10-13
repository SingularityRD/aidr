import type { MessagePairs } from "./define";

/** Agents list and agent detail pages. */
export const agentsMessages = {
	"agents.loadFailed": ["Failed to load agents", "Yapay zekâ araçları yüklenemedi"],
	"agents.unavailable": ["Agent data is unavailable.", "Yapay zekâ aracı verileri kullanılamıyor."],
	"agents.seatsLoadFailed": ["Failed to load seat usage", "Lisans kullanımı yüklenemedi"],
	"agents.seatsUnavailable": [
		"Seat usage data is unavailable.",
		"Lisans kullanım verileri kullanılamıyor.",
	],
	"agents.noTeam": [
		"Select a team to view its agents.",
		"Yapay zekâ araçlarını görmek için bir ekip seçin.",
	],
	"agents.summary": [
		"Known installations (unique {iid}). Allowed: {allowed}. Recorded: {recorded}.",
		"Bilinen kurulumlar (benzersiz {iid}). İzin verilen: {allowed}. Kayıtlı: {recorded}.",
	],
	"agents.badge.recorded": ["agents recorded", "kayıtlı yapay zekâ aracı var"],
	"agents.badge.none": ["no agents", "yapay zekâ aracı yok"],
	"agents.seatsWarning": [
		"Seat usage data is unavailable; do not infer the allowed-agent limit.",
		"Lisans kullanım verileri alınamadı; izin verilen yapay zekâ aracı sınırını tahmin etmeyin.",
	],
	"agents.runtime": ["Runtime", "Yapay zekâ aracı"],
	"agents.lastSeen": ["Last seen", "Son görülme"],
	"agents.view": ["View", "Görüntüle"],
	"agents.empty": [
		"No agents yet. Go to {link} to connect your first agent.",
		"Henüz yapay zekâ aracı yok. İlk yapay zekâ aracınızı bağlamak için {link} sayfasına gidin.",
	],

	"agent.missingId": ["Agent identifier is missing.", "Yapay zekâ aracı kimliği eksik."],
	"agent.noTeam": [
		"Select a team to view this agent.",
		"Bu yapay zekâ aracını görmek için bir ekip seçin.",
	],
	"agent.loadFailed": ["Failed to load agent", "Yapay zekâ aracı yüklenemedi"],
	"agent.entitlementFailed": [
		"Failed to load agent entitlement",
		"Yapay zekâ aracının lisans bilgisi yüklenemedi",
	],
	"agent.eventsFailed": ["Failed to load agent events", "Yapay zekâ aracı olayları yüklenemedi"],
	"agent.back": ["← Agents", "← Yapay zekâ araçları"],
	"agent.title": ["Agent", "Yapay zekâ aracı"],
	"agent.entitlement": ["Entitlement snapshot", "Lisans anlık görüntüsü"],
	"agent.entitlementLine": [
		"{tier} | allowed: {allowed} | expires: {expires}",
		"{tier} | izin verilen: {allowed} | bitiş: {expires}",
	],
	"agent.updated": ["Updated: {time}", "Güncellendi: {time}"],
	"agent.noEntitlement": ["No entitlement snapshot yet.", "Henüz lisans anlık görüntüsü yok."],
	"agent.unavailableNow": [
		"Agent data is unavailable right now.",
		"Yapay zekâ aracı verileri şu anda kullanılamıyor.",
	],
	"agent.notFound": ["Agent not found.", "Yapay zekâ aracı bulunamadı."],
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
