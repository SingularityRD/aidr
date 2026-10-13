import type { MessagePairs } from "./define";

/** Dashboard overview page. */
export const dashboardMessages = {
	"dash.queryFailed": ["Dashboard query failed.", "Panel sorgusu başarısız oldu."],
	"dash.malformed": ["Malformed dashboard query response.", "Panel sorgusu hatalı yanıt döndürdü."],
	"dash.timeout": ["Dashboard query timed out.", "Panel sorgusu zaman aşımına uğradı."],
	"dash.tokensUnavailable": [
		"Enrollment tokens are unavailable.",
		"Kayıt belirteçleri alınamıyor.",
	],
	"dash.tokenMalformed": ["Malformed enrollment token.", "Hatalı kayıt belirteci."],
	"dash.noTeam": ["Select a team to view dashboard.", "Paneli görmek için bir ekip seçin."],
	"dash.eyebrow": ["AIDR control plane", "AIDR kontrol düzlemi"],
	"dash.lead": [
		"Review reported agent security decisions in one dashboard.",
		"Yapay zekâ araçlarının bildirdiği güvenlik kararlarını tek bir panelde inceleyin.",
	],
	"dash.intro": [
		"Install with the Windows or Linux installer, approve the device code once, then review check-ins and security events as they arrive.",
		"Windows ya da Linux yükleyicisiyle kurun, cihaz kodunu bir kez onaylayın, ardından gelen bildirimleri ve güvenlik olaylarını inceleyin.",
	],
	"dash.connect": ["Connect agent", "Yapay zekâ aracı bağla"],
	"dash.verify": ["Verify code", "Kodu doğrula"],
	"dash.privacy": ["Privacy settings", "Gizlilik ayarları"],
	"dash.signedInAs": ["Signed in as", "Oturum açan hesap"],
	"dash.heartbeat": ["Latest heartbeat", "Son bildirim"],
	"dash.noAgentsYet": ["no agents yet", "henüz yapay zekâ aracı yok"],
	"dash.counters": ["Fleet counters", "Filo sayaçları"],
	"dash.agents": ["Agents", "Yapay zekâ araçları"],
	"dash.connected": ["Connected", "Bağlı"],
	"dash.atLeast": ["at least; latest {count} heartbeats", "en az; son {count} bildirim"],
	"dash.pending": ["Pending", "Bekleyen"],
	"dash.events": ["Events", "Etkinlikler"],
	"dash.latest500": ["latest 500", "son 500"],
	"dash.blocked": ["Blocked", "Engellenen"],
	"dash.needsApproval": ["Needs approval", "Onay gereken"],
	"dash.liveAgents": ["Live agents", "Canlı yapay zekâ araçları"],
	"dash.viewAll": ["View all", "Tümünü gör"],
	"dash.liveIntro": [
		"Connected installations and their current health.",
		"Bağlı kurulumlar ve güncel durumları.",
	],
	"dash.state": ["State", "Durum"],
	"dash.fresh": ["connected", "bağlı"],
	"dash.stale": ["stale", "eskimiş"],
	"dash.unknown": ["unknown", "bilinmiyor"],
	"dash.agentsUnavailable": [
		"Agent data is unavailable right now.",
		"Yapay zekâ aracı verileri şu anda kullanılamıyor.",
	],
	"dash.noAgents": [
		"No agents yet. Use {link} to enroll your first AI tool.",
		"Henüz yapay zekâ aracı yok. İlk yapay zekâ aracınızı kaydetmek için {link} sayfasını kullanın.",
	],
	"dash.recentEvents": ["Recent events", "Son etkinlikler"],
	"dash.recentIntro": [
		"The latest security events received from your agents.",
		"Yapay zekâ araçlarınızdan gelen son güvenlik etkinlikleri.",
	],
	"dash.eventsUnavailable": [
		"Event data is unavailable right now.",
		"Etkinlik verileri şu anda kullanılamıyor.",
	],
	"dash.noEvents": ["No events recorded yet.", "Henüz kaydedilmiş etkinlik yok."],
} as const satisfies MessagePairs<string>;
