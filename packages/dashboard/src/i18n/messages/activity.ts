import type { MessagePairs } from "./define";

/** Activity feed (events) and security incidents pages. */
export const activityMessages = {
	"verdict.allow": ["allowed", "izin verildi"],
	"verdict.deny": ["blocked", "engellendi"],
	"verdict.ask": ["needs approval", "onay gerekiyor"],
	"activity.tool": ["tool", "araç"],
	"activity.time": ["Time", "Zaman"],
	"activity.agent": ["Agent", "Yapay zekâ aracı"],
	"activity.type": ["Type", "Tür"],
	"activity.verdict": ["Decision", "Karar"],
	"activity.summary": ["Summary", "Özet"],

	"events.noTeam": ["Select a team to view events.", "Etkinlikleri görmek için bir ekip seçin."],
	"events.loadFailed": ["Failed to load events", "Etkinlikler yüklenemedi"],
	"events.noDetails": [
		"Additional event details are not shown.",
		"Ek etkinlik ayrıntıları gösterilmez.",
	],
	"events.intro": [
		"The latest 500 events received from this team's agents. With default reporting, blocked and approval-required decisions are uploaded; allowed actions are uploaded only when clean-verdict reporting is on.",
		"Bu ekibin yapay zekâ araçlarından alınan son 500 etkinlik. Varsayılan raporlamada engellenen ve onay gerektiren kararlar gönderilir; izin verilen işlemler yalnızca temiz karar raporlaması açıksa gönderilir.",
	],
	"events.count.deny": ["{count} blocked", "{count} engellendi"],
	"events.count.ask": ["{count} needs approval", "{count} onay gerekiyor"],
	"events.count.allow": ["{count} allowed", "{count} izin verildi"],
	"events.unavailable": [
		"Event data is unavailable right now.",
		"Etkinlik verileri şu anda kullanılamıyor.",
	],
	"events.loading": ["Loading events…", "Etkinlikler yükleniyor…"],
	"events.filter.range": ["Time range", "Zaman aralığı"],
	"events.range.all": ["All time", "Tüm zamanlar"],
	"events.range.1h": ["Last hour", "Son 1 saat"],
	"events.range.24h": ["Last 24 hours", "Son 24 saat"],
	"events.range.7d": ["Last 7 days", "Son 7 gün"],
	"events.range.30d": ["Last 30 days", "Son 30 gün"],
	"events.filter.typeAll": ["All types", "Tüm türler"],
	"events.filter.decisionAll": ["All decisions", "Tüm kararlar"],
	"events.filter.severity": ["Severity", "Önem"],
	"events.filter.severityAll": ["All severities", "Tüm önem düzeyleri"],
	"events.filter.agentAll": ["All agents", "Tüm yapay zekâ araçları"],
	"events.filter.rule": ["Rule ID", "Kural kimliği"],
	"events.filter.ruleInvalid": [
		"A rule ID uses letters, digits and . _ : - only.",
		"Kural kimliği yalnızca harf, rakam ve . _ : - içerir.",
	],
	"events.filter.apply": ["Apply", "Uygula"],
	"events.filter.clear": ["Clear filters", "Filtreleri temizle"],
	"events.filter.none": ["No events match these filters.", "Bu filtrelerle eşleşen etkinlik yok."],
	"events.capped": [
		"Showing the latest {count} matching events. Narrow the time range or filters to reach older events.",
		"Eşleşen son {count} etkinlik gösteriliyor. Daha eski etkinlikler için zaman aralığını veya filtreleri daraltın.",
	],
	"events.export.csv": ["Export CSV", "CSV dışa aktar"],
	"events.export.json": ["Export JSON", "JSON dışa aktar"],
	"events.export.hint": [
		"Exports the {count} events shown, as loaded under your access.",
		"Gösterilen {count} etkinliği, erişiminizle yüklendiği hâliyle dışa aktarır.",
	],
	"events.empty": [
		"No events received yet. Check agent enrollment and telemetry delivery.",
		"Henüz etkinlik alınmadı. Yapay zekâ aracı kaydını ve telemetri gönderimini kontrol edin.",
	],

	"incidents.noTeam": ["Select a team to view incidents.", "Vakaları görmek için bir ekip seçin."],
	"incidents.loadFailed": ["Failed to load incidents", "Vakalar yüklenemedi"],
	"incidents.noDetails": [
		"Additional incident details are not shown.",
		"Ek vaka ayrıntıları gösterilmez.",
	],
	"incidents.correlated": ["correlated incident", "ilişkili vaka"],
	"incidents.eventCount": ["{count} event(s)", "{count} etkinlik"],
	"incidents.intro": [
		"Possible security incidents built from the blocked and approval-required decisions your agents sent. Counts cover the latest 500 events, not the complete history kept on each computer.",
		"Yapay zekâ araçlarınızın gönderdiği engellenen ve onay gerektiren kararlardan oluşturulan olası güvenlik vakaları. Sayılar tüm geçmişi değil, son 500 etkinliği kapsar; her bilgisayarda tutulan geçmiş daha uzundur.",
	],
	"incidents.count.blocked": ["{count} blocked", "{count} engellendi"],
	"incidents.count.ask": ["{count} approval required", "{count} onay gerekli"],
	"incidents.count.scans": ["{count} scan findings", "{count} tarama bulgusu"],
	"incidents.canary": ["Canary triggered", "Tuzak kimlik bilgisi tetiklendi"],
	"incidents.unavailable": [
		"Incident data is unavailable right now.",
		"Vaka verileri şu anda kullanılamıyor.",
	],
	"incidents.loading": ["Loading incidents…", "Vakalar yükleniyor…"],
	"incidents.empty": ["No incidents yet.", "Henüz vaka yok."],
} as const satisfies MessagePairs<string>;
