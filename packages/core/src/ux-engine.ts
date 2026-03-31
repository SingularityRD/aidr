import type { Verdict } from "./types.js";

export interface UserMessage {
	icon: "✅" | "⚠️" | "🚫" | "ℹ️";
	title: string;
	description: string;
	action?: string;
	alternatives?: string[];
	details?: Record<string, string>;
}

export class UserExperienceEngine {
	/**
	 * Convert technical verdict to human-friendly message
	 */
	explainVerdict(
		verdict: Verdict,
		toolName: string,
		toolInput: Record<string, unknown>,
	): UserMessage {
		if (verdict.decision === "allow") {
			return {
				icon: "✅",
				title: "Güvenli",
				description: this.getAllowDescription(toolName, toolInput),
			};
		}

		if (verdict.decision === "deny") {
			return {
				icon: "🚫",
				title: "Engellendi",
				description: verdict.reasons[0] || "Güvenlik riski tespit edildi",
				action: "Güvenli alternatifleri görmek için tıklayın",
				alternatives: this.suggestAlternatives(toolName, toolInput),
				details: {
					"MITRE Technique": verdict.matchedThreatId || "Bilinmiyor",
					"Risk Skoru": String(verdict.confidence || "N/A"),
					Kategori: verdict.category || "Genel",
				},
			};
		}

		// Ask mode
		return {
			icon: "⚠️",
			title: "Onay Gerekiyor",
			description: verdict.reasons.join(". ") || "Bu işlem ek onay gerektiriyor",
			action: "Devam etmek istiyor musunuz?",
			details: {
				Etki: this.assessImpact(toolName, toolInput),
				Öneri: this.getRecommendation(toolName, toolInput),
			},
		};
	}

	private getAllowDescription(tool: string, input: Record<string, unknown>): string {
		const descriptions: Record<string, string> = {
			Bash: `Komut güvenli görünüyor: ${String(input.command || "").slice(0, 50)}...`,
			Write: `Dosya yazma izni: ${input.file_path}`,
			Read: `Dosya okuma: ${input.file_path}`,
			WebFetch: `URL erişimi: ${input.url}`,
		};
		return descriptions[tool] || `${tool} işlemi onaylandı`;
	}

	private suggestAlternatives(tool: string, input: Record<string, unknown>): string[] {
		const cmd = String(input.command || "");

		if (cmd.includes("curl") && cmd.includes("| bash")) {
			return [
				"1. curl -o script.sh && cat script.sh (incele)",
				"2. curl -o script.sh && sha256sum script.sh (verify)",
				"3. Package manager kullan: npm install / brew install",
			];
		}

		if (tool === "Bash" && cmd.includes("rm -rf /")) {
			return [
				"1. Önce --dry-run ile test et",
				"2. Sadece spesifik dosyaları sil",
				"3. Trash/recycle kullan (geri alınabilir)",
			];
		}

		return ["Manuel review yapın", "Güvenilir kaynak kullanın", "Sandbox ortamında test edin"];
	}

	private assessImpact(tool: string, input: Record<string, unknown>): string {
		const path = String(input.file_path || "");

		if (path.includes("/etc/") || path.includes("/system")) {
			return "🔴 Sistem dosyaları - Yüksek risk";
		}
		if (path.includes(".env") || path.includes("secret")) {
			return "🔴 Hassas veri - Yüksek risk";
		}
		if (path.includes("/home/") || path.includes("~/")) {
			return "🟡 Kullanıcı verisi - Orta risk";
		}
		return "🟢 Genel kullanım - Düşük risk";
	}

	private getRecommendation(tool: string, input: Record<string, unknown>): string {
		const cmd = String(input.command || "");

		if (cmd.includes("sudo")) {
			return "Root yetkisi gereksiz olabilir. Normal user yetkisi yeterli mi?";
		}

		if (tool === "Write" && input.file_path?.toString().includes(".sh")) {
			return "Script yazıyorsunuz. Executable bit ayarlamayı unutmayın: chmod +x";
		}

		return "Standart güvenlik uygulamalarını takip edin";
	}

	/**
	 * Format dashboard data for simple display
	 */
	formatDashboard(stats: {
		allowed: number;
		asked: number;
		denied: number;
		threats: Array<{ id: string; count: number }>;
	}): string {
		const lines = [
			"┌─────────────────────────────────────┐",
			"│  AIDR Security Dashboard            │",
			"├─────────────────────────────────────┤",
			`│  🟢 İzin verildi: ${String(stats.allowed).padStart(3)}          │`,
			`│  🟡 Sorgulandı:   ${String(stats.asked).padStart(3)}          │`,
			`│  🔴 Engellendi:   ${String(stats.denied).padStart(3)}          │`,
			"├─────────────────────────────────────┤",
			"│  Top Tehditler:                     │",
		];

		for (const threat of stats.threats.slice(0, 3)) {
			const line = `│  • ${threat.id.slice(0, 15).padEnd(15)}: ${String(threat.count).padStart(2)}   │`;
			lines.push(line);
		}

		lines.push("└─────────────────────────────────────┘");
		return lines.join("\n");
	}
}

export function createUXEngine(): UserExperienceEngine {
	return new UserExperienceEngine();
}
