import type { Verdict } from "./types.js";

export interface ToolCall {
	toolName: string;
	toolInput: Record<string, unknown>;
	timestamp: number;
	verdict: Verdict;
}

export interface ChainLink {
	from: ToolCall;
	to: ToolCall;
	relationship: ChainRelationship;
	riskScore: number;
}

export interface ChainRelationship {
	type: "data_flow" | "dependency" | "sequential" | "causal";
	dataTransferred?: string[];
	confidence: number;
}

export interface AttackChain {
	tools: ToolCall[];
	totalRisk: number;
	patterns: string[];
	isDataExfiltration: boolean;
	isPrivilegeEscalation: boolean;
	isPersistenceAttempt: boolean;
}

export interface ChainAnalysisResult {
	chains: AttackChain[];
	highestRiskChain: AttackChain | null;
	recommendedAction: "allow" | "deny" | "ask" | "monitor";
	confidence: number;
}

const DANGEROUS_SEQUENCES = [
	{
		pattern: ["Read", "Bash", "WebFetch"],
		risk: 90,
		description: "Potential data exfiltration: read file → execute command → upload",
	},
	{
		pattern: ["Read", "Bash"],
		condition: (calls: ToolCall[]) => {
			const readCall = calls[0];
			const bashCall = calls[1];
			if (!readCall || !bashCall) return false;
			const readPath = String(readCall.toolInput.file_path || "").toLowerCase();
			const bashCmd = String(bashCall.toolInput.command || "").toLowerCase();
			return (
				readPath.includes("/etc/passwd") && (bashCmd.includes("curl") || bashCmd.includes("wget"))
			);
		},
		risk: 95,
		description: "Critical: reading password file and sending via network",
	},
	{
		pattern: ["Read", "Write"],
		condition: (calls: ToolCall[]) => {
			const readCall = calls[0];
			const writeCall = calls[1];
			if (!readCall || !writeCall) return false;
			const readPath = String(readCall.toolInput.file_path || "").toLowerCase();
			const writePath = String(writeCall.toolInput.file_path || "").toLowerCase();
			return readPath.includes(".ssh") && writePath.includes("authorized_keys");
		},
		risk: 95,
		description: "SSH key tampering detected",
	},
	{
		pattern: ["Read", "Edit"],
		condition: (calls: ToolCall[]) => {
			const readCall = calls[0];
			const editCall = calls[1];
			if (!readCall || !editCall) return false;
			const readPath = String(readCall.toolInput.file_path || "").toLowerCase();
			const editPath = String(editCall.toolInput.file_path || "").toLowerCase();
			return readPath.includes("credential") && editPath.includes(".env");
		},
		risk: 85,
		description: "Credential file manipulation",
	},
];

const DATA_EXFILTRATION_PATTERNS = [
	{ read: ["secret", "credential", "key", "token"], transfer: ["curl", "wget", "upload"] },
	{ read: ["/etc/passwd", "/etc/shadow"], transfer: ["curl", "wget"] },
	{ read: [".env"], transfer: ["curl", "wget", "http"] },
];

export class CommandChainAnalyzer {
	private history: ToolCall[] = [];
	private readonly maxHistory: number;

	constructor(maxHistory = 50) {
		this.maxHistory = maxHistory;
	}

	recordToolCall(toolCall: ToolCall): void {
		this.history.push(toolCall);

		if (this.history.length > this.maxHistory) {
			this.history.shift();
		}
	}

	analyzeRecentChain(windowSize = 5): ChainAnalysisResult {
		const recentCalls = this.history.slice(-windowSize);

		if (recentCalls.length < 2) {
			return {
				chains: [],
				highestRiskChain: null,
				recommendedAction: "allow",
				confidence: 1.0,
			};
		}

		const chains = this.identifyAttackChains(recentCalls);

		if (chains.length === 0) {
			return {
				chains: [],
				highestRiskChain: null,
				recommendedAction: "allow",
				confidence: 1.0,
			};
		}

		const highestRiskChain = chains.reduce((max, chain) =>
			chain.totalRisk > max.totalRisk ? chain : max,
		);

		return {
			chains,
			highestRiskChain,
			recommendedAction: this.determineAction(highestRiskChain),
			confidence: highestRiskChain.totalRisk / 100,
		};
	}

	private identifyAttackChains(calls: ToolCall[]): AttackChain[] {
		const chains: AttackChain[] = [];

		for (const sequence of DANGEROUS_SEQUENCES) {
			const matches = this.findSequenceMatches(calls, sequence.pattern);

			for (const match of matches) {
				if (sequence.condition && !sequence.condition(match)) {
					continue;
				}

				const chain: AttackChain = {
					tools: match,
					totalRisk: sequence.risk,
					patterns: [sequence.description],
					isDataExfiltration: this.checkDataExfiltration(match),
					isPrivilegeEscalation: this.checkPrivilegeEscalation(match),
					isPersistenceAttempt: this.checkPersistence(match),
				};

				chains.push(chain);
			}
		}

		return chains;
	}

	private findSequenceMatches(calls: ToolCall[], pattern: string[]): ToolCall[][] {
		const matches: ToolCall[][] = [];

		for (let i = 0; i <= calls.length - pattern.length; i++) {
			const slice = calls.slice(i, i + pattern.length);
			const toolNames = slice.map((c) => c.toolName);

			if (JSON.stringify(toolNames) === JSON.stringify(pattern)) {
				matches.push(slice);
			}
		}

		return matches;
	}

	private checkDataExfiltration(calls: ToolCall[]): boolean {
		const callText = JSON.stringify(calls).toLowerCase();

		return DATA_EXFILTRATION_PATTERNS.some((pattern) => {
			const hasRead = pattern.read.some((r) => callText.includes(r));
			const hasTransfer = pattern.transfer.some((t) => callText.includes(t));
			return hasRead && hasTransfer;
		});
	}

	private checkPrivilegeEscalation(calls: ToolCall[]): boolean {
		const callText = JSON.stringify(calls).toLowerCase();
		return (
			callText.includes("sudo") || callText.includes("chmod 777") || callText.includes("chown")
		);
	}

	private checkPersistence(calls: ToolCall[]): boolean {
		const callText = JSON.stringify(calls).toLowerCase();
		return (
			callText.includes("crontab") ||
			callText.includes("bashrc") ||
			callText.includes("systemctl enable") ||
			callText.includes("ssh/authorized_keys")
		);
	}

	private determineAction(chain: AttackChain): "allow" | "deny" | "ask" | "monitor" {
		if (chain.totalRisk >= 90) return "deny";
		if (chain.totalRisk >= 70) return "ask";
		if (chain.totalRisk >= 50) return "monitor";
		return "allow";
	}

	getChainSummary(): { totalCalls: number; analyzedChains: number; averageRisk: number } {
		const recentAnalysis = this.analyzeRecentChain();
		const risks = recentAnalysis.chains.map((c) => c.totalRisk);

		return {
			totalCalls: this.history.length,
			analyzedChains: recentAnalysis.chains.length,
			averageRisk: risks.length > 0 ? risks.reduce((a, b) => a + b, 0) / risks.length : 0,
		};
	}
}

export function createCommandChainAnalyzer(maxHistory?: number): CommandChainAnalyzer {
	return new CommandChainAnalyzer(maxHistory);
}
