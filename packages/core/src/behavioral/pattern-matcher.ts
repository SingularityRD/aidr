/**
 * Pattern matcher for behavioral analysis.
 * Identifies recurring patterns in user behavior and detects deviations.
 */

import type { AnomalyResult } from "./anomaly-detector.js";

export interface CommandSequence {
	commands: string[];
	timestamp: number;
	directory: string;
	tool: string;
}

export interface Pattern {
	id: string;
	name: string;
	sequence: string[]; // Command patterns (can include wildcards)
	context: PatternContext;
	frequency: number;
	lastSeen: number;
}

export interface PatternContext {
	directories: string[];
	tools: string[];
	hours: number[];
}

export interface PatternMatch {
	pattern: Pattern;
	confidence: number;
	matches: number;
}

export interface BehaviorFingerprint {
	hourlyDistribution: number[]; // 24-hour activity distribution
	directoryPreferences: Record<string, number>;
	toolChainPatterns: string[]; // Common command chains
	sequenceEntropy: number; // Randomness measure
}

// Wildcard patterns for command matching
const WILDCARD_PATTERNS = {
	FILE_OP: "{file_op}", // read/write/edit/delete
	GIT_OP: "{git}", // git commands
	BUILD_OP: "{build}", // npm, make, cargo, etc.
	SHELL_OP: "{shell}", // bash, sh, etc.
	NET_OP: "{net}", // curl, wget, ssh, etc.
};

export class PatternMatcher {
	private patterns: Map<string, Pattern> = new Map();
	private recentSequences: CommandSequence[] = [];
	private maxHistorySize = 1000;

	/**
	 * Add a known good pattern
	 */
	addPattern(pattern: Omit<Pattern, "id">): Pattern {
		const id = `pattern_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
		const fullPattern: Pattern = { ...pattern, id };
		this.patterns.set(id, fullPattern);
		return fullPattern;
	}

	/**
	 * Record a command sequence for pattern learning
	 */
	recordSequence(sequence: CommandSequence): void {
		this.recentSequences.push(sequence);

		// Maintain bounded history
		if (this.recentSequences.length > this.maxHistorySize) {
			this.recentSequences = this.recentSequences.slice(-this.maxHistorySize / 2);
		}
	}

	/**
	 * Match a command sequence against known patterns
	 */
	matchSequence(
		commands: string[],
		context: { directory: string; tool: string },
	): PatternMatch | null {
		let bestMatch: PatternMatch | null = null;

		for (const pattern of this.patterns.values()) {
			const confidence = this.calculateMatchConfidence(pattern, commands, context);
			if (confidence > 0.7 && (!bestMatch || confidence > bestMatch.confidence)) {
				bestMatch = {
					pattern,
					confidence,
					matches: pattern.frequency,
				};
			}
		}

		return bestMatch;
	}

	/**
	 * Detect if current behavior matches user's typical patterns
	 */
	detectDeviation(
		recentCommands: string[],
		context: { directory: string; tool: string; hour: number },
		history: { commands: string[]; directory: string; tool: string; hour: number }[],
	): AnomalyResult | null {
		if (history.length < 5) {
			// Not enough history to detect deviation
			return null;
		}

		// Check if this exact sequence has been seen before
		const seenBefore = history.some(
			(h) =>
				this.similarity(h.commands.join(" "), recentCommands.join(" ")) > 0.8 &&
				h.directory === context.directory,
		);

		if (seenBefore) {
			return null;
		}

		// Calculate how "typical" this behavior is
		const dirTypicality = this.calculateDirectoryTypicality(context.directory, history);
		const toolTypicality = this.calculateToolTypicality(context.tool, history);
		const hourTypicality = this.calculateHourTypicality(context.hour, history);

		const atypicalityScore = 1 - (dirTypicality + toolTypicality + hourTypicality) / 3;

		if (atypicalityScore < 0.5) {
			return null;
		}

		// Check for suspicious patterns
		const isSuspicious = this.isSuspiciousPattern(recentCommands);
		const score = isSuspicious ? 0.75 : 0.4 + atypicalityScore * 0.3;

		return {
			score: Math.min(score, 1.0),
			type: "command_pattern_change",
			confidence: atypicalityScore,
			severity: score > 0.7 ? "high" : "medium",
			details: {
				expected: 1,
				actual: 0,
				deviation: atypicalityScore * 3,
				context: {
					dirTypicality,
					toolTypicality,
					hourTypicality,
					isSuspicious,
					commands: recentCommands,
				},
			},
		};
	}

	/**
	 * Build behavior fingerprint from history
	 */
	buildFingerprint(
		history: {
			commands: string[];
			directory: string;
			tool: string;
			hour: number;
			timestamp: number;
		}[],
	): BehaviorFingerprint {
		// Hourly distribution
		const hourlyDistribution = new Array(24).fill(0);
		for (const h of history) {
			hourlyDistribution[h.hour ?? 0]++;
		}

		// Normalize
		const total = history.length || 1;
		const normalizedHourly = hourlyDistribution.map((c) => c / total);

		// Directory preferences
		const dirCounts: Record<string, number> = {};
		for (const h of history) {
			dirCounts[h.directory] = (dirCounts[h.directory] || 0) + 1;
		}

		// Tool chain patterns
		const chains = this.extractCommandChains(history.flatMap((h) => h.commands));

		// Sequence entropy (measure of randomness)
		const entropy = this.calculateEntropy(history.map((h) => h.tool));

		return {
			hourlyDistribution: normalizedHourly,
			directoryPreferences: dirCounts,
			toolChainPatterns: chains,
			sequenceEntropy: entropy,
		};
	}

	/**
	 * Compare two fingerprints for similarity
	 */
	compareFingerprints(fp1: BehaviorFingerprint, fp2: BehaviorFingerprint): number {
		// Hourly correlation
		let hourlySim = 0;
		for (let i = 0; i < 24; i++) {
			hourlySim += Math.min(fp1.hourlyDistribution[i] ?? 0, fp2.hourlyDistribution[i] ?? 0);
		}

		// Directory overlap
		const dirs1 = Object.keys(fp1.directoryPreferences);
		const dirs2 = Object.keys(fp2.directoryPreferences);
		const commonDirs = dirs1.filter((d) => dirs2.includes(d));
		const dirSim = commonDirs.length / Math.max(dirs1.length, dirs2.length, 1);

		// Chain overlap
		const chains1 = new Set(fp1.toolChainPatterns);
		const chains2 = new Set(fp2.toolChainPatterns);
		const commonChains = [...chains1].filter((c) => chains2.has(c));
		const chainSim = commonChains.length / Math.max(chains1.size, chains2.size, 1);

		// Weighted average
		return hourlySim * 0.4 + dirSim * 0.3 + chainSim * 0.3;
	}

	/**
	 * Learn patterns from command history
	 */
	learnPatterns(history: { commands: string[]; directory: string; tool: string }[]): Pattern[] {
		const patterns: Pattern[] = [];

		// Find common sequences (length 2-5)
		for (let len = 2; len <= 5; len++) {
			const sequences = this.extractSequences(history, len);
			const frequent = this.findFrequentSequences(sequences, 3); // min 3 occurrences

			for (const seq of frequent) {
				const pattern: Pattern = {
					id: `pattern_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
					name: this.generatePatternName(seq),
					sequence: seq.commands,
					context: {
						directories: [...new Set(seq.contexts.map((c) => c.directory))],
						tools: [...new Set(seq.contexts.map((c) => c.tool))],
						hours: [],
					},
					frequency: seq.count,
					lastSeen: Date.now(),
				};
				this.patterns.set(pattern.id, pattern);
				patterns.push(pattern);
			}
		}

		return patterns;
	}

	private calculateMatchConfidence(
		pattern: Pattern,
		commands: string[],
		context: { directory: string; tool: string },
	): number {
		if (pattern.sequence.length !== commands.length) {
			return 0;
		}

		let matches = 0;
		let totalWeight = 0;

		for (let i = 0; i < pattern.sequence.length; i++) {
			const patternCmd = pattern.sequence[i] ?? "";
			const actualCmd = commands[i] ?? "";
			const weight = 1 + i * 0.1; // Later commands matter more

			if (this.matchesPattern(patternCmd, actualCmd)) {
				matches += weight;
			}
			totalWeight += weight;
		}

		const sequenceScore = matches / totalWeight;

		// Context bonus
		const dirMatch = pattern.context.directories.includes(context.directory) ? 0.1 : 0;
		const toolMatch = pattern.context.tools.includes(context.tool) ? 0.1 : 0;

		return Math.min(sequenceScore + dirMatch + toolMatch, 1.0);
	}

	private matchesPattern(pattern: string, actual: string): boolean {
		// Direct match
		if (pattern === actual) return true;

		// Wildcard patterns
		if (pattern === WILDCARD_PATTERNS.FILE_OP) {
			return /^(read|write|edit|delete|cat|less|more|head|tail|touch|rm|cp|mv)/i.test(actual);
		}
		if (pattern === WILDCARD_PATTERNS.GIT_OP) {
			return /^git\s/.test(actual);
		}
		if (pattern === WILDCARD_PATTERNS.BUILD_OP) {
			return /^(npm|yarn|pnpm|make|cargo|go|gradle|maven)/i.test(actual);
		}
		if (pattern === WILDCARD_PATTERNS.SHELL_OP) {
			return /^(bash|sh|zsh|fish|powershell)/i.test(actual);
		}
		if (pattern === WILDCARD_PATTERNS.NET_OP) {
			return /^(curl|wget|ssh|scp|ftp|sftp)/i.test(actual);
		}

		// Substring match (for partial patterns)
		if (pattern.includes("*")) {
			const regex = new RegExp(pattern.replace(/\*/g, ".*"), "i");
			return regex.test(actual);
		}

		return false;
	}

	private calculateDirectoryTypicality(
		directory: string,
		history: { directory: string }[],
	): number {
		if (history.length === 0) return 0.5;

		const dirCounts: Record<string, number> = {};
		for (const h of history) {
			dirCounts[h.directory] = (dirCounts[h.directory] || 0) + 1;
		}

		const total = history.length;
		return (dirCounts[directory] || 0) / total;
	}

	private calculateToolTypicality(tool: string, history: { tool: string }[]): number {
		if (history.length === 0) return 0.5;

		const toolCounts: Record<string, number> = {};
		for (const h of history) {
			toolCounts[h.tool] = (toolCounts[h.tool] || 0) + 1;
		}

		const total = history.length;
		return (toolCounts[tool] || 0) / total;
	}

	private calculateHourTypicality(hour: number, history: { hour: number }[]): number {
		if (history.length === 0) return 0.5;

		const hourCounts = new Array(24).fill(0);
		for (const h of history) {
			hourCounts[h.hour]++;
		}

		const total = history.length;
		return hourCounts[hour] / total;
	}

	private isSuspiciousPattern(commands: string[]): boolean {
		const commandStr = commands.join(" ");

		const suspiciousPatterns = [
			/\|\s*(bash|sh|zsh)/i,
			/curl.*\|/i,
			/wget.*\|/i,
			/>\s*\/etc/i,
			/chmod\s+\+x/i,
			/(sudo|doas)\s+/i,
			/(nc|netcat|ncat)\s+-l/i,
			/python.*-c/i,
			/perl.*-e/i,
		];

		return suspiciousPatterns.some((p) => p.test(commandStr));
	}

	private similarity(a: string, b: string): number {
		if (a === b) return 1;
		const longer = a.length > b.length ? a : b;
		const shorter = a.length > b.length ? b : a;
		if (longer.length === 0) return 1;
		const distance = this.levenshteinDistance(longer, shorter);
		return (longer.length - distance) / longer.length;
	}

	private levenshteinDistance(a: string, b: string): number {
		const matrix: number[][] = [];

		for (let i = 0; i <= b.length; i++) {
			matrix[i] = [i];
		}

		for (let j = 0; j <= a.length; j++) {
			matrix[0] = matrix[0] ?? [];
			matrix[0][j] = j;
		}

		for (let i = 1; i <= b.length; i++) {
			const currentRow = matrix[i] ?? (matrix[i] = []);
			for (let j = 1; j <= a.length; j++) {
				const prevRow = matrix[i - 1] ?? [];
				if (b.charAt(i - 1) === a.charAt(j - 1)) {
					const val = prevRow[j - 1];
					currentRow[j] = val ?? 0;
				} else {
					const prevDiagonal = prevRow[j - 1] ?? 0;
					const prevLeft = currentRow[j - 1] ?? 0;
					const prevUp = prevRow[j] ?? 0;
					currentRow[j] = Math.min(prevDiagonal + 1, Math.min(prevLeft + 1, prevUp + 1));
				}
			}
		}

		return matrix[b.length]?.[a.length] ?? 0;
	}

	private extractCommandChains(commands: string[]): string[] {
		const chains: string[] = [];
		const chainPatterns = [
			{ regex: /git\s+(add|commit|push)/gi, name: "git-workflow" },
			{ regex: /npm\s+(install|ci|run)/gi, name: "npm-workflow" },
			{ regex: /docker\s+(build|run|compose)/gi, name: "docker-workflow" },
			{ regex: /make\s+(build|test|install)/gi, name: "make-workflow" },
		];

		for (const { regex, name } of chainPatterns) {
			const matches = commands.filter((c) => regex.test(c));
			if (matches.length >= 2) {
				chains.push(name);
			}
		}

		return [...new Set(chains)];
	}

	private calculateEntropy(items: string[]): number {
		if (items.length === 0) return 0;

		const counts: Record<string, number> = {};
		for (const item of items) {
			counts[item] = (counts[item] || 0) + 1;
		}

		const probabilities = Object.values(counts).map((c) => c / items.length);
		return -probabilities.reduce((sum, p) => sum + p * Math.log2(p || 1), 0);
	}

	private extractSequences(
		history: { commands: string[]; directory: string; tool: string }[],
		len: number,
	): Array<{
		commands: string[];
		contexts: Array<{ directory: string; tool: string }>;
		count: number;
	}> {
		const sequences = new Map<
			string,
			{ commands: string[]; contexts: Array<{ directory: string; tool: string }>; count: number }
		>();

		for (const h of history) {
			if (h.commands.length < len) continue;

			for (let i = 0; i <= h.commands.length - len; i++) {
				const seq = h.commands.slice(i, i + len);
				const key = seq.join(" | ");

				const existing = sequences.get(key);
				if (existing) {
					existing.count++;
					existing.contexts.push({ directory: h.directory, tool: h.tool });
				} else {
					sequences.set(key, {
						commands: seq,
						contexts: [{ directory: h.directory, tool: h.tool }],
						count: 1,
					});
				}
			}
		}

		return Array.from(sequences.values());
	}

	private findFrequentSequences(
		sequences: Array<{
			commands: string[];
			contexts: Array<{ directory: string; tool: string }>;
			count: number;
		}>,
		minCount: number,
	): Array<{
		commands: string[];
		contexts: Array<{ directory: string; tool: string }>;
		count: number;
	}> {
		return sequences.filter((s) => s.count >= minCount).sort((a, b) => b.count - a.count);
	}

	private generatePatternName(seq: { commands: string[] }): string {
		if (seq.commands.length === 0) return "empty";

		const firstCmdParts = seq.commands[0]?.split(" ") ?? [];
		const firstCmd = firstCmdParts[0] ?? "";
		if (seq.commands.length === 1) {
			return `${firstCmd}-single`;
		}

		const lastCmdParts = seq.commands[seq.commands.length - 1]?.split(" ") ?? [];
		const lastCmd = lastCmdParts[0] ?? "";
		return `${firstCmd}-to-${lastCmd}-sequence`;
	}
}

export function createPatternMatcher(): PatternMatcher {
	return new PatternMatcher();
}
