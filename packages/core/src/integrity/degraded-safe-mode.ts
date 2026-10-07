let degradedSafeMode = false;
let degradedReason: string | undefined;

export function enterDegradedSafeMode(reason: string): void {
	degradedSafeMode = true;
	degradedReason = reason;
}

export function isDegradedSafeMode(): boolean {
	return degradedSafeMode;
}

export function getDegradedSafeModeReason(): string | undefined {
	return degradedReason;
}

/** Test hook: leave degraded safe mode (production code never leaves it). */
export function resetDegradedSafeModeForTests(): void {
	degradedSafeMode = false;
	degradedReason = undefined;
}
