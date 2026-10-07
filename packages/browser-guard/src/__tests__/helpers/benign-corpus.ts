/**
 * Benign text that Browser Guard's detection engine must leave untouched. Shared by the
 * false-positive guards in detect.test.ts and the labelled-detector corpus check.
 */
export const BENIGN_SNIPPETS: ReadonlyArray<readonly [name: string, text: string]> = [
	["git sha", "fixed in commit 9fceb02d0ae598e95dc970b74767f19372d61af8 yesterday"],
	["short sha", "see a1b2c3d for details"],
	["uuid", "request id 550e8400-e29b-41d4-a716-446655440000 failed"],
	["sha256", "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ok"],
	["unix epoch", "created_at 1727136000 and updated 1727136000123 ms"],
	["epoch ms luhn-valid", "timestamp 1727136000125 recorded"],
	["iso dates", "between 2026-09-24 and 2026-10-01T12:30:00Z the job ran"],
	[
		"prices and orders",
		"Order #100234 total $1,299.99 (qty 3), invoice INV-2026-00042, 1.250,00 TL",
	],
	["semver", "upgrade from v1.2.3 to 2.10.0-beta.1 and node 22.12.0"],
	[
		"base64 blob",
		`data:image/png;base64,${"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==".repeat(4)}`,
	],
	["long hex", `digest ${"ab12".repeat(32)} end`],
];

/** Benign prose and code lines from the engine's performance fixture. */
export const BENIGN_PROSE: readonly string[] = [
	"The deploy at 2026-09-24T10:00:00Z used commit 9fceb02d0ae598e95dc970b74767f19372d61af8 and v2.3.1.",
	"function add(a, b) { return a + b; } // order #100234 total $19.99",
	"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.",
];
