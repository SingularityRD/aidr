declare module "node:sqlite" {
	// Minimal typing surface. This module is optional at runtime and is used behind dynamic import.
	export class DatabaseSync {
		constructor(path: string);
		exec(sql: string): void;
		prepare(sql: string): { run: (...args: unknown[]) => void };
		close(): void;
	}
}
