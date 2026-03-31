import { initSentry as coreInitSentry } from "@singularityrd/aidr-core";
export function initSentry(): void {
	coreInitSentry({ name: "aidr-sdk" });
}
