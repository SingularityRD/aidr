import { describe, expect, it } from "vitest";
import { createIntelReputationProvider } from "../intel/provider.js";
import type { IntelMerged } from "../intel/types.js";
import { emptyIntelMerged } from "../intel/types.js";

describe("intel reputation provider", () => {
	it("URL allowlist overrides denylist and domain risk", () => {
		const merged: IntelMerged = emptyIntelMerged();
		merged.urlAllowHosts.add("good.example");
		merged.urlDenyHosts.add("good.example");
		merged.domainRisk.set("good.example", {
			domain: "good.example",
			action: "deny",
			severity: "high",
			confidence: 0.99,
		});

		const p = createIntelReputationProvider(merged);
		const r = p.checkUrl("https://good.example/path");
		expect(r.verdict).toBe("allow");
	});

	it("Domain risk matches subdomains", () => {
		const merged: IntelMerged = emptyIntelMerged();
		merged.domainRisk.set("risk.example", {
			domain: "risk.example",
			action: "deny",
			severity: "high",
			confidence: 0.93,
		});

		const p = createIntelReputationProvider(merged);
		const r = p.checkUrl("https://a.b.risk.example/");
		expect(r.verdict).toBe("deny");
		expect(r.severity).toBe("high");
	});

	it("Package name/hash denylists return deny", () => {
		const merged: IntelMerged = emptyIntelMerged();
		merged.packageNameDeny.add("leftpad");
		merged.packageHashDeny.add("deadbeef".padEnd(64, "0"));

		const p = createIntelReputationProvider(merged);
		expect(p.checkPackageName("leftpad").verdict).toBe("deny");
		expect(p.checkPackageHashSha256("deadbeef".padEnd(64, "0")).verdict).toBe("deny");
	});
});
