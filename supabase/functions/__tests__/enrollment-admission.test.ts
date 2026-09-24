import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const source = (path: string) => readFileSync(join(root, path), "utf8");
const triggerMigration = source("supabase/migrations/20260923000028_enrollment_admission.sql");
const admissionMigration = source("supabase/migrations/20260923000034_tenant_ga_admission.sql");

describe("enrollment admission boundary", () => {
	it("requires tenant admission and positive seat capacity for every new credential or agent", () => {
		expect(admissionMigration).toContain("create or replace function public.tenant_admission_capacity");
		expect(admissionMigration).toContain("if v_mode = 'pilot' then");
		expect(admissionMigration).toContain("public.tenant_admissions");
		expect(admissionMigration).toContain("public.effective_tenant_seats(p_tenant_id)");
		expect(admissionMigration).toContain("public.tenant_admission_capacity(new.tenant_id)");
		for (const table of ["api_keys", "enrollment_tokens", "agents"]) {
			expect(triggerMigration).toContain(`on public.${table}`);
		}
		expect(triggerMigration).toMatch(/before insert or update of key_hash on public\.api_keys/);
		expect(triggerMigration).toMatch(/before insert or update of token_hash on public\.enrollment_tokens/);
		expect(triggerMigration).toMatch(/before insert on public\.agents/);
	});

	it("reports admission denial as forbidden on credential and exchange routes", () => {
		for (const route of ["api-keys", "enrollment-tokens", "enroll", "ingest"]) {
			const edge = source(`supabase/functions/${route}/index.ts`);
			expect(edge).toContain('"42501"');
			expect(edge).toContain('error: "tenant_not_admitted"');
		}
	});
});
