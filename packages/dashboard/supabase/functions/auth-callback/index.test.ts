import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "index.ts"), "utf8");

describe("auth callback security contract", () => {
  it("does not expose service-role credentials or admin session APIs", () => {
    expect(source).not.toContain("SUPABASE_SERVICE_ROLE_KEY");
    expect(source).not.toContain("auth.admin");
    expect(source).toContain("signInWithIdToken");
  });

  it("requires exact origins and signed tenant-bound state", () => {
    expect(source).toContain('"AUTH_CALLBACK_ALLOWED_ORIGINS"');
    expect(source).toContain('"AUTH_CALLBACK_STATE_SECRET"');
    expect(source).toContain("crypto.subtle.verify");
    expect(source).toContain('error: "tenant_not_allowed"');
    expect(source).not.toContain('Access-Control-Allow-Origin": "*"');
  });

  it("fails closed for auth and session failures", () => {
    expect(source).toContain('error: "authorization_failed"');
    expect(source).toContain('return json(401,');
    expect(source).toContain('return json(500,');
    const tenantGuard = source.indexOf("if (membershipError || !membership || membership.tenant_id !== state.tenantId)");
    const successResponse = source.indexOf("return json(200, {");
    expect(tenantGuard).toBeGreaterThanOrEqual(0);
    expect(successResponse).toBeGreaterThan(tenantGuard);
  });
});
