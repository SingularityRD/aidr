// Tenant role vocabulary shared by the Edge functions.
//
// `auditor` is a lateral, read-only role (supabase/migrations/
// 20261016000400_auditor_role.sql). It is never a rung of the
// owner > admin > member > viewer ladder: every write gate in the Edge
// functions and the database is a positive list that does not name it, so an
// auditor fails closed on every write. These helpers are for READ gates only.

/** Roles that may read tenant data the Edge functions expose to members. */
const TENANT_READ_ROLES: ReadonlySet<string> = new Set(["owner", "admin", "member", "viewer", "auditor"]);

/**
 * Roles that may read the audit-reader surfaces: both audit trails and their
 * bulk export, compliance evidence and executive reports.
 */
export const AUDIT_READER_ROLES: ReadonlySet<string> = new Set(["owner", "admin", "auditor"]);

/** Roles an owner or admin may grant through an invitation. Never `owner`. */
const INVITABLE_ROLES = ["admin", "member", "viewer", "auditor"] as const;
export type InvitableRole = (typeof INVITABLE_ROLES)[number];

export function isTenantReadRole(role: unknown): boolean {
	return typeof role === "string" && TENANT_READ_ROLES.has(role);
}

export function isAuditReaderRole(role: unknown): boolean {
	return typeof role === "string" && AUDIT_READER_ROLES.has(role);
}

export function isInvitableRole(role: unknown): role is InvitableRole {
	return typeof role === "string" && (INVITABLE_ROLES as readonly string[]).includes(role);
}
