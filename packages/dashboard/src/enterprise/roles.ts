// Tenant roles as the console sees them. Kept out of team-provider so pages
// and their tests can use the helpers without the provider.
//
// Mirrors the database check constraint on public.team_members.role
// (`owner | admin | member | viewer | auditor`). "owner" is not cosmetic: the
// handle_new_user_team trigger makes every new user the owner of their
// personal team. `auditor` is the lateral read-only audit role
// (supabase/migrations/20261016000400_auditor_role.sql): it reads what a
// viewer reads plus both audit trails, reports and compliance evidence, and
// can change nothing. The server re-checks every one of these decisions.
export type TeamRole = "owner" | "admin" | "member" | "viewer" | "auditor";

/** Owners, admins and auditors read and export the audit trails and reports. */
export function isAuditReaderRole(role: string | null | undefined): boolean {
	return role === "owner" || role === "admin" || role === "auditor";
}
