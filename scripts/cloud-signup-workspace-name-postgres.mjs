// Run only against a disposable migrated Supabase PostgreSQL container.
// Every inserted user/team and the function replacement roll back.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const container = process.env.AIDR_POSTGRES_DOCKER_CONTAINER;
assert.ok(container, "AIDR_POSTGRES_DOCKER_CONTAINER must name a disposable PostgreSQL container");
assert.match(container, /^[A-Za-z0-9_.-]+$/, "invalid Docker container name");
const dockerDesktop = process.env.LOCALAPPDATA
	? resolve(process.env.LOCALAPPDATA, "Programs/DockerDesktop/resources/bin/docker.exe")
	: null;
const docker = process.env.AIDR_DOCKER_BIN ?? (dockerDesktop && existsSync(dockerDesktop) ? dockerDesktop : "docker");
const dbUser = process.env.AIDR_POSTGRES_DB_USER ?? "postgres";
assert.match(dbUser, /^[A-Za-z_][A-Za-z0-9_]*$/, "invalid PostgreSQL role");
const migration = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../supabase/migrations/20260923000042_cloud_signup_workspace_name.sql"), "utf8");
const cloudId = randomUUID();
const nonCloudId = randomUUID();
const invalidId = randomUUID();
const invalidControlId = randomUUID();

const user = (id, metadata) => `insert into auth.users(id,email,aud,role,instance_id,raw_app_meta_data,raw_user_meta_data)
values ('${id}','workspace-${id}@example.invalid','authenticated','authenticated',
  '00000000-0000-0000-0000-000000000000','{}'::jsonb,'${metadata}'::jsonb);`;

const sql = `begin;
${migration}
update app.tenant_admission_config set mode='cloud' where singleton;
${user(cloudId, '{"full_name":"Alice","workspace_name":"  Acme Security  "}')}
do $$
declare team_name text;
begin
  select t.name into team_name from public.team_members m join public.teams t on t.id=m.team_id
  where m.user_id='${cloudId}' limit 1;
  if team_name is distinct from 'Acme Security' then
    raise exception 'cloud workspace name mismatch: %', team_name;
  end if;
end $$;
do $$
begin
  begin
    ${user(invalidId, '{"workspace_name":"   "}')}
    raise exception 'invalid workspace name was accepted';
  exception when sqlstate '22023' then null;
  end;
end $$;
do $$
begin
  begin
    ${user(invalidControlId, JSON.stringify({ workspace_name: "Acme\u007fSecurity" }))}
    raise exception 'control character in workspace name was accepted';
  exception when sqlstate '22023' then null;
  end;
end $$;
update app.tenant_admission_config set mode='onprem' where singleton;
${user(nonCloudId, '{"full_name":"Alice","workspace_name":"Not Used"}')}
do $$
declare team_name text;
begin
  select t.name into team_name from public.team_members m join public.teams t on t.id=m.team_id
  where m.user_id='${nonCloudId}' limit 1;
  if team_name is distinct from 'Alice' then
    raise exception 'non-cloud naming changed: %', team_name;
  end if;
end $$;
rollback;`;

const result = spawnSync(docker, ["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", dbUser, "-d", "postgres"], {
	input: sql,
	encoding: "utf8",
	maxBuffer: 8 * 1024 * 1024,
});
if (result.status !== 0) {
	process.stderr.write(result.stderr || result.stdout || String(result.error));
	process.exitCode = 1;
} else {
	console.log("Cloud signup team naming rollback test passed.");
}
