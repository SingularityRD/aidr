// Real-Docker drill for the pgsodium/Vault root key in cold backups. Opt-in:
//   AIDR_BACKUP_DOCKER_DRILL=1 node --test scripts/deployment-backup-vault-key-docker.test.mjs
// It runs the shipped backup tool against a minimal Compose project on the pinned
// supabase/postgres image: create a Vault secret, back up, verify, recover into a
// new project and volumes, then read vault.decrypted_secrets. A backup with the
// key record stripped (an older backup) is recovered too and must report
// VAULT_KEY_MISSING and fail to decrypt. Every project, volume and directory the
// drill creates is removed afterwards. Optional: AIDR_BACKUP_DOCKER_DRILL_IMAGE
// (default supabase/postgres:17.11.0.004, which must already be loaded locally),
// AIDR_BACKUP_DOCKER_DRILL_HELPER_BASE and AIDR_BACKUP_DOCKER_DRILL_EVIDENCE (a
// JSON summary path).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, createHmac, hkdfSync, randomBytes } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

const SCRIPT = resolve("scripts/deployment-backup.mjs");
const IMAGE = process.env.AIDR_BACKUP_DOCKER_DRILL_IMAGE ?? "supabase/postgres:17.11.0.004";
const SIDE_IMAGE = process.env.AIDR_BACKUP_DOCKER_DRILL_HELPER_BASE ?? "node:24.21.0-alpine3.24";
const enabled = process.env.AIDR_BACKUP_DOCKER_DRILL === "1" && process.platform !== "win32";
const SECRET = `aidr-drill-${randomBytes(12).toString("hex")}`;

function run(exe, args, options = {}) {
	const result = spawnSync(exe, args, { encoding: "utf8", timeout: 600000, maxBuffer: 16 * 1024 * 1024, ...options });
	if (result.status !== 0 && !options.allowFailure) throw new Error(`${exe} ${args.slice(0, 6).join(" ")} failed (exit ${result.status}): ${result.stderr}`);
	return result;
}
const compose = (directory, project, ...args) => run("docker", ["compose", "--project-directory", directory, "-f", join(directory, "compose.yml"), "--project-name", project, ...args]);
const psql = (directory, project, sql, options) => run("docker", ["compose", "--project-directory", directory, "-f", join(directory, "compose.yml"), "--project-name", project, "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-tAc", sql], options);
function keyFileFacts(directory, project) {
	const container = compose(directory, project, "ps", "--all", "--quiet", "db").stdout.trim();
	const volume = JSON.parse(run("docker", ["inspect", container]).stdout)[0].Mounts.find((mount) => mount.Destination === "/etc/postgresql-custom").Name;
	const out = run("docker", ["run", "--rm", "--network", "none", "--mount", `type=volume,src=${volume},dst=/c,readonly`, SIDE_IMAGE, "sh", "-c", "stat -c '%u:%g:%a' /c/pgsodium_root.key; sha256sum /c/pgsodium_root.key; ls /c"]).stdout.trim().split("\n");
	return { owner_mode: out[0], sha256: out[1].split(/\s+/)[0], config_entries: out.slice(2).sort() };
}

function deploymentFixture(root, project) {
	const deployment = join(root, "deployment");
	for (const directory of ["auth-templates", "backup", "dashboard", "health", "ingress", "maintenance", "migrations", "volumes/functions"]) mkdirSync(join(deployment, directory), { recursive: true });
	const files = {
		".env": `POSTGRES_PASSWORD=${randomBytes(16).toString("hex")}\n`,
		".env.functions": "AIDR_FIXTURE=true\n",
		".env.ingress": "AIDR_INGRESS_FIXTURE=true\n",
		".env.readiness": "AIDR_HEALTH_STATE_DIR=/srv/aidr/health\n",
		"agent-config.json": "{}\n",
		// The upstream kit's db service keeps pgsodium_root.key on the db-config
		// named volume; this mirrors only the mounts the backup tool relies on.
		"compose.yml": `services:
  db:
    image: ${IMAGE}
    pull_policy: never
    network_mode: none
    environment:
      POSTGRES_PASSWORD: \${POSTGRES_PASSWORD}
    volumes:
      - aidr-db:/var/lib/postgresql/data
      - db-config:/etc/postgresql-custom
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "postgres", "-h", "localhost"]
      interval: 2s
      timeout: 5s
      retries: 60
  storage:
    image: ${SIDE_IMAGE}
    pull_policy: never
    network_mode: none
    init: true
    command: ["sh", "-c", "echo object > /var/lib/storage/object.txt; exec sleep infinity"]
    volumes:
      - aidr-storage:/var/lib/storage
volumes:
  aidr-db: {}
  aidr-storage: {}
  db-config: {}
`,
		"auth-templates/recovery.html": "safe\n",
		"backup/timer.service": "safe\n",
		"dashboard/index.html": "safe\n",
		"ingress/proxy.conf": "safe\n",
		"maintenance/readiness.service": "safe\n",
		"migrations/20260922000000_fixture.sql": "select 1;\n",
		"volumes/functions/index.ts": "safe\n",
	};
	for (const [name, content] of Object.entries(files)) writeFileSync(join(deployment, name), content);
	const sha256 = (name) => createHash("sha256").update(files[name]).digest("hex");
	writeFileSync(join(deployment, "deployment.json"), JSON.stringify({
		schema_version: 1, mode: "self-hosted", project_name: project, source_commit: "d".repeat(40), source_has_changes: false,
		migrations: [{ name: "20260922000000_fixture.sql", sha256: sha256("migrations/20260922000000_fixture.sql") }],
		artifacts: ["auth-templates/recovery.html", "backup/timer.service", "dashboard/index.html", "ingress/proxy.conf", "maintenance/readiness.service", "volumes/functions/index.ts"].map((path) => ({ path, sha256: sha256(path) })),
	}));
	return deployment;
}

test("a recovered project decrypts Vault secrets written before the backup", { skip: !enabled && "set AIDR_BACKUP_DOCKER_DRILL=1 to run the Docker drill", timeout: 900000 }, async (t) => {
	const root = mkdtempSync(join(tmpdir(), "aidr-vault-key-drill-"));
	const suffix = randomBytes(6).toString("hex");
	const source = `aidr-vault-drill-${suffix}`;
	const projects = [[join(root, "deployment"), source]];
	t.after(() => {
		for (const [directory, project] of projects) run("docker", ["compose", "--project-directory", directory, "-f", join(directory, "compose.yml"), "--project-name", project, "down", "--volumes", "--remove-orphans", "--timeout", "5"], { allowFailure: true });
		rmSync(root, { recursive: true, force: true });
	});
	const evidence = { scope: "Local same-host engineering drill of scripts/deployment-backup.mjs with a disposable recovery key, Compose project and volumes, all deleted afterwards. Not production or offsite acceptance.", command: "AIDR_BACKUP_DOCKER_DRILL=1 node --test scripts/deployment-backup-vault-key-docker.test.mjs", image: IMAGE, image_id: run("docker", ["image", "inspect", "--format", "{{.Id}}", IMAGE]).stdout.trim(), started_at: new Date().toISOString() };
	const deployment = deploymentFixture(root, source);
	const runtime = join(root, "reviewed-runtime");
	cpSync(deployment, runtime, { recursive: true });
	for (const directory of ["custody", "state", "backups"]) mkdirSync(join(root, directory), { mode: 0o700 });
	const key = join(root, "custody", "recovery.key");
	run(process.execPath, [SCRIPT, "keygen", "--key-file", key]);

	compose(deployment, source, "up", "-d", "--wait", "db", "storage");
	psql(deployment, source, `select vault.create_secret('${SECRET}', 'aidr_drill', 'backup drill')`);
	evidence.source_key = keyFileFacts(deployment, source);

	const backup = join(root, "backups", "b1");
	const backed = run(process.execPath, [SCRIPT, "backup", "--deployment", deployment, "--output", backup, "--key-file", key, "--recovery-journal", join(root, "state", "journal.json"), "--maintenance"]);
	assert.match(backed.stdout, /pgsodium\/Vault root key are authenticated/);
	const backupJson = readFileSync(join(backup, "backup.json"), "utf8");
	const record = JSON.parse(JSON.parse(backupJson).payload).pgsodium_root_key;
	assert.equal(record.status, "captured");
	assert.equal(record.sha256, evidence.source_key.sha256, "the manifest hash must match the source volume's key file");
	const plaintextKey = run("docker", ["compose", "--project-directory", deployment, "-f", join(deployment, "compose.yml"), "--project-name", source, "exec", "-T", "db", "cat", "/etc/postgresql-custom/pgsodium_root.key"]).stdout;
	assert.ok(!backupJson.includes(plaintextKey.trim()), "plaintext key must not appear in the manifest");
	const verified = run(process.execPath, [SCRIPT, "verify", "--backup", backup, "--key-file", key]);
	assert.match(verified.stdout, new RegExp(`captured and authenticated \\(sha256 ${record.sha256}\\)`));
	evidence.manifest_key_record = { status: record.status, sha256: record.sha256, bytes: record.bytes };

	const recover = (from, label) => {
		const project = `aidr-recovery-${randomBytes(8).toString("hex")}`;
		const output = join(root, label);
		projects.push([output, project]);
		const result = run(process.execPath, [SCRIPT, "recover", "--backup", from, "--output", output, "--key-file", key, "--runtime", runtime, "--project", project]);
		const receipt = JSON.parse(readFileSync(join(output, "recovery-receipt.json"), "utf8"));
		assert.equal(receipt.services_started, false);
		return { output, project, result, receipt };
	};

	const recovered = recover(backup, "recovered");
	assert.equal(recovered.receipt.vault_root_key, "restored");
	assert.equal(recovered.receipt.vault_root_key_sha256, record.sha256);
	const restoredKey = keyFileFacts(recovered.output, recovered.project);
	assert.equal(restoredKey.sha256, evidence.source_key.sha256);
	assert.match(restoredKey.owner_mode, /^[1-9]\d*:[1-9]\d*:600$/);
	assert.deepEqual(restoredKey.config_entries, evidence.source_key.config_entries, "the image's default configuration must still be present beside the key");
	compose(recovered.output, recovered.project, "up", "-d", "--wait", "db");
	assert.equal(psql(recovered.output, recovered.project, "select decrypted_secret from vault.decrypted_secrets where name = 'aidr_drill'").stdout.trim(), SECRET);
	evidence.recovered = { vault_root_key: recovered.receipt.vault_root_key, key_file: restoredKey, decrypted_secret_matches: true };

	// Strip the key record to reproduce a backup made by the previous tool version.
	const legacy = join(root, "backups", "legacy");
	cpSync(backup, legacy, { recursive: true });
	const manifest = JSON.parse(JSON.parse(backupJson).payload);
	delete manifest.pgsodium_root_key;
	const payload = JSON.stringify(manifest);
	const macKey = Buffer.from(hkdfSync("sha256", Buffer.from(readFileSync(key, "utf8").trim(), "hex"), "aidr-backup-v1", "manifest", 32));
	writeFileSync(join(legacy, "backup.json"), JSON.stringify({ payload, hmac_sha256: createHmac("sha256", macKey).update(payload).digest("hex") }));
	const old = recover(legacy, "recovered-legacy");
	assert.equal(old.receipt.vault_root_key, "VAULT_KEY_MISSING");
	assert.match(old.result.stderr, /^VAULT_KEY_MISSING: /m);
	compose(old.output, old.project, "up", "-d", "--wait", "db");
	const failed = psql(old.output, old.project, "select decrypted_secret from vault.decrypted_secrets where name = 'aidr_drill'", { allowFailure: true });
	assert.notEqual(failed.status, 0);
	assert.match(failed.stderr, /invalid ciphertext/);
	assert.notEqual(keyFileFacts(old.output, old.project).sha256, evidence.source_key.sha256, "without the record the image generates a new key");
	evidence.legacy = { vault_root_key: old.receipt.vault_root_key, decrypt_error: "invalid ciphertext" };
	evidence.finished_at = new Date().toISOString();
	if (process.env.AIDR_BACKUP_DOCKER_DRILL_EVIDENCE) writeFileSync(process.env.AIDR_BACKUP_DOCKER_DRILL_EVIDENCE, `${JSON.stringify(evidence, null, 2)}\n`);
	t.diagnostic(JSON.stringify(evidence));
});
