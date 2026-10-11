// Static and rendered checks for the AIDR Helm chart (node --test).
//
// The static suite always runs. The rendered suite needs a Helm 3 binary: set
// HELM_BIN or put `helm` on PATH. Without one those tests are skipped
// explicitly (reported as "skipped", never as passed).
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { PRIVACY_GATEWAY_LAYOUT } from "../privacy-gateway/privacy-gateway.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const chartDir = join(here, "aidr");
const { parse, parseAllDocuments } = createRequire(join(root, "packages/core/package.json"))("yaml");
const readYaml = (path) => parse(readFileSync(path, "utf8"));
const CI_VALUES = ["default", "prod", "posture-scanner", "privacy-gateway"];
const KUBE_VERSION = "1.30.0";

function findHelm() {
	const candidates = [process.env.HELM_BIN, "helm"].filter(Boolean);
	for (const candidate of candidates) {
		const probe = spawnSync(candidate, ["version", "--short"], { encoding: "utf8" });
		if (probe.status === 0 && /^v3\./.test(probe.stdout.trim())) return candidate;
	}
	return null;
}
const helm = findHelm();
const helmSkip = helm ? false : "Helm 3 not found (set HELM_BIN or add helm to PATH)";

function runHelm(args) {
	return spawnSync(helm, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
}

function render(valuesFiles, setArgs = [], extraArgs = []) {
	const args = ["template", "aidr", chartDir, "--namespace", "aidr", "--kube-version", KUBE_VERSION, ...extraArgs];
	for (const file of valuesFiles) args.push("-f", file);
	for (const entry of setArgs) args.push("--set", entry);
	return runHelm(args);
}

function renderOk(valuesFiles, setArgs = [], extraArgs = []) {
	const result = render(valuesFiles, setArgs, extraArgs);
	assert.equal(result.status, 0, `${setArgs.join(" ")} ${extraArgs.join(" ")}: ${result.stderr}`);
	return parseAllDocuments(result.stdout).map((doc) => doc.toJSON()).filter(Boolean);
}

function renderDocs(valuesName) {
	const result = render([join(chartDir, "ci", `${valuesName}-values.yaml`)]);
	assert.equal(result.status, 0, result.stderr);
	return parseAllDocuments(result.stdout).map((doc) => {
		assert.equal(doc.errors.length, 0, String(doc.errors[0]));
		return doc.toJSON();
	}).filter(Boolean);
}

function podSpecs(docs) {
	return docs.flatMap((doc) => {
		if (["Deployment", "StatefulSet", "Job"].includes(doc.kind)) return [{ doc, spec: doc.spec.template.spec }];
		if (doc.kind === "CronJob") return [{ doc, spec: doc.spec.jobTemplate.spec.template.spec }];
		return [];
	});
}

test("chart metadata pins apiVersion v2 and appVersion to the product version", () => {
	const chart = readYaml(join(chartDir, "Chart.yaml"));
	assert.equal(chart.apiVersion, "v2");
	assert.equal(chart.name, "aidr");
	assert.equal(chart.appVersion, "0.6.0");
	const dashboardPackage = JSON.parse(readFileSync(join(root, "packages/dashboard/package.json"), "utf8"));
	assert.equal(chart.appVersion, dashboardPackage.version);
});

test("default values are secure and generate no credentials", () => {
	const values = readYaml(join(chartDir, "values.yaml"));
	assert.equal(values.secrets.existingSecret, "", "platform Secret must be supplied, never defaulted");
	assert.equal(values.secrets.functionsExistingSecret, "");
	assert.equal(values.publicUrls.dashboard, "");
	assert.equal(values.networkPolicy.enabled, true);
	assert.equal(values.podSecurityContext.runAsNonRoot, true);
	assert.equal(values.podSecurityContext.seccompProfile.type, "RuntimeDefault");
	assert.deepEqual(values.containerSecurityContext.capabilities.drop, ["ALL"]);
	assert.equal(values.containerSecurityContext.allowPrivilegeEscalation, false);
	assert.equal(values.containerSecurityContext.readOnlyRootFilesystem, true);
	assert.equal(values.serviceAccount.automountServiceAccountToken, false);
	assert.equal(values.auth.disableSignup, true);
	assert.equal(values.postureScanner.enabled, false);
	assert.equal(Object.hasOwn(values, "aig"), false, "the pre-rename values key must not return");
	assert.ok(["small", "medium", "large"].includes(values.resourcesPreset));
	const images = [];
	const walk = (node, path) => {
		if (!node || typeof node !== "object") return;
		if ("repository" in node && "tag" in node) images.push({ path, ...node });
		for (const [key, value] of Object.entries(node)) walk(value, `${path}.${key}`);
	};
	walk(values, "values");
	assert.ok(images.length >= 10);
	for (const image of images) assert.notEqual(String(image.tag), "latest", `${image.path} uses latest`);
	const templates = readdirSync(join(chartDir, "templates")).map((name) => readFileSync(join(chartDir, "templates", name), "utf8"));
	assert.ok(!templates.some((text) => /^kind:\s*Secret\s*$/m.test(text)), "the chart must not create Secrets");
	assert.ok(!templates.some((text) => /randAlphaNum|randAscii|genPrivateKey|randBytes/.test(text)), "the chart must not generate credentials");
});

test("values schema and every CI values file parse", () => {
	const schema = JSON.parse(readFileSync(join(chartDir, "values.schema.json"), "utf8"));
	assert.equal(schema.properties.resourcesPreset.enum.join(","), "small,medium,large");
	assert.ok(schema.required.includes("secrets"));
	for (const name of CI_VALUES) {
		const values = readYaml(join(chartDir, "ci", `${name}-values.yaml`));
		assert.match(values.publicUrls.dashboard, /^https:\/\//);
		assert.ok(values.secrets.existingSecret);
	}
});

test("every workload template applies resources and hardened security contexts", () => {
	for (const name of readdirSync(join(chartDir, "templates")).filter((file) => file.endsWith(".yaml"))) {
		const text = readFileSync(join(chartDir, "templates", name), "utf8");
		const containers = (text.match(/^\s+- name: [a-z-]+\n\s+image: /gm) ?? []).length;
		if (containers === 0) continue;
		const resourceBlocks = (text.match(/include "aidr\.resources"/g) ?? []).length + (text.match(/^\s+resources:\n\s+requests:\n\s+cpu: /gm) ?? []).length;
		assert.equal(resourceBlocks, containers, `${name}: resources per container`);
		assert.equal((text.match(/include "aidr\.containerSecurityContext"/g) ?? []).length, containers, `${name}: container securityContext`);
		assert.ok((text.match(/include "aidr\.podSecurityContext"/g) ?? []).length >= 1, `${name}: pod securityContext`);
	}
});

test("helm lint passes for every CI values file", { skip: helmSkip }, () => {
	for (const name of CI_VALUES) {
		const result = runHelm(["lint", chartDir, "--strict", "--kube-version", KUBE_VERSION, "-f", join(chartDir, "ci", `${name}-values.yaml`)]);
		assert.equal(result.status, 0, `${name}: ${result.stdout}${result.stderr}`);
	}
});

for (const name of CI_VALUES) {
	test(`rendered ${name} manifests are hardened, pinned and network-isolated`, { skip: helmSkip }, () => {
		const docs = renderDocs(name);
		const workloads = podSpecs(docs);
		assert.ok(workloads.length >= 6, "expected the full stack");
		for (const { doc, spec } of workloads) {
			const where = `${doc.kind}/${doc.metadata.name}`;
			assert.equal(spec.automountServiceAccountToken, false, `${where}: service account token`);
			assert.equal(spec.securityContext?.runAsNonRoot, true, `${where}: runAsNonRoot`);
			assert.ok(Number.isInteger(spec.securityContext?.runAsUser) && spec.securityContext.runAsUser > 0, `${where}: numeric non-root uid`);
			assert.equal(spec.securityContext?.seccompProfile?.type, "RuntimeDefault", `${where}: seccomp`);
			for (const container of [...(spec.initContainers ?? []), ...spec.containers]) {
				const at = `${where}/${container.name}`;
				for (const kind of ["requests", "limits"]) {
					assert.ok(container.resources?.[kind]?.cpu, `${at}: ${kind}.cpu`);
					assert.ok(container.resources?.[kind]?.memory, `${at}: ${kind}.memory`);
				}
				assert.equal(container.securityContext?.allowPrivilegeEscalation, false, `${at}: privilege escalation`);
				assert.equal(container.securityContext?.runAsNonRoot, true, `${at}: runAsNonRoot`);
				assert.deepEqual(container.securityContext?.capabilities?.drop, ["ALL"], `${at}: capabilities`);
				assert.ok(!container.securityContext?.privileged, `${at}: privileged`);
				assert.match(container.image, /^[a-z0-9.-]+(:[0-9]+)?\/[^:@\s]+:[A-Za-z0-9_][A-Za-z0-9_.-]*(@sha256:[a-f0-9]{64})?$/, `${at}: registry/repository:tag`);
				assert.doesNotMatch(container.image, /:latest(@|$)/, `${at}: latest tag`);
				for (const probe of [container.command, container.args, container.readinessProbe?.exec?.command, container.livenessProbe?.exec?.command, container.startupProbe?.exec?.command]) {
					for (const part of probe ?? []) assert.equal(typeof part, "string", `${at}: command/probe arguments must be strings`);
				}
				for (const entry of container.env ?? []) {
					assert.equal(typeof (entry.value ?? ""), "string", `${at}: ${entry.name} value must be a string`);
					if (!/(PASSWORD|_PASS$|_SECRET$|SECRET_KEY|_KEY$|_TOKEN$|POSTGRES_DSN$)/.test(entry.name)) continue;
					assert.ok(entry.valueFrom?.secretKeyRef || entry.value?.startsWith("$("), `${at}: ${entry.name} must come from a Secret`);
				}
			}
		}
		const roFalse = workloads.flatMap(({ doc, spec }) => spec.containers.filter((container) => container.securityContext.readOnlyRootFilesystem !== true).map(() => doc.metadata.name));
		assert.deepEqual([...new Set(roFalse)].filter((entry) => !entry.endsWith("-db")), [], "only Postgres may keep a writable root filesystem");

		assert.ok(!docs.some((doc) => doc.kind === "Secret"), "the chart must not render Secrets");
		const policies = docs.filter((doc) => doc.kind === "NetworkPolicy");
		const defaultDeny = policies.find((doc) => doc.metadata.name.endsWith("-default-deny"));
		assert.ok(defaultDeny, "default-deny NetworkPolicy");
		assert.deepEqual(defaultDeny.spec.policyTypes, ["Ingress", "Egress"]);
		assert.equal(defaultDeny.spec.ingress, undefined);
		assert.equal(defaultDeny.spec.egress, undefined);
		const selected = new Set(policies.filter((doc) => doc.spec.podSelector?.matchLabels?.["app.kubernetes.io/component"]).map((doc) => doc.spec.podSelector.matchLabels["app.kubernetes.io/component"]));
		for (const { doc } of workloads) {
			const component = doc.metadata.labels["app.kubernetes.io/component"];
			if (["migrations", "backup"].includes(component)) continue;
			assert.ok(selected.has(component), `NetworkPolicy allow-list for ${component}`);
		}

		const ingress = docs.find((doc) => doc.kind === "Ingress");
		assert.ok(ingress?.spec.tls?.[0]?.secretName, "Ingress terminates TLS");
		const job = docs.find((doc) => doc.kind === "Job");
		assert.match(job.metadata.annotations["helm.sh/hook"], /pre-upgrade/);
		const gateway = docs.find((doc) => doc.kind === "ConfigMap" && doc.metadata.name.endsWith("-api-gw"));
		for (const file of ["envoy.yaml", "cds.yaml", "lds.template.yaml"]) assert.ok(parse(gateway.data[file]), `${file} parses`);
		assert.doesNotMatch(JSON.stringify(gateway.data), /eyJ[A-Za-z0-9_-]{10,}/, "API keys never land in the ConfigMap");
		assert.match(gateway.data["lds.template.yaml"], /exact: "https:\/\/aidr\.example\.com"/, "CORS pinned to the dashboard origin");
	});
}

test("rendered production values use the external database and backups", { skip: helmSkip }, () => {
	const docs = renderDocs("prod");
	assert.ok(!docs.some((doc) => doc.kind === "StatefulSet"), "no in-cluster Postgres");
	assert.ok(docs.some((doc) => doc.kind === "CronJob" && doc.metadata.name.endsWith("-backup")));
	assert.equal(docs.filter((doc) => doc.kind === "HorizontalPodAutoscaler").length, 2);
	const auth = docs.find((doc) => doc.kind === "Deployment" && doc.metadata.name.endsWith("-auth"));
	const dbUrl = auth.spec.template.spec.containers[0].env.find((entry) => entry.name === "GOTRUE_DB_DATABASE_URL").value;
	assert.equal(dbUrl, "postgres://supabase_auth_admin:$(POSTGRES_PASSWORD)@aidr-db.internal.example.com:5432/postgres?sslmode=verify-full");
	const ingress = docs.find((doc) => doc.kind === "Ingress");
	assert.equal(ingress.metadata.annotations["cert-manager.io/cluster-issuer"], "letsencrypt-prod");
});

// ---------------------------------------------------------------------------
// Backups: stored objects are covered (or the gap is explicit) and the
// pre-upgrade migration never runs without a fresh backup.
// ---------------------------------------------------------------------------
const hookWeight = (text) => Number(text.match(/helm\.sh\/hook-weight: "(-?\d+)"/)?.[1]);

test("backup defaults gate upgrades and never silently skip stored objects", () => {
	const values = readYaml(join(chartDir, "values.yaml"));
	assert.equal(values.backup.preUpgrade.enabled, true, "a pre-upgrade backup is on whenever backups are");
	assert.equal(values.backup.storage.enabled, false);
	assert.equal(values.backup.storage.acknowledgeNotBackedUp, false, "accepting a database-only backup must be explicit");
	assert.equal(values.migrations.allowWithoutBackup, false, "migrating without a backup must be explicit");
	assert.ok(values.backup.activeDeadlineSeconds >= 60);
	const schema = JSON.parse(readFileSync(join(chartDir, "values.schema.json"), "utf8"));
	assert.equal(schema.properties.migrations.properties.allowWithoutBackup.type, "boolean");
	assert.equal(schema.properties.backup.properties.preUpgrade.properties.enabled.type, "boolean");
	assert.deepEqual(Object.keys(schema.properties.backup.properties.storage.properties).sort(), ["acknowledgeNotBackedUp", "enabled"]);
});

test("the backup guards fail rendering for uncovered file storage and unguarded upgrades", () => {
	const helpers = readFileSync(join(chartDir, "templates", "_backup.tpl"), "utf8");
	const validate = helpers.slice(helpers.indexOf('define "aidr.backup.validate"'), helpers.indexOf('define "aidr.backup.podSpec"'));
	assert.match(validate, /if and \$backup\.enabled \(eq \$storage\.backend "file"\) \(not \$storageBackup\) \(not \$backup\.storage\.acknowledgeNotBackedUp\) -\}\}\s*\{\{- fail /);
	assert.match(validate, /if and \$storageBackup \(ne \$storage\.backend "file"\) -\}\}\s*\{\{- fail /);
	assert.match(validate, /has "ReadWriteOncePod" \$storage\.persistence\.accessModes\) -\}\}\s*\{\{- fail /);
	assert.match(validate, /if and \.Release\.IsUpgrade \.Values\.migrations\.enabled \(not \(and \$backup\.enabled \$backup\.preUpgrade\.enabled\)\) \(not \.Values\.migrations\.allowWithoutBackup\) -\}\}\s*\{\{- fail /);
	// The guard runs on every render, not only when backups are enabled.
	const cron = readFileSync(join(chartDir, "templates", "backup-cronjob.yaml"), "utf8");
	assert.match(cron, /^\{\{- include "aidr\.backup\.validate" \. \}\}\n\{\{- if \.Values\.backup\.enabled \}\}/);
});

test("the pre-upgrade backup hook reuses the CronJob pod spec and runs before the migrations hook", () => {
	const cron = readFileSync(join(chartDir, "templates", "backup-cronjob.yaml"), "utf8");
	const preUpgrade = readFileSync(join(chartDir, "templates", "backup-pre-upgrade-job.yaml"), "utf8");
	const migrations = readFileSync(join(chartDir, "templates", "migrations-job.yaml"), "utf8");
	assert.match(cron, /include "aidr\.backup\.podSpec" \(dict "root" \. "suffix" ""\)/);
	assert.match(preUpgrade, /include "aidr\.backup\.podSpec" \(dict "root" \. "suffix" "-pre-upgrade"\)/);
	assert.match(preUpgrade, /^\{\{- if and \.Values\.backup\.enabled \.Values\.backup\.preUpgrade\.enabled \}\}/);
	assert.match(preUpgrade, /helm\.sh\/hook: pre-upgrade\n/);
	assert.match(preUpgrade, /backoffLimit: 0/);
	assert.match(migrations, /helm\.sh\/hook: post-install,pre-upgrade/);
	assert.ok(hookWeight(preUpgrade) < hookWeight(migrations), "backup hook-weight must sort before the migrations hook");
});

test("the shared backup pod archives file storage read-only with a checksum and hardened container", () => {
	const helpers = readFileSync(join(chartDir, "templates", "_backup.tpl"), "utf8");
	const podSpec = helpers.slice(helpers.indexOf('define "aidr.backup.podSpec"'));
	assert.equal((podSpec.match(/^\s+- name: [a-z-]+\n\s+image: /gm) ?? []).length, 1);
	assert.match(podSpec, /include "aidr\.resources"/);
	assert.match(podSpec, /include "aidr\.containerSecurityContext"/);
	assert.match(podSpec, /include "aidr\.podSecurityContext"/);
	assert.match(podSpec, /- name: storage-data\n\s+mountPath: \/storage-data\n\s+readOnly: true/);
	assert.match(podSpec, /- name: storage-data\n\s+persistentVolumeClaim:\n\s+claimName: [^\n]+\n\s+readOnly: true/);
	assert.match(podSpec, /sha256sum "\$\{base\}\.dump\.partial"/);
	assert.match(podSpec, /sha256sum "\$\{base\}\.storage\.tar\.gz\.partial"/);
	assert.match(podSpec, /tar -tzf "\$\{base\}\.storage\.tar\.gz\.partial"/, "the archive is verified before it is published");
	// The database dump is taken before the archive (see README "Consistency").
	assert.ok(podSpec.indexOf("pg_dump") < podSpec.indexOf("/storage-data -czf"));
	assert.match(podSpec, /"topologyKey" "kubernetes\.io\/hostname"/, "RWO storage volumes are mounted next to the storage pod");
});

test("the chart README states what is and is not backed up", () => {
	const readme = readFileSync(join(chartDir, "README.md"), "utf8");
	for (const needle of ["backup.storage.enabled", "backup.storage.acknowledgeNotBackedUp", "migrations.allowWithoutBackup", "backup.preUpgrade.enabled", "ReadWriteOncePod", "storage.backend=s3`"]) {
		assert.ok(readme.includes(needle), needle);
	}
	assert.match(readme, /\| Stored objects, `storage\.backend=s3` \| \*\*No\*\*/);
	assert.match(readme, /\| Stored objects, `storage\.backend=file` \| Only with `backup\.storage\.enabled=true` \|/);
});

test("rendering refuses backups that miss file storage objects", { skip: helmSkip }, () => {
	const base = join(chartDir, "ci", "default-values.yaml");
	const prod = join(chartDir, "ci", "prod-values.yaml");
	const cases = [
		[[base], ["backup.enabled=true"], /does not cover stored objects/],
		[[prod], ["backup.storage.enabled=true"], /backup\.storage\.enabled archives the storage\.backend=file volume/],
		[[base], ["backup.enabled=true", "backup.storage.enabled=true", "storage.persistence.accessModes={ReadWriteOncePod}"], /ReadWriteOncePod/],
	];
	for (const [files, sets, message] of cases) {
		const result = render(files, sets);
		assert.notEqual(result.status, 0, `expected failure for ${sets.join(" ")}`);
		assert.match(result.stderr, message, sets.join(" "));
	}
	const acknowledged = renderOk([base], ["backup.enabled=true", "backup.storage.acknowledgeNotBackedUp=true"]);
	const cron = acknowledged.find((doc) => doc.kind === "CronJob" && doc.metadata.name === "aidr-backup");
	assert.ok(!cron.spec.jobTemplate.spec.template.spec.volumes.some((volume) => volume.name === "storage-data"));
});

test("rendered storage backup mounts the file volume read-only next to the storage pod", { skip: helmSkip }, () => {
	const base = join(chartDir, "ci", "default-values.yaml");
	const docs = renderOk([base], ["backup.enabled=true", "backup.storage.enabled=true"]);
	for (const name of ["aidr-backup", "aidr-backup-pre-upgrade"]) {
		const doc = docs.find((item) => ["CronJob", "Job"].includes(item.kind) && item.metadata.name === name);
		assert.ok(doc, name);
		const spec = doc.kind === "CronJob" ? doc.spec.jobTemplate.spec.template.spec : doc.spec.template.spec;
		const volume = spec.volumes.find((item) => item.name === "storage-data");
		assert.deepEqual(volume.persistentVolumeClaim, { claimName: "aidr-storage", readOnly: true });
		const mount = spec.containers[0].volumeMounts.find((item) => item.name === "storage-data");
		assert.equal(mount.readOnly, true);
		const term = spec.affinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution[0];
		assert.equal(term.topologyKey, "kubernetes.io/hostname");
		assert.equal(term.labelSelector.matchLabels["app.kubernetes.io/component"], "storage");
		assert.deepEqual(spec.securityContext.supplementalGroups, [1000]);
		const script = spec.containers[0].command[2];
		assert.match(script, /\.storage\.tar\.gz\.sha256/);
		assert.match(script, /\.dump\.sha256/);
	}
	const rwx = renderOk([base], ["backup.enabled=true", "backup.storage.enabled=true", "storage.persistence.accessModes={ReadWriteMany}"]);
	const cron = rwx.find((doc) => doc.kind === "CronJob" && doc.metadata.name === "aidr-backup");
	assert.equal(cron.spec.jobTemplate.spec.template.spec.affinity, undefined, "ReadWriteMany needs no co-location");
});

test("rendered upgrades run the backup hook before migrations and refuse to migrate without one", { skip: helmSkip }, () => {
	const base = join(chartDir, "ci", "default-values.yaml");
	const prod = join(chartDir, "ci", "prod-values.yaml");
	const docs = renderOk([prod], [], ["--is-upgrade"]);
	const backup = docs.find((doc) => doc.kind === "Job" && doc.metadata.name === "aidr-backup-pre-upgrade");
	const migrations = docs.find((doc) => doc.kind === "Job" && doc.metadata.name === "aidr-migrations");
	assert.equal(backup.metadata.annotations["helm.sh/hook"], "pre-upgrade");
	assert.match(migrations.metadata.annotations["helm.sh/hook"], /pre-upgrade/);
	assert.ok(Number(backup.metadata.annotations["helm.sh/hook-weight"]) < Number(migrations.metadata.annotations["helm.sh/hook-weight"]));
	assert.equal(backup.spec.backoffLimit, 0);
	assert.match(backup.spec.template.spec.containers[0].command[2], /-pre-upgrade"/);

	for (const [files, sets] of [[[base], []], [[prod], ["backup.preUpgrade.enabled=false"]], [[prod], ["backup.enabled=false"]]]) {
		const refused = render(files, sets, ["--is-upgrade"]);
		assert.notEqual(refused.status, 0, `expected the upgrade to be refused: ${sets.join(" ")}`);
		assert.match(refused.stderr, /refusing to upgrade/);
	}
	renderOk([base], ["migrations.allowWithoutBackup=true"], ["--is-upgrade"]);
	renderOk([base], ["migrations.enabled=false"], ["--is-upgrade"]);
	// A fresh install has nothing to back up and is not gated.
	assert.ok(!renderOk([base]).some((doc) => doc.metadata.name === "aidr-backup-pre-upgrade"));
});

test("the notification dispatcher CronJob is opt-in, token-authenticated and never sees the service-role key", () => {
	const values = readYaml(join(chartDir, "values.yaml"));
	assert.equal(values.notifications.dispatcher.enabled, false, "upgrades with an older functions Secret must not start failing jobs");
	assert.equal(values.notifications.dispatcher.schedule, "* * * * *");
	const template = readFileSync(join(chartDir, "templates", "notification-dispatch-cronjob.yaml"), "utf8");
	assert.match(template, /^\{\{- if \.Values\.notifications\.dispatcher\.enabled \}\}/);
	assert.match(template, /concurrencyPolicy: Forbid/);
	assert.match(template, /secretKeyRef:\s+name: \{\{ include "aidr\.functionsSecretName" \. \}\}\s+key: AIDR_NOTIFICATION_DISPATCH_TOKEN/);
	assert.match(template, /http:\/\/%s:9000\/notification-dispatch/);
	assert.doesNotMatch(template, /service-role-key|SERVICE_ROLE/);
	assert.doesNotMatch(template, /\$\{?AIDR_NOTIFICATION_DISPATCH_TOKEN/, "the token is read from the environment, never interpolated into argv");
	const policies = readFileSync(join(chartDir, "templates", "networkpolicy.yaml"), "utf8");
	assert.match(policies, /component" "notification-dispatch"\) \| nindent 8 \}\}[\s\S]*?port: 9000/);
});

test("rendered prod values add the notification dispatcher with its own network allow-list", { skip: helmSkip }, () => {
	const docs = renderDocs("prod");
	const cron = docs.find((doc) => doc.kind === "CronJob" && doc.metadata.name.endsWith("-notification-dispatch"));
	assert.ok(cron, "notification-dispatch CronJob");
	const container = cron.spec.jobTemplate.spec.template.spec.containers[0];
	const token = container.env.find((entry) => entry.name === "AIDR_NOTIFICATION_DISPATCH_TOKEN");
	assert.deepEqual(token.valueFrom.secretKeyRef, { name: "aidr-functions", key: "AIDR_NOTIFICATION_DISPATCH_TOKEN" });
	assert.ok(!JSON.stringify(container.command).includes(token.valueFrom.secretKeyRef.key.toLowerCase()));
	const policy = docs.find((doc) => doc.kind === "NetworkPolicy" && doc.metadata.name.endsWith("-notification-dispatch"));
	assert.equal(policy.spec.egress[0].ports[0].port, 9000);
	const functions = docs.find((doc) => doc.kind === "NetworkPolicy" && doc.metadata.name.endsWith("-functions"));
	assert.ok(JSON.stringify(functions.spec.ingress).includes("notification-dispatch"));
	assert.ok(!renderDocs("default").some((doc) => doc.kind === "CronJob" && doc.metadata.name.endsWith("-notification-dispatch")));
});

test("rendered posture-scanner values add the scanning stack with an egress-proxied agent", { skip: helmSkip }, () => {
	const docs = renderDocs("posture-scanner");
	for (const component of ["posture-scanner-server", "posture-scanner-agent", "posture-scanner-bridge"]) {
		assert.ok(docs.some((doc) => doc.kind === "Deployment" && doc.metadata.labels["app.kubernetes.io/component"] === component), component);
		assert.ok(docs.some((doc) => doc.kind === "NetworkPolicy" && doc.metadata.name.endsWith(component)), `${component} NetworkPolicy`);
	}
	const agent = docs.find((doc) => doc.kind === "Deployment" && doc.metadata.name.endsWith("-posture-scanner-agent"));
	const env = Object.fromEntries(agent.spec.template.spec.containers[0].env.map((entry) => [entry.name, entry.value]));
	assert.equal(env.HTTPS_PROXY, "http://egress-proxy.security.svc:3128");
	// Every Kubernetes object the chart names for the scanner uses the posture-scanner name.
	const scannerObjects = docs.filter((doc) => /posture-scanner|aig/.test(doc.metadata?.name ?? ""));
	assert.ok(scannerObjects.length >= 11, "Deployments, Services, PVCs and NetworkPolicies are rendered");
	for (const doc of scannerObjects) assert.doesNotMatch(doc.metadata.name, /aig/, `${doc.kind}/${doc.metadata.name}`);
	for (const doc of docs.filter((item) => item.kind === "Deployment" && /posture-scanner/.test(item.metadata.name))) {
		assert.match(doc.spec.template.spec.containers[0].image, /^registry\.example\.internal\/aidr\/posture-scanner-(server|agent|bridge):/);
	}
});

test("rendering fails closed on missing secrets, weak URLs and mutable tags", { skip: helmSkip }, () => {
	const base = join(chartDir, "ci", "default-values.yaml");
	const cases = [
		[["secrets.existingSecret="], /secrets\.existingSecret is required/],
		[["secrets.functionsExistingSecret="], /secrets\.functionsExistingSecret is required/],
		[["publicUrls.api=http://api.aidr.example.com"], /publicUrls/],
		// Helm 3.19 rejects this in values.schema.json and names the JSON pointer /auth/image/tag.
		[["auth.image.tag=latest"], /latest|auth[./]image[./]tag/],
		[["global.imageRegistry="], /no registry/],
		[["ingress.tlsSecretName="], /TLS is mandatory/],
		[["postgresql.enabled=false", "externalDatabase.host=db.example.com"], /networkPolicyCIDRs is required/],
		[["storage.replicaCount=2"], /storage\.replicaCount > 1/],
		[["postureScanner.enabled=true"], /postureScanner\.existingSecret is required/],
		// The pre-rename key is refused with a pointer to the new one, never silently ignored.
		[["aig.enabled=true"], /values key `aig` was renamed to `postureScanner`/],
		[["aig.enabled=false"], /values key `aig` was renamed to `postureScanner`/],
	];
	for (const [sets, message] of cases) {
		const result = render([base], sets);
		assert.notEqual(result.status, 0, `expected failure for ${sets.join(" ")}`);
		assert.match(result.stderr, message, sets.join(" "));
	}
});

test("a shared dashboard/API host routes only the API prefixes to the gateway", { skip: helmSkip }, () => {
	const result = render([join(chartDir, "ci", "default-values.yaml")], ["publicUrls.api=https://aidr.example.com"]);
	assert.equal(result.status, 0, result.stderr);
	const ingress = parseAllDocuments(result.stdout).map((doc) => doc.toJSON()).find((doc) => doc?.kind === "Ingress");
	assert.equal(ingress.spec.rules.length, 1);
	const routes = Object.fromEntries(ingress.spec.rules[0].http.paths.map((path) => [path.path, path.backend.service.name]));
	assert.equal(routes["/"], "aidr-dashboard");
	for (const prefix of ["/auth/v1/", "/rest/v1/", "/storage/v1/", "/functions/v1/"]) assert.equal(routes[prefix], "aidr-api-gw");
});

// Optional: validate against the Kubernetes OpenAPI schemas when kubeconform is
// available (KUBECONFORM_BIN or PATH). It downloads schemas unless cached.
function findKubeconform() {
	for (const candidate of [process.env.KUBECONFORM_BIN, "kubeconform"].filter(Boolean)) {
		if (spawnSync(candidate, ["-v"], { encoding: "utf8" }).status === 0) return candidate;
	}
	return null;
}
const kubeconform = helm ? findKubeconform() : null;
test("rendered manifests validate against the Kubernetes 1.25 and 1.30 schemas", { skip: kubeconform ? false : "helm or kubeconform not found (set HELM_BIN and KUBECONFORM_BIN)" }, () => {
	for (const name of CI_VALUES) {
		const rendered = render([join(chartDir, "ci", `${name}-values.yaml`)]);
		assert.equal(rendered.status, 0, rendered.stderr);
		for (const version of ["1.25.0", "1.30.0"]) {
			const result = spawnSync(kubeconform, ["-strict", "-summary", "-kubernetes-version", version, "-"], { input: rendered.stdout, encoding: "utf8" });
			assert.equal(result.status, 0, `${name} @ ${version}: ${result.stdout}${result.stderr}`);
		}
	}
});

test("rendered images give the complete air-gap pull list", { skip: helmSkip }, () => {
	const images = new Set();
	for (const name of CI_VALUES) {
		for (const { spec } of podSpecs(renderDocs(name))) for (const container of spec.containers) images.add(container.image);
	}
	for (const expected of ["supabase/gotrue:v2.197.0", "postgrest/postgrest:v14.17", "supabase/storage-api:v1.80.2", "envoyproxy/envoy:v1.39.2", "supabase/postgres:17.6.1.136", "aidr/dashboard:0.6.0", "aidr/edge-functions:0.6.0", "aidr/migrations:0.6.0"]) {
		assert.ok([...images].some((image) => image === `registry.example.internal/${expected}`), expected);
	}
});

// --- Optional privacy gateway --------------------------------------------------------

test("the privacy gateway is opt-in, mTLS-only and has no defaulted credentials, model or egress", () => {
	const values = readYaml(join(chartDir, "values.yaml")).privacyGateway;
	assert.equal(values.enabled, false);
	assert.equal(values.mtls.enabled, true);
	assert.equal(values.mtls.existingSecret, "");
	assert.equal(values.existingSecret, "");
	assert.equal(values.trustConfigMap, "");
	assert.equal(values.models.existingClaim, "");
	assert.deepEqual(values.egress.cidrs, []);
	assert.deepEqual(values.serviceConfig, {});
	assert.equal(values.service.type, "ClusterIP");
	const schema = JSON.parse(readFileSync(join(chartDir, "values.schema.json"), "utf8")).properties.privacyGateway;
	assert.deepEqual(schema.properties.service.properties.type.enum, ["ClusterIP", "LoadBalancer", "NodePort"]);
	assert.equal(schema.properties.egress.properties.cidrs.$ref, "#/definitions/cidrList");
});

test("the privacy gateway template validates before rendering and meets the restricted Pod Security Standard", () => {
	const template = readFileSync(join(chartDir, "templates", "privacy-gateway.yaml"), "utf8");
	const body = template.replace(/^\{\{-? \/\*[\s\S]*?\*\/ -?\}\}\n/, "");
	assert.match(body, /^\{\{- if \.Values\.privacyGateway\.enabled \}\}\n\{\{- include "aidr\.privacyGateway\.validate" \. \}\}/, "validation runs before any object renders");
	assert.match(template, /replicas: 1\n\s+strategy:\n\s+type: Recreate/, "single writer for the SQLite ledger");
	assert.match(template, /include "aidr\.podSecurityContext" \(dict "root" \. "runAsUser" 10001 "fsGroup" 10001\)/);
	assert.match(template, /include "aidr\.containerSecurityContext" \(dict "root" \. "readOnlyRootFilesystem" true\)/);
	for (const forbidden of [/hostPath/, /hostNetwork/, /hostPID/, /hostIPC/, /hostPort/, /privileged/, /allowPrivilegeEscalation: true/, /\bSYS_|NET_ADMIN|NET_RAW/]) {
		assert.doesNotMatch(template, forbidden, `restricted PSS forbids ${forbidden}`);
	}
	// Secrets arrive only as read-only files, never as environment variables.
	assert.doesNotMatch(template, /secretKeyRef|envFrom/);
	assert.match(template, /- name: secrets\n\s+projected:\n\s+defaultMode: 0440/);
	assert.match(template, /key: tls\.key\n\s+path: aidr-privacy-tls-key/);
	for (const probe of ["startupProbe", "readinessProbe", "livenessProbe"]) assert.match(template, new RegExp(`${probe}:\\n\\s+tcpSocket:\\n\\s+port: mtls`), probe);
	// The NetworkPolicy is part of the gateway contract and does not depend on networkPolicy.enabled.
	assert.doesNotMatch(template, /\.Values\.networkPolicy\.enabled/);
	assert.match(template, /kind: NetworkPolicy[\s\S]*policyTypes: \["Ingress", "Egress"\][\s\S]*port: 8443[\s\S]*include "aidr\.np\.cidrs" \(dict "cidrs" \$pg\.egress\.cidrs "port" 443\)/);
	assert.match(template, /externalTrafficPolicy: Local/, "client source addresses survive for clientCIDRs");
});

test("privacy gateway validation fails closed on missing mutual TLS, secrets, model, egress and owned settings", () => {
	const helpers = readFileSync(join(chartDir, "templates", "_helpers.tpl"), "utf8");
	const validate = helpers.slice(helpers.indexOf('{{- define "aidr.privacyGateway.validate" -}}'), helpers.indexOf('{{- define "aidr.privacyGateway.serviceConfig" -}}'));
	assert.ok(validate.length > 0);
	for (const expected of [
		/if not \$pg\.mtls\.enabled -\}\}\n\{\{- fail "privacyGateway\.mtls\.enabled=false is refused/,
		/required "privacyGateway\.mtls\.existingSecret is required when privacyGateway\.enabled[^"]*mutual TLS is mandatory/,
		/required "privacyGateway\.existingSecret is required/,
		/required "privacyGateway\.trustConfigMap is required/,
		/required "privacyGateway\.models\.existingClaim is required/,
		/if empty \$pg\.egress\.cidrs -\}\}\n\{\{- fail "privacyGateway\.egress\.cidrs is required/,
		/include "aidr\.privacyGateway\.cidrs" \(dict "name" "privacyGateway\.egress\.cidrs"/,
		/list "tls" "host" "port" "secretStore" "databasePath" "documents"/,
		/contains "REPLACE" \(toJson \$cfg\)/,
		/"openai-responses" "https:\/\/api\.openai\.com" "gemini-generate-content" "https:\/\/generativelanguage\.googleapis\.com"/,
		/regexMatch "\^\[a-f0-9\]\{64\}\$" \(toString \$ner\.manifestSha256\)/,
		/service\.type=%s exposes the gateway outside the cluster/,
	]) assert.match(validate, expected);
	const cidrs = helpers.slice(helpers.indexOf('{{- define "aidr.privacyGateway.cidrs" -}}'), helpers.indexOf('{{- define "aidr.privacyGateway.trustPath" -}}'));
	assert.match(cidrs, /ternary 16 8 \(contains ":" \$cidr\)/, "IPv4 /8 and IPv6 /16 minimum prefixes");
	assert.match(cidrs, /169\\\\\.254\\\\\./, "cloud metadata link-local range refused");
});

test("the chart-owned service settings match the container layout the image enforces", () => {
	const helpers = readFileSync(join(chartDir, "templates", "_helpers.tpl"), "utf8");
	const render = helpers.slice(helpers.indexOf('{{- define "aidr.privacyGateway.serviceConfig" -}}'));
	const L = PRIVACY_GATEWAY_LAYOUT;
	assert.ok(render.includes(`"python" "${L.nerPython}"`));
	assert.ok(render.includes(`set $cfg "secretStore" "mounted-files"`));
	assert.ok(render.includes(`set $cfg "port" ${L.port}`));
	assert.ok(render.includes(`"databasePath" "${L.database}"`));
	assert.ok(render.includes(`"certPath" "${L.tlsCert}" "clientCaPath" "${L.tlsClientCa}" "keyRef" "${L.tlsKeyRef}"`));
	const template = readFileSync(join(chartDir, "templates", "privacy-gateway.yaml"), "utf8");
	assert.ok(template.includes(`value: ${L.config}`));
	for (const path of [L.trust, L.tls, L.secrets, L.models, L.state]) assert.ok(template.includes(`mountPath: ${path}`), path);
	assert.ok(template.includes(`mountPath: ${L.config.slice(0, L.config.lastIndexOf("/"))}`));
	assert.ok(helpers.includes("^/etc/aidr-privacy/trust/") && helpers.includes('hasPrefix "/opt/aidr-models/"'));
});

test("rendered privacy-gateway values add a hardened gateway with an egress allow-list and no Secret objects", { skip: helmSkip }, () => {
	const docs = renderDocs("privacy-gateway");
	const deployment = docs.find((doc) => doc.kind === "Deployment" && doc.metadata.name === "aidr-privacy-gateway");
	assert.ok(deployment);
	const spec = deployment.spec.template.spec;
	assert.equal(deployment.spec.replicas, 1);
	assert.equal(spec.securityContext.runAsUser, 10001);
	assert.equal(spec.containers[0].securityContext.readOnlyRootFilesystem, true);
	assert.equal(spec.containers[0].image, "registry.example.internal/aidr/privacy-gateway:0.6.0");
	assert.ok(!spec.containers[0].env.some((entry) => entry.valueFrom));
	const config = JSON.parse(docs.find((doc) => doc.kind === "ConfigMap" && doc.metadata.name === "aidr-privacy-gateway").data["service.json"]);
	assert.equal(config.secretStore, "mounted-files");
	assert.equal(config.port, 8443);
	assert.deepEqual(config.tls, { certPath: "/etc/aidr-privacy/tls/server.pem", clientCaPath: "/etc/aidr-privacy/tls/client-ca.pem", keyRef: "aidr-privacy-tls-key" });
	const policy = docs.find((doc) => doc.kind === "NetworkPolicy" && doc.metadata.name === "aidr-privacy-gateway");
	assert.deepEqual(policy.spec.policyTypes, ["Ingress", "Egress"]);
	const egress443 = policy.spec.egress.find((rule) => rule.ports.some((port) => port.port === 443));
	assert.deepEqual(egress443.to.map((peer) => peer.ipBlock.cidr), ["162.159.140.0/24", "10.50.0.10/32"]);
	assert.ok(policy.spec.egress.every((rule) => rule.ports.every((port) => [53, 443].includes(port.port))));
	assert.deepEqual(policy.spec.ingress[0].ports, [{ port: 8443, protocol: "TCP" }]);
	assert.ok(!docs.some((doc) => doc.kind === "Secret"));
	assert.ok(!renderDocs("default").some((doc) => doc.metadata?.name?.includes("privacy-gateway")), "disabled by default");
});

test("rendering refuses a weak privacy gateway configuration", { skip: helmSkip }, () => {
	const base = join(chartDir, "ci", "privacy-gateway-values.yaml");
	const cases = [
		[["privacyGateway.mtls.enabled=false"], /privacyGateway\.mtls\.enabled=false is refused/],
		[["privacyGateway.mtls.existingSecret="], /privacyGateway\.mtls\.existingSecret is required/],
		[["privacyGateway.existingSecret="], /privacyGateway\.existingSecret is required/],
		[["privacyGateway.models.existingClaim="], /privacyGateway\.models\.existingClaim is required/],
		[["privacyGateway.egress.cidrs=null"], /privacyGateway\.egress\.cidrs is required/],
		[["privacyGateway.egress.cidrs[0]=0.0.0.0/0"], /too broad/],
		[["privacyGateway.egress.cidrs[0]=169.254.169.254/32"], /link-local/],
		[["privacyGateway.serviceConfig.tls.certPath=/tmp/server.pem"], /serviceConfig\.tls must not be set/],
		[["privacyGateway.serviceConfig.documents.python=/usr/bin/python3"], /serviceConfig\.documents must not be set/],
		[["privacyGateway.serviceConfig.destination.origin=https://proxy.example.com"], /destination must be openai-responses/],
		[["privacyGateway.serviceConfig.destination.model=REPLACE_WITH_MODEL"], /REPLACE placeholder/],
		[["privacyGateway.serviceConfig.ner.manifestSha256=abc"], /manifestSha256 must be the independently approved/],
		[["privacyGateway.serviceConfig.oidc.caPath=/etc/ssl/certs/ca.pem"], /oidc\.caPath must be \/etc\/aidr-privacy\/trust/],
		[["privacyGateway.clientCIDRs=null", "privacyGateway.service.type=LoadBalancer"], /exposes the gateway outside the cluster/],
	];
	for (const [sets, message] of cases) {
		const result = render([base], sets);
		assert.notEqual(result.status, 0, `expected failure for ${sets.join(" ")}`);
		assert.match(result.stderr, message, sets.join(" "));
	}
});
