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

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const chartDir = join(here, "aidr");
const { parse, parseAllDocuments } = createRequire(join(root, "packages/core/package.json"))("yaml");
const readYaml = (path) => parse(readFileSync(path, "utf8"));
const CI_VALUES = ["default", "prod", "aig"];
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

function render(valuesFiles, setArgs = []) {
	const args = ["template", "aidr", chartDir, "--namespace", "aidr", "--kube-version", KUBE_VERSION];
	for (const file of valuesFiles) args.push("-f", file);
	for (const entry of setArgs) args.push("--set", entry);
	return runHelm(args);
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
	assert.equal(values.aig.enabled, false);
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

test("helm lint passes for default, prod and aig values", { skip: helmSkip }, () => {
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

test("rendered aig values add the scanning stack with an egress-proxied agent", { skip: helmSkip }, () => {
	const docs = renderDocs("aig");
	for (const component of ["aig-server", "aig-agent", "aig-bridge"]) {
		assert.ok(docs.some((doc) => doc.kind === "Deployment" && doc.metadata.labels["app.kubernetes.io/component"] === component), component);
		assert.ok(docs.some((doc) => doc.kind === "NetworkPolicy" && doc.metadata.name.endsWith(component)), `${component} NetworkPolicy`);
	}
	const agent = docs.find((doc) => doc.kind === "Deployment" && doc.metadata.name.endsWith("-aig-agent"));
	const env = Object.fromEntries(agent.spec.template.spec.containers[0].env.map((entry) => [entry.name, entry.value]));
	assert.equal(env.HTTPS_PROXY, "http://egress-proxy.security.svc:3128");
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
		[["aig.enabled=true"], /aig\.existingSecret is required/],
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
	for (const expected of ["supabase/gotrue:v2.196.0", "postgrest/postgrest:v14.17", "supabase/storage-api:v1.74.0", "envoyproxy/envoy:v1.39.1", "supabase/postgres:17.6.1.136", "aidr/dashboard:0.6.0", "aidr/edge-functions:0.6.0", "aidr/migrations:0.6.0"]) {
		assert.ok([...images].some((image) => image === `registry.example.internal/${expected}`), expected);
	}
});
