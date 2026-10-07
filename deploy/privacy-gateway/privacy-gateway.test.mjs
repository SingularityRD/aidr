/**
 * node --test sibling for the generated privacy gateway egress firewall.
 *
 * The invariant: re-applying the firewall must never leave the gateway subnet
 * unfiltered or partially filtered. The chain DOCKER-USER jumps to is never
 * flushed while it is jumped to; a complete replacement chain (ending in REJECT)
 * is built first, the jump is swapped, and only then is the old chain retired.
 * The behavioural cases run the generated script under bash against a stub
 * `iptables` that keeps chain state on disk and checks the invariant after
 * every mutating call.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { PRIVACY_GATEWAY_FIREWALL_CHAINS, PRIVACY_GATEWAY_LEGACY_FIREWALL_CHAIN, renderPrivacyGatewayFirewall } from "./privacy-gateway.mjs";

const [CHAIN_A, CHAIN_B] = PRIVACY_GATEWAY_FIREWALL_CHAINS;
const LEGACY = PRIVACY_GATEWAY_LEGACY_FIREWALL_CHAIN;
const SUBNET = "172.31.253.0/28";
const firewall = renderPrivacyGatewayFirewall({ subnet: SUBNET, egressCidrs: ["162.159.140.0/24", "10.20.30.0/24"], dnsCidrs: ["10.0.0.53/32"] });

const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
const bash = process.platform === "win32" && existsSync(gitBash) ? gitBash : "bash";
const probe = spawnSync(bash, ["-c", "echo ok"], { encoding: "utf8" });
const skip = probe.status === 0 && probe.stdout.trim() === "ok" ? false : "bash is required to run the generated firewall script";
const toBash = (path) => process.platform === "win32"
	? path.replace(/^([A-Za-z]):/, (_match, drive) => `/${drive.toLowerCase()}`).replaceAll("\\", "/")
	: path;

// Stub iptables: one file per chain under $IPT_STATE/chains holding its rules.
// After every call it records a violation when DOCKER-USER jumps to an AIDR
// chain that is missing or does not end in REJECT, or when the subnet lost its
// AIDR jump after having had one.
const STUB = String.raw`#!/usr/bin/env bash
state=$IPT_STATE
printf '%s\n' "$*" >> "$state/log"
args=("$@")
[ "%{args[0]}" = -w ] && args=("%{args[@]:1}")
op=%{args[0]} chain=%{args[1]:-}
rest="%{args[*]:2}"
f="$state/chains/$chain"
if [ -n "%{IPT_FAIL_ON:-}" ] && [[ "$*" == *"$IPT_FAIL_ON"* ]]; then echo "stub: injected failure" >&2; exit 1; fi
status=0
case "$op" in
	-S) if [ -f "$f" ]; then echo "-N $chain"; while IFS= read -r r; do echo "-A $chain $r"; done < "$f"; else echo "iptables: No chain/target/match by that name." >&2; status=1; fi ;;
	-N) if [ -f "$f" ]; then status=1; else : > "$f"; fi ;;
	-F) if [ -f "$f" ]; then : > "$f"; else status=1; fi ;;
	-X) if [ ! -f "$f" ] || [ -s "$f" ] || grep -qE -- "-j $chain\$" "$state"/chains/*; then status=1; else rm "$f"; fi ;;
	-A) if [ -f "$f" ]; then printf '%s\n' "$rest" >> "$f"; else status=1; fi ;;
	-I) if [ -f "$f" ]; then rest="%{args[*]:3}"; { printf '%s\n' "$rest"; cat "$f"; } > "$f.tmp"; mv "$f.tmp" "$f"; else status=1; fi ;;
	-C) [ -f "$f" ] && grep -qxF -- "$rest" "$f" || status=1 ;;
	-D) if [ -f "$f" ] && grep -qxF -- "$rest" "$f"; then awk -v r="$rest" 'd || $0 != r { print; next } { d = 1 }' "$f" > "$f.tmp"; mv "$f.tmp" "$f"; else status=1; fi ;;
	*) status=2 ;;
esac
jumps=0
if [ -f "$state/chains/DOCKER-USER" ]; then
	while IFS= read -r target; do
		case "$target" in AIDR-*) ;; *) continue ;; esac
		jumps=$((jumps + 1))
		if [ ! -f "$state/chains/$target" ] || [ "$(tail -n 1 "$state/chains/$target")" != "-j REJECT" ]; then
			echo "after '$*': DOCKER-USER jumps to incomplete chain $target" >> "$state/violations"
		fi
	done < <(sed -n 's/^.*-j \([^ ]*\)$/\1/p' "$state/chains/DOCKER-USER")
fi
if [ "$jumps" -gt 0 ]; then : > "$state/protected"
elif [ -f "$state/protected" ]; then echo "after '$*': the gateway subnet has no AIDR jump" >> "$state/violations"
fi
exit "$status"
`.replaceAll("%{", "${"); // "${" cannot appear literally inside a template literal

function harness(seed = {}) {
	const work = mkdtempSync(join(tmpdir(), "aidr-egress-firewall-"));
	const stubs = join(work, "bin");
	const state = join(work, "state");
	mkdirSync(stubs);
	mkdirSync(join(state, "chains"), { recursive: true });
	writeFileSync(join(stubs, "iptables"), STUB, { mode: 0o755 });
	writeFileSync(join(work, "egress-firewall.sh"), firewall, { mode: 0o700 });
	for (const [chain, rules] of Object.entries({ "DOCKER-USER": ["-j RETURN"], ...seed })) {
		if (rules !== null) writeFileSync(join(state, "chains", chain), rules.map((rule) => `${rule}\n`).join(""));
	}
	if (Object.keys(seed).some((chain) => (seed[chain] ?? []).some((rule) => rule.includes("-j AIDR")))) writeFileSync(join(state, "protected"), "");
	const chains = () => Object.fromEntries(readdirSync(join(state, "chains")).map((name) => [name, readFileSync(join(state, "chains", name), "utf8").split("\n").filter(Boolean)]));
	return {
		chains,
		run(env = {}) {
			for (const file of ["log", "violations"]) rmSync(join(state, file), { force: true });
			const result = spawnSync(bash, ["-c", 'PATH="$1:$PATH" exec bash "$2"', "harness", toBash(stubs), toBash(join(work, "egress-firewall.sh"))], {
				encoding: "utf8",
				env: { ...process.env, IPT_STATE: toBash(state), ...env },
				timeout: 60_000,
			});
			const read = (file) => existsSync(join(state, file)) ? readFileSync(join(state, file), "utf8").split("\n").filter(Boolean) : [];
			return { ...result, log: read("log"), violations: read("violations") };
		},
		dispose() { rmSync(work, { recursive: true, force: true }); },
	};
}

const EXPECTED_RULES = [
	"-m conntrack --ctstate ESTABLISHED,RELATED -j RETURN",
	"-d 162.159.140.0/24 -p tcp --dport 443 -j RETURN",
	"-d 10.20.30.0/24 -p tcp --dport 443 -j RETURN",
	"-d 10.0.0.53/32 -p udp --dport 53 -j RETURN",
	"-d 10.0.0.53/32 -p tcp --dport 53 -j RETURN",
	"-j REJECT",
];
const jump = (chain) => `-s ${SUBNET} -j ${chain}`;
const indexOf = (log, needle) => log.findIndex((line) => line.includes(needle));

test("generated firewall is strict bash and never flushes the live chain before the swap", () => {
	assert.match(firewall, /^#!\/usr\/bin\/env bash\n/);
	assert.match(firewall, /^set -euo pipefail$/m);
	assert.match(firewall, /^trap cleanup EXIT$/m);
	assert.match(firewall, /^SUBNET='172\.31\.253\.0\/28'$/m);
	assert.doesNotMatch(firewall, /0\.0\.0\.0\/0/);
	const swap = firewall.indexOf('iptables -w -I DOCKER-USER 1 -s "$SUBNET" -j "$NEW"');
	const reject = firewall.indexOf('iptables -w -A "$NEW" -j REJECT');
	const dropOld = firewall.indexOf('iptables -w -D DOCKER-USER -s "$SUBNET" -j "$old"');
	const flushOld = firewall.indexOf('iptables -w -F "$old"');
	assert.ok(reject > 0 && swap > reject, "the new chain ends in REJECT before DOCKER-USER jumps to it");
	assert.ok(dropOld > swap, "the old jump is removed only after the new jump is inserted");
	assert.ok(flushOld > dropOld, "the old chain is flushed only after nothing jumps to it");
	// Before the swap the only chain ever flushed is the unreferenced new one.
	const beforeSwap = firewall.slice(0, swap).split("\n").filter((line) => !line.trimStart().startsWith("#"));
	for (const line of beforeSwap.filter((entry) => / -F /.test(entry))) assert.match(line, /-F "\$NEW"/, `unexpected flush before the swap: ${line}`);
	assert.doesNotMatch(firewall, /-F "\$CHAIN"|-F AIDR-PRIVACY/, "no flush of a fixed (possibly live) chain name");
	// The candidate is chosen only among chains DOCKER-USER does not reference.
	assert.match(firewall, /if ! referenced "\$candidate"; then NEW=\$candidate; break; fi/);
	// Every allow rule targets the new chain; the final rule is the reject.
	const appends = firewall.split("\n").filter((line) => line.startsWith('iptables -w -A "$NEW"'));
	assert.equal(appends.at(-1), 'iptables -w -A "$NEW" -j REJECT');
	assert.ok(appends.some((line) => line.includes("-d '162.159.140.0/24' -p tcp --dport 443 -j RETURN")));
	assert.ok(appends.some((line) => line.includes("-d '10.0.0.53/32' -p udp --dport 53 -j RETURN")));
});

test("first apply builds chain A completely, then jumps to it", { skip }, () => {
	const h = harness();
	try {
		const result = h.run();
		assert.equal(result.status, 0, result.stderr);
		assert.deepEqual(result.violations, []);
		const chains = h.chains();
		assert.deepEqual(chains[CHAIN_A], EXPECTED_RULES);
		assert.deepEqual(chains["DOCKER-USER"], [jump(CHAIN_A), "-j RETURN"], "the jump is inserted at the top of DOCKER-USER");
		assert.ok(indexOf(result.log, `-A ${CHAIN_A} -j REJECT`) < indexOf(result.log, `-I DOCKER-USER 1 ${jump(CHAIN_A)}`));
	} finally { h.dispose(); }
});

test("re-applying alternates chains, swaps the jump first and never flushes the live chain", { skip }, () => {
	const h = harness();
	try {
		assert.equal(h.run().status, 0);
		const second = h.run();
		assert.equal(second.status, 0, second.stderr);
		assert.deepEqual(second.violations, []);
		const rejectB = indexOf(second.log, `-A ${CHAIN_B} -j REJECT`);
		const insertB = indexOf(second.log, `-I DOCKER-USER 1 ${jump(CHAIN_B)}`);
		const deleteA = indexOf(second.log, `-D DOCKER-USER ${jump(CHAIN_A)}`);
		const flushA = indexOf(second.log, `-F ${CHAIN_A}`);
		assert.ok(rejectB >= 0 && rejectB < insertB, "chain B is complete before the jump to it");
		assert.ok(insertB < deleteA, "the jump to B is inserted before the jump to A is removed");
		assert.ok(deleteA < flushA, "chain A is flushed only after it is no longer jumped to");
		let chains = h.chains();
		assert.equal(chains[CHAIN_A], undefined, "the retired chain is deleted");
		assert.deepEqual(chains[CHAIN_B], EXPECTED_RULES);
		assert.deepEqual(chains["DOCKER-USER"], [jump(CHAIN_B), "-j RETURN"]);

		const third = h.run();
		assert.equal(third.status, 0, third.stderr);
		assert.deepEqual(third.violations, []);
		chains = h.chains();
		assert.deepEqual(chains["DOCKER-USER"], [jump(CHAIN_A), "-j RETURN"], "idempotent: exactly one jump after every run");
		assert.deepEqual(chains[CHAIN_A], EXPECTED_RULES);
		assert.equal(chains[CHAIN_B], undefined);
	} finally { h.dispose(); }
});

test("the single-chain layout of earlier releases is migrated without a gap", { skip }, () => {
	const h = harness({ "DOCKER-USER": [jump(LEGACY), "-j RETURN"], [LEGACY]: EXPECTED_RULES });
	try {
		const result = h.run();
		assert.equal(result.status, 0, result.stderr);
		assert.deepEqual(result.violations, []);
		const chains = h.chains();
		assert.equal(chains[LEGACY], undefined);
		assert.deepEqual(chains["DOCKER-USER"], [jump(CHAIN_A), "-j RETURN"]);
		assert.ok(indexOf(result.log, `-I DOCKER-USER 1 ${jump(CHAIN_A)}`) < indexOf(result.log, `-F ${LEGACY}`));
	} finally { h.dispose(); }
});

test("a leftover unreferenced chain from an interrupted run is rebuilt cleanly", { skip }, () => {
	const h = harness({ "DOCKER-USER": [jump(CHAIN_A), "-j RETURN"], [CHAIN_A]: EXPECTED_RULES, [CHAIN_B]: ["-d 203.0.113.0/24 -j RETURN"] });
	try {
		const result = h.run();
		assert.equal(result.status, 0, result.stderr);
		assert.deepEqual(result.violations, []);
		assert.deepEqual(h.chains()[CHAIN_B], EXPECTED_RULES);
		assert.equal(h.chains()[CHAIN_A], undefined);
	} finally { h.dispose(); }
});

test("a failure while building leaves the active chain in place and removes the half-built one", { skip }, () => {
	const h = harness();
	try {
		assert.equal(h.run().status, 0);
		const failed = h.run({ IPT_FAIL_ON: "--dport 53" });
		assert.notEqual(failed.status, 0);
		assert.match(failed.stderr, /NOT updated; the previous rules are unchanged/);
		assert.deepEqual(failed.violations, []);
		const chains = h.chains();
		assert.deepEqual(chains["DOCKER-USER"], [jump(CHAIN_A), "-j RETURN"]);
		assert.deepEqual(chains[CHAIN_A], EXPECTED_RULES, "the active chain was never touched");
		assert.equal(chains[CHAIN_B], undefined, "the half-built chain is removed");
		assert.equal(indexOf(failed.log, `-F ${CHAIN_A}`), -1);
		// The next run recovers normally.
		assert.equal(h.run().status, 0);
		assert.deepEqual(h.chains()["DOCKER-USER"], [jump(CHAIN_B), "-j RETURN"]);
	} finally { h.dispose(); }
});

test("a missing DOCKER-USER chain fails before touching anything", { skip }, () => {
	const h = harness({ "DOCKER-USER": null });
	try {
		const result = h.run();
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /DOCKER-USER chain is missing/);
		assert.deepEqual(h.chains(), {});
	} finally { h.dispose(); }
});
