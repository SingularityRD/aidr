/**
 * node --test sibling for the lifecycle lock in deploy/fleet/unix/aidr-fleet.sh.
 *
 * The lock must exclude a concurrent lifecycle run while its owner is alive, and
 * must not block every future run after its owner was SIGKILLed or the host
 * rebooted. Each case runs the real script under bash in its non-root test-root
 * mode; the "install" action fails right after it takes the lock (no artifact is
 * supplied), which is enough to observe whether the lock was acquired.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const engine = join(dirname(fileURLToPath(import.meta.url)), "aidr-fleet.sh");
const gitBash = "C:\\Program Files\\Git\\bin\\bash.exe";
const bash = process.platform === "win32" && existsSync(gitBash) ? gitBash : "bash";
const probe = spawnSync(bash, ["-c", "echo ok"], { encoding: "utf8" });
const skip = probe.status === 0 && probe.stdout.trim() === "ok" ? false : "bash is required to run the fleet lifecycle script";
const toBash = (path) => process.platform === "win32"
	? path.replace(/^([A-Za-z]):/, (_match, drive) => `/${drive.toLowerCase()}`).replaceAll("\\", "/")
	: path;

const BUSY = "another AIDR fleet lifecycle operation is active";
const ACQUIRED = "required file missing";
const RECOVERED = "recovered a stale lifecycle lock";

// $1 work dir, $2 engine, $3 node, $4 scenario. The scenario seeds the lock
// (possibly with a live holder process), then runs the engine once.
const HARNESS = String.raw`
set -u
work=$1 engine=$2 node=$3 scenario=$4
lock="$work/install/.fleet-operation.lock"
mkdir -p "$work/home" "$work/install" "$work/state"
start_of() { [ -r "/proc/$1/stat" ] && sed 's/^.*) //' "/proc/$1/stat" | awk '{print $20}'; }
owner() { mkdir -p "$lock"; printf 'pid=%s\nboot_id=%s\nstart_time=%s\ncreated=fixture\n' "$1" "$2" "$3" > "$lock/owner"; }
holder=
case "$scenario" in
	free) ;;
	dead) ( exit 0 ) & dead=$!; wait "$dead"; owner "$dead" current-boot "" ;;
	live) sleep 60 & holder=$!; owner "$holder" current-boot "$(start_of "$holder")" ;;
	reused) sleep 60 & holder=$!; [ -r "/proc/$holder/stat" ] || { kill "$holder"; echo "SKIP no /proc start time"; exit 0; }; owner "$holder" current-boot "0" ;;
	previous-boot) sleep 60 & holder=$!; owner "$holder" previous-boot "$(start_of "$holder")" ;;
	fresh-no-owner) mkdir -p "$lock" ;;
	old-no-owner) mkdir -p "$lock"; touch -t 202001010000 "$lock" ;;
	abandoned-guard) ( exit 0 ) & dead=$!; wait "$dead"; owner "$dead" current-boot ""; mkdir -p "$lock.recovery"; touch -t 202001010000 "$lock.recovery" ;;
	fresh-guard) ( exit 0 ) & dead=$!; wait "$dead"; owner "$dead" current-boot ""; mkdir -p "$lock.recovery" ;;
esac
AIDR_FLEET_TEST_ROOT="$work" AIDR_FLEET_TEST_BOOT_ID=current-boot AIDR_NODE_BIN="$node" AIDR_FLEET_PLATFORM=linux \
	bash "$engine" install --user fixture-user --home "$work/home" --install-root "$work/install" --state-root "$work/state"
status=$?
[ -z "$holder" ] || kill "$holder" 2>/dev/null
exit "$status"
`;

function scenario(name) {
	const work = mkdtempSync(join(tmpdir(), "aidr-fleet-lock-"));
	try {
		const lock = join(work, "install", ".fleet-operation.lock");
		const result = spawnSync(bash, ["-c", HARNESS, "harness", toBash(work), toBash(engine), toBash(process.execPath), name], { encoding: "utf8", timeout: 60_000 });
		const before = existsSync(join(lock, "owner")) ? readFileSync(join(lock, "owner"), "utf8") : null;
		return {
			status: result.status,
			stdout: result.stdout,
			stderr: result.stderr,
			lockExists: existsSync(lock),
			owner: before,
			leftovers: existsSync(join(work, "install")) ? readdirSync(join(work, "install")).filter((entry) => entry.startsWith(".fleet-operation.lock")) : [],
		};
	} finally {
		rmSync(work, { recursive: true, force: true });
	}
}

function assertAcquired(result, { recovered }) {
	assert.notEqual(result.status, 0, result.stderr);
	assert.ok(result.stderr.includes(ACQUIRED), `lock should have been acquired; stderr: ${result.stderr}`);
	assert.ok(!result.stderr.includes(BUSY), result.stderr);
	assert.equal(result.stderr.includes(RECOVERED), recovered, result.stderr);
	assert.equal(result.lockExists, false, "the lock is released on exit");
	assert.deepEqual(result.leftovers, [], "no tombstone or recovery guard is left behind");
}

function assertBlocked(result) {
	assert.notEqual(result.status, 0);
	assert.ok(result.stderr.includes(BUSY), `lock should have blocked; stderr: ${result.stderr}`);
	assert.ok(!result.stderr.includes(RECOVERED), result.stderr);
	assert.equal(result.lockExists, true, "a held lock is never removed by a contender");
}

test("an uncontended lock is taken and released", { skip }, () => {
	assertAcquired(scenario("free"), { recovered: false });
});

test("a lock whose owner pid is dead is recovered", { skip }, () => {
	assertAcquired(scenario("dead"), { recovered: true });
});

test("a lock held by a live process blocks and is left untouched", { skip }, () => {
	const result = scenario("live");
	assertBlocked(result);
	assert.match(result.owner ?? "", /^boot_id=current-boot$/m, "the holder's owner record is preserved");
});

test("a live pid whose start time differs (pid reuse) is recovered", { skip }, (t) => {
	const result = scenario("reused");
	if (result.stdout.includes("SKIP")) return t.skip("no /proc process start time on this platform");
	assertAcquired(result, { recovered: true });
});

test("a lock from a previous boot is recovered even if its pid is alive now", { skip }, () => {
	assertAcquired(scenario("previous-boot"), { recovered: true });
});

test("a fresh lock without an owner record blocks (owner may still be writing it)", { skip }, () => {
	assertBlocked(scenario("fresh-no-owner"));
});

test("a lock without an owner record older than the grace period is recovered", { skip }, () => {
	assertAcquired(scenario("old-no-owner"), { recovered: true });
});

test("an abandoned recovery guard is cleared and the stale lock recovered", { skip }, () => {
	assertAcquired(scenario("abandoned-guard"), { recovered: true });
});

test("a fresh recovery guard (another contender recovering) blocks", { skip }, () => {
	const result = scenario("fresh-guard");
	assertBlocked(result);
	assert.ok(result.leftovers.includes(".fleet-operation.lock.recovery"), "another contender's guard is not removed");
});

test("the script source keeps the lock recovery invariants", () => {
	const source = readFileSync(engine, "utf8");
	assert.match(source, /mv "\$LOCK_DIR" "\$tombstone"/, "stale locks are renamed to a tombstone before removal");
	assert.doesNotMatch(source, /rm -rf "\$LOCK_DIR"/, "a lock directory is never removed in place");
	assert.match(source, /if \[ "\$\(lock_owner_pid\)" = "\$\$" \]; then rm -f/, "release only removes a lock this process owns");
});
