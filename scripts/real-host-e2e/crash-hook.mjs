#!/usr/bin/env node
/**
 * Stand-in for an AIDR hook process that dies before it writes a verdict.
 *
 * The real-host E2E tier registers this in place of the AIDR hook to observe
 * what the host does with a hook process that is killed mid-call (the
 * `crashed-hook` condition of deploy/native/interception-matrix.json). It reads
 * the hook payload, leaves a proof-of-invocation line next to itself (so a run
 * can tell "hook crashed" from "hook never ran"), then SIGKILLs itself: no
 * stdout, no exit code the process chose.
 */
import { appendFileSync, readFileSync } from "node:fs";

const proof = process.env.AIDR_REAL_HOST_CRASH_PROOF;
let payload = "";
try {
	payload = readFileSync(0, "utf8");
} catch {
	// A crash probe never needs the payload; it only proves it was invoked.
}
if (proof) {
	let event = "unknown";
	try {
		event = JSON.parse(payload)?.hook_event_name ?? "unknown";
	} catch {
		// Unparseable payloads still count as an invocation.
	}
	appendFileSync(proof, `${JSON.stringify({ invoked: true, event })}\n`);
}
process.kill(process.pid, "SIGKILL");
