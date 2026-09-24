// (0) Harness preflight: proves the plumbing every other scenario relies on
// before any product behaviour is judged. The extension's service worker is
// running, fixture origins are served by the route layer (never the network),
// anything else is refused, API calls are recorded with their bodies, and the
// leak detector finds a value that did go out.

import { waitFor } from "../lib/expect.mjs";
import { SITES } from "../lib/sites.mjs";

const PROBE = "preflight-probe-7f3c";

export default [
	{
		id: "preflight",
		title: "harness: extension loaded, fixtures routed, requests recorded, network sealed",
		async run({ h, checks, open }) {
			checks.must(
				"extension service worker is running",
				h.worker.url().startsWith(`chrome-extension://${h.extensionId}/`),
				h.worker.url(),
			);
			checks.check(
				"extension id looks like a Chrome extension id",
				/^[a-p]{32}$/.test(h.extensionId),
				h.extensionId,
			);

			// open() also waits for the content script's isolated world.
			const page = await open("chatgpt");
			checks.equal(
				"fixture is served for https://chatgpt.com",
				await page.evaluate(() => location.origin),
				SITES.chatgpt.origin,
			);

			const mark = h.recorder.mark();
			const reply = await page.evaluate(
				async ({ endpoint, probe }) => {
					const res = await fetch(endpoint, {
						method: "POST",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({ site: "chatgpt", prompt: `ping ${probe}` }),
					});
					return (await res.json()).reply;
				},
				{ endpoint: SITES.chatgpt.endpoint, probe: PROBE },
			);
			checks.contains("fake model answered through the route layer", reply, PROBE);
			const recorded = await waitFor(
				() => h.recorder.apiSince(mark, { site: "chatgpt", kind: "prompt" })[0],
				{
					timeout: 3000,
					message: "the probe request to be recorded",
				},
			).catch(() => null);
			checks.equal("recorder captured the JSON body", recorded?.json?.prompt, `ping ${PROBE}`);
			checks.check(
				"leak detector finds a value that was sent",
				h.recorder.leaks(mark, [PROBE]).length > 0,
				h.recorder.requests.slice(-3),
			);
			checks.check(
				"leak detector ignores a value that was not sent",
				h.recorder.leaks(mark, ["never-sent-value"]).length === 0,
			);

			const outside = await page.evaluate(async () => {
				try {
					await fetch("https://unrouted.invalid/exfil", { method: "POST", body: "x" });
					return "reached";
				} catch (error) {
					return `refused: ${error.message}`;
				}
			});
			checks.contains("non-fixture origins are refused (hermetic run)", outside, "refused");
		},
	},
];
