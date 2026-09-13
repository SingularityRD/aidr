// Diagnostic-only hook RSS sampler. The measurement run includes this preload's overhead.
const { writeFileSync } = require("node:fs");

let peak = process.memoryUsage().rss;
const timer = setInterval(() => {
	peak = Math.max(peak, process.memoryUsage().rss);
}, 5);
timer.unref();
process.on("exit", () => {
	peak = Math.max(peak, process.memoryUsage().rss);
	if (process.env.AIDR_RESOURCE_RSS_OUTPUT) {
		writeFileSync(process.env.AIDR_RESOURCE_RSS_OUTPUT, String(peak), { flag: "wx", mode: 0o600 });
	}
});
