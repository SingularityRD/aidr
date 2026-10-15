/**
 * Timestamps for people: the stored values stay ISO-8601 UTC (scripts and the
 * `--json` output keep them), but a person in Istanbul should read 17:29, not
 * 14:29Z. The offset is printed so the time is never ambiguous.
 */
function pad(value: number): string {
	return String(value).padStart(2, "0");
}

/** `2026-10-13 17:29:33 (UTC+3)` in the machine's time zone; the input when it is not a date. */
export function localTime(iso: string): string {
	const date = new Date(iso);
	if (!iso || Number.isNaN(date.getTime())) return iso;
	const offset = -date.getTimezoneOffset();
	const sign = offset < 0 ? "-" : "+";
	const hours = Math.floor(Math.abs(offset) / 60);
	const minutes = Math.abs(offset) % 60;
	const zone = offset === 0 ? "UTC" : `UTC${sign}${hours}${minutes ? `:${pad(minutes)}` : ""}`;
	return (
		`${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ` +
		`${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())} (${zone})`
	);
}
