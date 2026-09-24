// (7) File upload: a CSV with emails reaches the page's upload handler masked.

import { waitFor } from "../lib/expect.mjs";
import { assertNoLeaks } from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

const SITE = "chatgpt";

export default [
	{
		id: "file-upload-csv",
		title: "file upload: CSV with emails is masked before the page reads it",
		settings: { mode: "auto" },
		async run({ h, checks, data, open }) {
			const page = await open(SITE);
			const mark = h.recorder.mark();
			await page.locator(SITES[SITE].fileInput).setInputFiles({
				name: "customers.csv",
				mimeType: "text/csv",
				buffer: Buffer.from(data.csv, "utf8"),
			});

			const upload = await waitFor(() => h.recorder.apiSince(mark, { kind: "upload" })[0], {
				timeout: 8000,
				message: "the page to upload the selected file",
			});
			const content = upload.json?.content ?? "";
			checks.equal(
				"exactly one upload reached the page handler",
				h.recorder.apiSince(mark, { kind: "upload" }).length,
				1,
			);
			for (const item of data.csvItems) {
				checks.excludes(`uploaded CSV does not contain ${item.value}`, content, item.value);
			}
			checks.contains("uploaded CSV contains email placeholders", content, /\[EMAIL_\d+\]/);
			checks.contains("CSV structure (header row) is preserved", content, /^name,email/);
			checks.check(
				"uploaded file keeps a .csv name",
				/\.csv$/i.test(upload.json?.name ?? ""),
				upload.json?.name,
			);
			assertNoLeaks(
				checks,
				h,
				mark,
				data.csvItems.map((i) => i.value),
			);
		},
	},
];
