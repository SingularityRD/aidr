// (7) File upload: a CSV with emails reaches the page's upload handler masked; a DOCX with
// an e-mail and a TCKN split across formatted runs reaches it as a re-zipped DOCX whose
// document.xml holds placeholders; a PDF with sensitive data is blocked (PDFs are scanned,
// never rewritten) and the user is told to paste the text instead.

import { splitRunDocx, textPdf, unzip } from "../lib/documents.mjs";
import { staysFalse, waitFor } from "../lib/expect.mjs";
import { assertNoLeaks } from "../lib/harness.mjs";
import { SITES } from "../lib/sites.mjs";

const SITE = "chatgpt";
const DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/** Office/PDF handling is product behaviour the self-test extension does not implement. */
const productOnly = (_h, data) =>
	(data?.items ?? []).some((i) => i.type === "TC_KIMLIK")
		? null
		: "product feature (document sanitisation) not implemented by the self-test extension";

function itemValue(data, type) {
	const item = data.items.find((i) => i.type === type);
	if (!item) throw new Error(`test data has no ${type} item`);
	return item.value;
}

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
	{
		id: "file-upload-docx",
		title: "file upload: DOCX with split-run e-mail/TCKN is re-zipped with placeholders",
		settings: { mode: "auto" },
		skip: productOnly,
		async run({ h, checks, data, open }) {
			const email = itemValue(data, "EMAIL");
			const tckn = itemValue(data, "TC_KIMLIK");
			const page = await open(SITE);
			const mark = h.recorder.mark();
			await page.locator(SITES[SITE].fileInput).setInputFiles({
				name: "musteri-raporu.docx",
				mimeType: DOCX_TYPE,
				buffer: splitRunDocx(email, tckn),
			});

			const upload = await waitFor(() => h.recorder.apiSince(mark, { kind: "upload" })[0], {
				timeout: 10000,
				message: "the page to upload the selected DOCX",
			});
			checks.equal(
				"exactly one upload reached the page handler",
				h.recorder.apiSince(mark, { kind: "upload" }).length,
				1,
			);
			checks.equal("uploaded file keeps its name", upload.json?.name, "musteri-raporu.docx");
			checks.equal("uploaded file keeps its MIME type", upload.json?.type, DOCX_TYPE);
			let parts = new Map();
			try {
				parts = unzip(Buffer.from(upload.json?.bytesB64 ?? "", "base64"));
			} catch (error) {
				checks.check("uploaded DOCX is a readable ZIP", false, String(error));
			}
			const xml = parts.get("word/document.xml") ?? "";
			checks.check("uploaded DOCX has word/document.xml", xml.length > 0, [...parts.keys()]);
			checks.contains("document.xml contains an e-mail placeholder", xml, /\[EMAIL_\d+\]/);
			checks.contains("document.xml contains a TCKN placeholder", xml, /\[TCKN_\d+\]/);
			const at = email.indexOf("@");
			for (const fragment of [email, tckn, email.slice(0, at + 1), email.slice(at + 1), tckn.slice(0, 5)]) {
				checks.excludes(`document.xml does not contain "${fragment}"`, xml, fragment);
			}
			const all = [...parts.values()].join("\n");
			checks.excludes("no part of the uploaded DOCX holds the e-mail", all, email);
			checks.excludes("no part of the uploaded DOCX holds the TCKN", all, tckn);
			checks.contains("clean Turkish text is preserved", xml, "Bu satır temiz: çalışma planı.");
			checks.contains("run formatting is preserved", xml, "<w:b/>");
			assertNoLeaks(checks, h, mark, [email, tckn]);
		},
	},
	{
		id: "file-upload-pdf-blocked",
		title: "file upload: a PDF with sensitive data is blocked with a paste-instead hint",
		settings: { mode: "auto" },
		skip: productOnly,
		async run({ h, checks, data, open }) {
			const email = itemValue(data, "EMAIL");
			const page = await open(SITE);
			const baseline = await h.overlays(page, SITE);
			const mark = h.recorder.mark();
			await page.locator(SITES[SITE].fileInput).setInputFiles({
				name: "sozlesme.pdf",
				mimeType: "application/pdf",
				buffer: textPdf(["Sozlesme taraflari", `E-posta: ${email}`]),
			});
			const bubble = await waitFor(
				async () =>
					(await h.overlays(page, SITE)).find(
						(o) => !baseline.includes(o) && o.includes("SENSITIVE_DATA_IN_PDF"),
					),
				{ timeout: 10000, message: "a bubble explaining the blocked PDF" },
			).catch(() => null);
			checks.check("a bubble names SENSITIVE_DATA_IN_PDF", bubble, await h.overlays(page, SITE));
			checks.contains("the bubble suggests pasting the text instead", bubble ?? "", /paste/i);
			let quiet = true;
			await staysFalse(() => h.recorder.apiSince(mark, { kind: "upload" }).length > 0, {
				window: 1500,
				message: "a PDF upload",
			}).catch(() => {
				quiet = false;
			});
			checks.check("the PDF never reached the page's upload handler", quiet, h.recorder.apiSince(mark));
			assertNoLeaks(checks, h, mark, [email]);
		},
	},
];
