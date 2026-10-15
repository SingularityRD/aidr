/**
 * PII masking quality regression: a TR/EN corpus of prompts a customer actually pastes
 * (labelled forms, free text, pasted tables/JSON, secrets) plus benign controls, run through
 * the Browser Guard engine with the shipped default policy.
 *
 * Every sensitive value must be masked unless it is listed in KNOWN_GAPS, and every benign
 * control must survive untouched. A closed gap fails too, so the list stays honest: remove
 * the entry when a detector learns it. Values are synthetic; checksums are generated.
 */
import { describe, expect, it } from "vitest";
import { DEFAULT_POLICY } from "../background/policy.js";
import { createDetectionEngine } from "../engine/detect.js";
import type { Finding } from "../types.js";

// Credential-shaped values are assembled at runtime so repository secret scanners skip them.
const AWS_ID = `AKIA${"IOSFODNN7EXAMPLE"}`;
const AWS_SECRET = `wJalrXUtnFEMI${"/K7MDENG/bPxRfiCY"}EXAMPLEKEY`;
const SLACK = `xox${"b-"}123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx`;
const STRIPE = `sk_${"live_"}51HxYzABCDEFGHIJKLMNOPQRSTUV`;
const GOOGLE = `AIza${"SyD-"}1234567890abcdefghijklmnopqrstu`;
const ANTHROPIC = `sk-${"ant-api03-"}abcdefghijklmnopqrstuvwxyz0123456789`;
const AZURE = `Zm9vYmFyYmF6cXV4cXV1eGNv${"cmdlZ3JhdWx0Z2FycGx5d2FsZG8x"}MjM0NTY3OA==`;

function tckn(seed: string): string {
	const d = [...seed].map(Number); // 9 digits, first non-zero
	const odd = d[0] + d[2] + d[4] + d[6] + d[8],
		even = d[1] + d[3] + d[5] + d[7];
	d.push((((odd * 7 - even) % 10) + 10) % 10);
	d.push(d.reduce((a, b) => a + b, 0) % 10);
	return d.join("");
}
function iban(cc: string, bban: string): string {
	const r = bban + cc + "00";
	let rem = 0;
	for (const c of r)
		for (const x of c >= "A" && c <= "Z" ? String(c.charCodeAt(0) - 55) : c)
			rem = (rem * 10 + Number(x)) % 97;
	return cc + String(98 - rem).padStart(2, "0") + bban;
}
function luhn(prefix: string): string {
	for (let c = 0; c < 10; c++) {
		const s = prefix + c;
		let sum = 0,
			tw = false;
		for (let i = s.length - 1; i >= 0; i--) {
			let d = +s[i];
			if (tw) {
				d *= 2;
				if (d > 9) d -= 9;
			}
			sum += d;
			tw = !tw;
		}
		if (sum % 10 === 0) return s;
	}
	throw 0;
}
function vkn(seed: string): string {
	// TR tax id (10 digits) checksum
	const d = [...seed].map(Number);
	let sum = 0;
	for (let i = 0; i < 9; i++) {
		const t = (d[i] + 9 - i) % 10;
		let v = (t * 2 ** (9 - i)) % 9;
		if (t !== 0 && v === 0) v = 9;
		sum += v;
	}
	return seed + String((10 - (sum % 10)) % 10);
}
const T1 = tckn("123456789"),
	T2 = tckn("345678912"),
	T3 = tckn("567891234");
const IB = iban("TR", "0006200000012345678900");
const IBs = IB.replace(/(.{4})/g, "$1 ").trim();
const CC = luhn("454360000000001"),
	CCs = CC.replace(/(.{4})/g, "$1 ").trim();
const VKN = vkn("123456789");

type Case = { id: string; cat: string; text: string; pii: string[]; keep?: string[] };
const C: Case[] = [
	// --- labelled (should be strong)
	{
		id: "lab-tr",
		cat: "labelled",
		text: `Ad Soyad: Mehmet Kaya\nTCKN: ${T1}\nTelefon: 0532 111 22 33\nE-posta: mehmet.kaya@firma.com.tr\nIBAN: ${IBs}`,
		pii: ["Mehmet Kaya", T1, "0532 111 22 33", "mehmet.kaya@firma.com.tr", IBs],
	},
	{
		id: "lab-en",
		cat: "labelled",
		text: `Name: Sarah Johnson\nEmail: sarah.j@acme.io\nPhone: +1 415 555 0134\nSSN: 123-45-6789`,
		pii: ["Sarah Johnson", "sarah.j@acme.io", "+1 415 555 0134", "123-45-6789"],
	},
	// --- free-text names (the hard part)
	{
		id: "name-tr-1",
		cat: "free-name",
		text: "Müşterimiz Ayşe Demir dün aradı, siparişi hâlâ gelmemiş. Ona nasıl bir özür maili yazayım?",
		pii: ["Ayşe Demir"],
		keep: ["siparişi", "özür maili"],
	},
	{
		id: "name-tr-2",
		cat: "free-name",
		text: "Ahmet Yılmaz'ın performans değerlendirmesini özetle: hedeflerin %60'ını tutturdu.",
		pii: ["Ahmet Yılmaz"],
	},
	{
		id: "name-tr-3",
		cat: "free-name",
		text: "Bu e-postayı Zeynep Arslan ve Can Öztürk'e iletmem gerekiyor, daha kibar yaz.",
		pii: ["Zeynep Arslan", "Can Öztürk"],
	},
	{
		id: "name-tr-4",
		cat: "free-name",
		text: "Hasta Fatma Şahin, 54 yaşında, tip 2 diyabet ve hipertansiyon tanılı.",
		pii: ["Fatma Şahin"],
	},
	{
		id: "name-en-1",
		cat: "free-name",
		text: "Please draft a termination letter for John Smith, effective next Monday.",
		pii: ["John Smith"],
	},
	{
		id: "name-en-2",
		cat: "free-name",
		text: "Summarize the complaint from Emily Clarke about the delayed refund.",
		pii: ["Emily Clarke"],
	},
	{
		id: "name-sayin",
		cat: "free-name",
		text: "Sayın Hakan Çelik, başvurunuz alınmıştır.",
		pii: ["Hakan Çelik"],
	},
	{
		id: "name-hanim",
		cat: "free-name",
		text: "Elif Hanım'a ve Murat Bey'e toplantı davetini gönder.",
		pii: ["Elif", "Murat"],
	},
	// --- identifiers in free text
	{
		id: "tckn-free",
		cat: "free-id",
		text: `Müşterinin kimlik numarası ${T2} olarak kayıtlı, kontrol eder misin?`,
		pii: [T2],
	},
	{ id: "tckn-suffix", cat: "free-id", text: `${T3}'li kaydı sil.`, pii: [T3] },
	{
		id: "phone-nospace",
		cat: "free-id",
		text: "Beni 05321234567 numarasından arayabilirsiniz.",
		pii: ["05321234567"],
	},
	{
		id: "phone-no0",
		cat: "free-id",
		text: "Cep: 532 123 45 67, ofis 212 555 66 77",
		pii: ["532 123 45 67", "212 555 66 77"],
	},
	{
		id: "phone-intl",
		cat: "free-id",
		text: "WhatsApp: +90 (532) 123-45-67",
		pii: ["+90 (532) 123-45-67"],
	},
	{ id: "phone-suffix", cat: "free-id", text: "0533 444 55 66'yı ara", pii: ["0533 444 55 66"] },
	{ id: "iban-free", cat: "free-id", text: `Ödemeyi ${IB} hesabına yaptım.`, pii: [IB] },
	{ id: "iban-lower", cat: "free-id", text: `iban ${IB.toLowerCase()}`, pii: [IB.toLowerCase()] },
	{
		id: "cc-free",
		cat: "free-id",
		text: `Kartım ${CCs}, son kullanma 08/27, CVV 123`,
		pii: [CCs, "123"],
	},
	{
		id: "vkn-free",
		cat: "free-id",
		text: `Firmanın vergi numarası ${VKN}, Kadıköy VD.`,
		pii: [VKN],
	},
	{
		id: "email-suffix",
		cat: "free-id",
		text: "ali.veli@gmail.com'a cevap yaz",
		pii: ["ali.veli@gmail.com"],
	},
	{
		id: "email-obf",
		cat: "free-id",
		text: "mail adresim ali.veli at gmail dot com",
		pii: ["ali.veli"],
	},
	{
		id: "dob-free",
		cat: "free-id",
		text: "15.03.1985 doğumlu, İstanbul nüfusuna kayıtlı.",
		pii: ["15.03.1985"],
	},
	{
		id: "plate",
		cat: "free-id",
		text: "Aracın plakası 34 ABC 123, diğeri 06AB1234.",
		pii: ["34 ABC 123", "06AB1234"],
	},
	{
		id: "passport",
		cat: "free-id",
		text: "Pasaport numarası U12345678 olan yolcu.",
		pii: ["U12345678"],
	},
	// --- addresses
	{
		id: "addr-tr-1",
		cat: "address",
		text: "Teslimat: Atatürk Cad. No:12 D:5 Kadıköy/İstanbul",
		pii: ["Atatürk Cad. No:12 D:5"],
	},
	{
		id: "addr-tr-2",
		cat: "address",
		text: "Bağdat Caddesi 123/4 Suadiye'de oturuyor.",
		pii: ["Bağdat Caddesi 123/4"],
	},
	{
		id: "addr-tr-3",
		cat: "address",
		text: "Adresi Moda Mahallesi, Şair Nefi Sokak No 7 Kadıköy.",
		pii: ["Moda Mahallesi", "Şair Nefi Sokak No 7"],
	},
	{
		id: "addr-en",
		cat: "address",
		text: "Ship it to 742 Evergreen Terrace, Springfield.",
		pii: ["742 Evergreen Terrace"],
	},
	// --- table / CSV / JSON pastes (very common in POCs)
	{
		id: "csv",
		cat: "structured",
		text: `ad,soyad,tckn,telefon\nAhmet,Yılmaz,${T1},05321112233\nAyşe,Kara,${T2},05439998877`,
		pii: ["Ahmet", "Yılmaz", T1, "05321112233", "Ayşe", "Kara", T2, "05439998877"],
	},
	{
		id: "tsv-en",
		cat: "structured",
		text: "first_name\tlast_name\temail\nMichael\tBrown\tmbrown@corp.com",
		pii: ["Michael", "Brown", "mbrown@corp.com"],
	},
	{
		id: "json",
		cat: "structured",
		text: `{"customer":{"fullName":"Deniz Aydın","tc":"${T3}","gsm":"5051234567"}}`,
		pii: ["Deniz Aydın", T3, "5051234567"],
	},
	{
		id: "md-table",
		cat: "structured",
		text: `| Ad | Telefon |\n|---|---|\n| Burak Koç | 0542 765 43 21 |`,
		pii: ["Burak Koç", "0542 765 43 21"],
	},
	// --- secrets
	{
		id: "sec-aws",
		cat: "secret",
		text: `AWS_ACCESS_KEY_ID=${AWS_ID}\nAWS_SECRET_ACCESS_KEY=${AWS_SECRET}`,
		pii: [AWS_ID, AWS_SECRET],
	},
	{
		id: "sec-dburl",
		cat: "secret",
		text: "DATABASE_URL=postgres://admin:S3cr3tPass!@db.internal:5432/prod",
		pii: ["S3cr3tPass!"],
	},
	{ id: "sec-slack", cat: "secret", text: `token: ${SLACK}`, pii: [SLACK] },
	{
		id: "sec-stripe",
		cat: "secret",
		text: `const stripe = require('stripe')('${STRIPE}');`,
		pii: [STRIPE],
	},
	{ id: "sec-google", cat: "secret", text: `GOOGLE_MAPS_KEY = "${GOOGLE}"`, pii: [GOOGLE] },
	{
		id: "sec-anthropic",
		cat: "secret",
		text: `export ANTHROPIC_API_KEY=${ANTHROPIC}`,
		pii: [ANTHROPIC],
	},
	{ id: "sec-pw-tr", cat: "secret", text: "Wifi şifresi: Kedi2024!Mavi", pii: ["Kedi2024!Mavi"] },
	{
		id: "sec-pw-yaml",
		cat: "secret",
		text: "spring:\n  datasource:\n    password: Prod#Pass2025",
		pii: ["Prod#Pass2025"],
	},
	{
		id: "sec-azure",
		cat: "secret",
		text: `DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=${AZURE};EndpointSuffix=core.windows.net`,
		pii: [AZURE],
	},
	// --- false-positive controls (should be untouched)
	{
		id: "fp-code",
		cat: "fp",
		text: "interface User { name: string; email: string; phone?: number }",
		pii: [],
		keep: ["name: string", "email: string"],
	},
	{
		id: "fp-numbers",
		cat: "fp",
		text: "Sipariş no 20240512 için 1.250,00 TL ödendi; build 1712345678901, v2.14.3",
		pii: [],
		keep: ["20240512", "1.250,00", "1712345678901", "v2.14.3"],
	},
	{
		id: "fp-uuid",
		cat: "fp",
		text: "request id 550e8400-e29b-41d4-a716-446655440000 and commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
		pii: [],
		keep: ["550e8400-e29b-41d4-a716-446655440000", "9fceb02d0ae598e95dc970b74767f19372d61af8"],
	},
	{
		id: "fp-prose",
		cat: "fp",
		text: "Merhaba, bu raporu daha kısa ve profesyonel bir dille yeniden yazar mısın? Toplantı saat 14:30'da.",
		pii: [],
		keep: ["raporu", "14:30"],
	},
	{
		id: "fp-public",
		cat: "fp",
		text: "Mustafa Kemal Atatürk 1881'de doğdu. Elon Musk Tesla'nın CEO'sudur.",
		pii: [],
		keep: ["Atatürk", "Tesla"],
	},
	{
		id: "fp-ip-version",
		cat: "fp",
		text: "Python 3.11.4 ve Node 22.16.0 kullanıyoruz, localhost:8080",
		pii: [],
		keep: ["3.11.4", "22.16.0"],
	},
	{
		id: "fp-code-token",
		cat: "fp",
		text: "const token = getToken();\nconst API_KEY = process.env.API_KEY;\nlet accessKey: string;\nCACHE_KEY=users",
		pii: [],
		keep: ["getToken()", "process.env.API_KEY", "accessKey: string", "CACHE_KEY=users"],
	},
	{
		id: "fp-prose-token",
		cat: "fp",
		text: "The token: it expires after one hour. Parolanız: en az 8 karakter olmalı.",
		pii: [],
		keep: ["it expires"],
	},
	{
		id: "fp-pkgjson",
		cat: "fp",
		text: '{"name": "my-app", "version": "1.0.0", "author": "Acme"}',
		pii: [],
		keep: ["my-app"],
	},
	{
		id: "fp-csv-pkg",
		cat: "fp",
		text: "name,version\nreact,18.2.0\nvite,5.0.1",
		pii: [],
		keep: ["react", "vite"],
	},
	{
		id: "fp-md-pkg",
		cat: "fp",
		text: "| Name | Version |\n|---|---|\n| lodash | 4.17.21 |",
		pii: [],
		keep: ["lodash"],
	},
	{
		id: "fp-max-tokens",
		cat: "fp",
		text: '{"model": "gpt-4o", "max_tokens": 1024, "temperature": 0.2}',
		pii: [],
		keep: ["1024", "gpt-4o"],
	},
];

/**
 * Leaks we know about (case id -> values). Free-text names need the NER layer: the rule
 * engine only sees names after a label, a title or a self-introduction.
 */
const KNOWN_GAPS: Readonly<Record<string, readonly string[]>> = {
	"name-tr-1": ["Ayşe Demir"],
	"name-tr-2": ["Ahmet Yılmaz"],
	"name-tr-3": ["Zeynep Arslan", "Can Öztürk"],
	"name-tr-4": ["Fatma Şahin"],
	"name-en-1": ["John Smith"],
	"name-en-2": ["Emily Clarke"],
	"name-hanim": ["Elif", "Murat"],
	"email-obf": ["ali.veli"],
	plate: ["06AB1234"],
	"addr-en": ["742 Evergreen Terrace"],
};

function masked(text: string, findings: readonly Finding[]): string {
	let out = "";
	let pos = 0;
	for (const f of [...findings].sort((a, b) => a.start - b.start)) {
		if (f.start < pos) continue;
		out += `${text.slice(pos, f.start)}[${f.type}]`;
		pos = f.end;
	}
	return out + text.slice(pos);
}

describe("PII masking quality corpus (default policy)", () => {
	const engine = createDetectionEngine({
		enabledEntities: DEFAULT_POLICY.enabledEntities,
		literals: [],
		exactData: [],
		detectSignals: false,
		maxInputChars: 200_000,
		maxScanMs: 5_000,
	});

	for (const c of C) {
		it(`${c.cat}: ${c.id}`, async () => {
			const result = await engine.scan(c.text);
			expect(result.incomplete).toBe(false);
			const out = masked(c.text, result.findings);
			const leaked = c.pii.filter((value) => out.includes(value));
			expect(leaked).toEqual(KNOWN_GAPS[c.id] ?? []);
			for (const value of c.keep ?? []) expect(out).toContain(value);
		});
	}
});
