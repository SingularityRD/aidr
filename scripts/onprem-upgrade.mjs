#!/usr/bin/env node
/**
 * One-command upgrade of a self-hosted (Docker Compose) AIDR installation.
 *
 *   node scripts/onprem-upgrade.mjs --to /srv/aidr-target            (pnpm onprem:upgrade --to ...)
 *   node scripts/onprem-upgrade.mjs --to /srv/aidr-target --dry-run  (print the plan, run nothing)
 *   node scripts/onprem-upgrade.mjs --to /srv/aidr-target --resume   (continue an interrupted upgrade)
 *
 * It composes the existing tools and never reimplements them:
 *
 *   1 check      scripts/deployment-upgrade.mjs check     version and compatibility (read-only)
 *   2 backup     scripts/deployment-backup.mjs backup      encrypted cold backup
 *   3 verify     scripts/deployment-backup.mjs verify      backup verification
 *   4 preflight  scripts/deployment-upgrade.mjs preflight  hash, contract and backup binding
 *   5 apply      scripts/deployment-upgrade.mjs apply      atomic migrations + install, which
 *   6 restart                                              also restarts the services and
 *   7 doctor     scripts/deployment-doctor.mjs --online    runs the doctor; the doctor is then rerun
 *   8 smoke      read-only post-upgrade checks             receipt binding, doctor evidence, dashboard
 *
 * It stops at the first failed step, says in English or Turkish what happened
 * and prints the exact recovery step. It never restores automatically: the
 * upgrade tool already restarts the previous services when a failure happens
 * before the schema commit; after the commit a restore always goes into a new,
 * separate installation and needs the operator's approval before users are
 * moved (deploy/UPGRADE.md, "Failure and recovery").
 *
 * The run writes `<current>/.aidr-upgrade/onprem-upgrade-receipt.json`.
 */
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { selectLanguage } from "./lib/onprem-language.mjs";

const here = dirname(fileURLToPath(import.meta.url));

export const STAGES = Object.freeze(["check", "backup", "verify", "preflight", "apply", "restart", "doctor", "smoke"]);

const DEFAULTS = Object.freeze({
	current: "/srv/aidr",
	contract: "/secure/aidr-upgrade/upgrade-compatibility.json",
	keyFile: "/secure/aidr-recovery.key",
	backupRoot: "/backups",
	recoveryJournal: "/var/lib/aidr-backup/recovery-journal.json",
});

const STATE_DIR = ".aidr-upgrade";
const RECEIPT_NAME = "onprem-upgrade-receipt.json";

const MESSAGES = {
	en: {
		title: (from, to) => `Singularity AIDR on-prem upgrade: ${from} -> ${to}`,
		stage: {
			check: "Check that the new release fits this installation",
			backup: "Take an encrypted backup (the services stop for the snapshot)",
			verify: "Verify the backup can be decrypted and is complete",
			preflight: "Final checks before the change (files, contract, backup)",
			apply: "Apply the database changes in one transaction and install the new files",
			restart: "Start the new version",
			doctor: "Run the health check (doctor)",
			smoke: "Post-upgrade checks (receipt, health evidence, dashboard answers)",
		},
		insideApply: "done by step 5",
		running: (n, total, label) => `\nStep ${n}/${total}: ${label}`,
		ok: "  OK",
		skipped: (why) => `  Skipped: ${why}`,
		reuseBackup: (path) => `the backup ${path} given with --backup is used`,
		resumeSkip: "continuing the earlier upgrade with --resume",
		dryRunHeader: "Dry run: nothing was started and nothing was changed. The upgrade would run these steps:",
		dryRunFooter: "Run the same command without --dry-run to upgrade.",
		problemsHeader: "The upgrade cannot start:",
		versions: (from, to, count) => `  Current ${from}, new ${to}; ${count} new database change(s).`,
		archived: (path) => `  The finished earlier upgrade record was moved to ${path}.`,
		success: (receipt) => `\nUpgrade complete. The new version is running and passed the health check.\nReceipt: ${receipt}\nStill to do by you: sign in as an administrator, enroll a test device, check that a blocked action is blocked and export the audit log.`,
		failedAt: (n, total, label) => `\nThe upgrade stopped at step ${n}/${total}: ${label}`,
		reason: (text) => `What went wrong: ${text}`,
		installation: "Your installation:",
		nextStep: "What to do now:",
		noAutoRestore: "No automatic restore is attempted: a restore always goes into a separate, new installation and needs your approval before users are moved.",
		receiptAt: (path) => `Record of this run: ${path}`,
		interrupted: "The upgrade was stopped safely because it received a stop signal.",
		unchanged: "Nothing was changed. The current version keeps running.",
		backupUnchanged: "The upgrade did not start and the installation was not changed. The backup tool restarts the services it stopped.",
		backupServices: (cmd) => `If some services are still stopped, start exactly the ones that were running with:\n  ${cmd}`,
		badBackup: (path) => `Do not use the backup in ${path}.`,
		rerun: (cmd) => `Fix the reason above, then run the same command again:\n  ${cmd}`,
		rerunWithBackup: (cmd) => `Fix the reason above, then run again. To reuse the backup that was just verified (allowed for 24 hours) add --backup:\n  ${cmd}`,
		preCommit: "The database was not changed and the previous version was started again.",
		resume: (cmd) => `Fix the reason above, then continue where it stopped:\n  ${cmd}`,
		unknownCommit: "The database change may or may not have been saved. Keep users away from the system (keep traffic drained) and do not copy old files back.",
		postCommit: "The database is already on the new version, so going back means restoring the backup.",
		tryResumeFirst: (cmd) => `First, check the service logs (docker compose --project-directory <current> logs), fix the cause and continue:\n  ${cmd}`,
		restore: (cmd, plan) => `If it cannot be fixed, restore the verified backup into a new, separate installation (the plan is in ${plan}):\n  ${cmd}\nThen start it on its own, run the doctor there, check sign-in, enrollment, a blocked action and the audit export, and only then move users. Guide: docs/operations/onprem-upgrade.md#if-the-upgrade-fails`,
		recoveryRuntime: "<clean directory prepared from the CURRENT (old) release>",
		installedButUnhealthy: "The new version is installed and running, but a check after the upgrade failed.",
		rerunDoctor: (cmd) => `Fix the FAIL lines above and run the health check again:\n  ${cmd}`,
		smokeOnly: (cmd) => `Then confirm with:\n  ${cmd}`,
		usage: "Usage: node scripts/onprem-upgrade.mjs --to <prepared release directory> [--current /srv/aidr] [--contract <file>] [--key-file <file>] [--backup-root <dir> | --backup <verified backup dir>] [--recovery-journal <file>] [--recovery-output <dir>] [--max-backup-age-hours N] [--dry-run] [--resume] [--lang en|tr]",
		problem: {
			missingTo: "--to <prepared release directory> is required.",
			missingCurrent: (path) => `The current installation ${path} has no deployment.json. Pass --current <dir>.`,
			missingTarget: (path) => `The new release ${path} has no deployment.json. Prepare it first with scripts/deployment-prepare.mjs --output ${path}.`,
			sameDir: "The new release directory is the live installation. Prepare the new release in a separate directory (for example /srv/aidr-target) and pass that with --to.",
			nested: "The new release directory and the live installation are inside each other. Use two separate directories.",
			targetLive: (path) => `${path} has already been used as a running installation (it has health or upgrade records). Prepare the new release in a fresh directory.`,
			missingFile: (label, path, flag) => `The ${label} ${path} does not exist. Pass ${flag} <file>.`,
			missingDir: (path) => `The backup folder ${path} does not exist. Create it (install -d -m 0700 ${path}) or pass --backup-root <dir>.`,
			badAge: "--max-backup-age-hours must be a number above 0 and at most 168.",
			resumeWithBackup: "--resume continues with the backup recorded by the earlier run; do not pass --backup.",
		},
		label: { contract: "compatibility contract", key: "backup key file", backup: "backup" },
		stateBusy: "Another upgrade is running for this installation (its lock is held). Wait for it to finish.",
		stateUnfinished: (status, phase, cmd) => `An earlier upgrade of this installation did not finish (status ${status}, last step ${phase}). Continue it with:\n  ${cmd}`,
		stateOtherTarget: (path) => `The unfinished earlier upgrade was for ${path}. Finish or recover that upgrade first (docs/operations/onprem-upgrade.md).`,
		nothingToResume: "There is no unfinished upgrade to continue. Run without --resume.",
		alreadyComplete: "That upgrade has already completed; the checks below confirm the installed version.",
		smokeReceipt: "The upgrade receipt does not match the installed release.",
		smokeDoctor: "The health check record is missing, failed or older than this run.",
		smokeDashboard: (status) => `The dashboard did not answer with its page (${status}).`,
		childFailed: (label, code) => `${label} exited with ${code}. Its own messages are shown above.`,
		childNoStart: (label) => `${label} could not be started.`,
	},
	tr: {
		title: (from, to) => `Singularity AIDR kurum içi güncelleme: ${from} -> ${to}`,
		stage: {
			check: "Yeni sürümün bu kuruluma uyduğunu kontrol et",
			backup: "Şifreli yedek al (yedek sırasında servisler durur)",
			verify: "Yedeğin açılabildiğini ve eksiksiz olduğunu doğrula",
			preflight: "Değişiklik öncesi son kontroller (dosyalar, uyumluluk sözleşmesi, yedek)",
			apply: "Veritabanı değişikliklerini tek seferde uygula ve yeni dosyaları kur",
			restart: "Yeni sürümü başlat",
			doctor: "Sağlık kontrolünü (doctor) çalıştır",
			smoke: "Güncelleme sonrası kontroller (kayıt, sağlık kaydı, panelin yanıt vermesi)",
		},
		insideApply: "5. adımda yapılır",
		running: (n, total, label) => `\nAdım ${n}/${total}: ${label}`,
		ok: "  Tamam",
		skipped: (why) => `  Atlandı: ${why}`,
		reuseBackup: (path) => `--backup ile verilen ${path} yedeği kullanılıyor`,
		resumeSkip: "önceki güncellemeye --resume ile devam ediliyor",
		dryRunHeader: "Deneme çalıştırması: hiçbir şey başlatılmadı ve hiçbir şey değiştirilmedi. Güncelleme şu adımları çalıştırır:",
		dryRunFooter: "Güncellemek için aynı komutu --dry-run olmadan çalıştırın.",
		problemsHeader: "Güncelleme başlatılamıyor:",
		versions: (from, to, count) => `  Mevcut ${from}, yeni ${to}; ${count} yeni veritabanı değişikliği.`,
		archived: (path) => `  Tamamlanmış önceki güncelleme kaydı ${path} konumuna taşındı.`,
		success: (receipt) => `\nGüncelleme tamamlandı. Yeni sürüm çalışıyor ve sağlık kontrolünden geçti.\nKayıt: ${receipt}\nSizin yapmanız gerekenler: yönetici olarak giriş yapın, bir deneme cihazı kaydedin, engellenmesi gereken bir işlemin engellendiğini görün ve denetim kaydını dışa aktarın.`,
		failedAt: (n, total, label) => `\nGüncelleme ${n}/${total}. adımda durdu: ${label}`,
		reason: (text) => `Ne oldu: ${text}`,
		installation: "Kurulumunuzun durumu:",
		nextStep: "Şimdi ne yapmalı:",
		noAutoRestore: "Otomatik geri yükleme yapılmaz: geri yükleme her zaman ayrı, yeni bir kuruluma yapılır ve kullanıcılar taşınmadan önce sizin onayınızı gerektirir.",
		receiptAt: (path) => `Bu çalıştırmanın kaydı: ${path}`,
		interrupted: "Güncelleme bir durdurma sinyali aldığı için güvenli şekilde durduruldu.",
		unchanged: "Hiçbir şey değiştirilmedi. Mevcut sürüm çalışmaya devam ediyor.",
		backupUnchanged: "Güncelleme başlamadı ve kurulum değiştirilmedi. Yedek aracı durdurduğu servisleri yeniden başlatır.",
		backupServices: (cmd) => `Bazı servisler hâlâ duruyorsa, yalnızca daha önce çalışanları şu komutla başlatın:\n  ${cmd}`,
		badBackup: (path) => `${path} içindeki yedeği kullanmayın.`,
		rerun: (cmd) => `Yukarıdaki nedeni giderin, ardından aynı komutu yeniden çalıştırın:\n  ${cmd}`,
		rerunWithBackup: (cmd) => `Yukarıdaki nedeni giderin ve yeniden çalıştırın. Az önce doğrulanan yedeği (24 saat içinde) yeniden kullanmak için --backup ekleyin:\n  ${cmd}`,
		preCommit: "Veritabanı değiştirilmedi ve önceki sürüm yeniden başlatıldı.",
		resume: (cmd) => `Yukarıdaki nedeni giderin, ardından kaldığı yerden devam edin:\n  ${cmd}`,
		unknownCommit: "Veritabanı değişikliğinin kaydedilip kaydedilmediği bilinmiyor. Kullanıcıları sistemden uzak tutun (trafiği kapalı tutun) ve eski dosyaları geri kopyalamayın.",
		postCommit: "Veritabanı zaten yeni sürümde; geri dönmek yedeğin geri yüklenmesi anlamına gelir.",
		tryResumeFirst: (cmd) => `Önce servis kayıtlarına bakın (docker compose --project-directory <mevcut> logs), nedeni giderin ve devam edin:\n  ${cmd}`,
		restore: (cmd, plan) => `Giderilemiyorsa, doğrulanmış yedeği yeni ve ayrı bir kuruluma geri yükleyin (plan: ${plan}):\n  ${cmd}\nArdından onu tek başına başlatın, orada doctor'ı çalıştırın; giriş, cihaz kaydı, engellenen işlem ve denetim kaydı dışa aktarımını kontrol edin ve kullanıcıları ancak bundan sonra taşıyın. Rehber: docs/operations/onprem-upgrade.tr.md#guncelleme-basarisiz-olursa`,
		recoveryRuntime: "<MEVCUT (eski) sürümden hazırlanmış temiz dizin>",
		installedButUnhealthy: "Yeni sürüm kuruldu ve çalışıyor, ancak güncelleme sonrası bir kontrol başarısız oldu.",
		rerunDoctor: (cmd) => `Yukarıdaki FAIL satırlarını giderin ve sağlık kontrolünü yeniden çalıştırın:\n  ${cmd}`,
		smokeOnly: (cmd) => `Ardından şu komutla doğrulayın:\n  ${cmd}`,
		usage: "Kullanım: node scripts/onprem-upgrade.mjs --to <hazırlanmış sürüm dizini> [--current /srv/aidr] [--contract <dosya>] [--key-file <dosya>] [--backup-root <dizin> | --backup <doğrulanmış yedek dizini>] [--recovery-journal <dosya>] [--recovery-output <dizin>] [--max-backup-age-hours N] [--dry-run] [--resume] [--lang en|tr]",
		problem: {
			missingTo: "--to <hazırlanmış sürüm dizini> gereklidir.",
			missingCurrent: (path) => `Mevcut kurulum ${path} içinde deployment.json yok. --current <dizin> verin.`,
			missingTarget: (path) => `Yeni sürüm ${path} içinde deployment.json yok. Önce scripts/deployment-prepare.mjs --output ${path} ile hazırlayın.`,
			sameDir: "Yeni sürüm dizini, çalışan kurulumun kendisi. Yeni sürümü ayrı bir dizinde hazırlayın (örneğin /srv/aidr-target) ve onu --to ile verin.",
			nested: "Yeni sürüm dizini ile çalışan kurulum iç içe. İki ayrı dizin kullanın.",
			targetLive: (path) => `${path} daha önce çalışan bir kurulum olarak kullanılmış (sağlık veya güncelleme kayıtları var). Yeni sürümü boş bir dizinde hazırlayın.`,
			missingFile: (label, path, flag) => `${label} ${path} bulunamadı. ${flag} <dosya> verin.`,
			missingDir: (path) => `Yedek klasörü ${path} yok. Oluşturun (install -d -m 0700 ${path}) veya --backup-root <dizin> verin.`,
			badAge: "--max-backup-age-hours 0'dan büyük ve en fazla 168 olmalıdır.",
			resumeWithBackup: "--resume önceki çalıştırmanın kaydettiği yedekle devam eder; --backup vermeyin.",
		},
		label: { contract: "Uyumluluk sözleşmesi", key: "Yedek anahtar dosyası", backup: "Yedek" },
		stateBusy: "Bu kurulum için başka bir güncelleme çalışıyor (kilidi tutuyor). Bitmesini bekleyin.",
		stateUnfinished: (status, phase, cmd) => `Bu kurulumun önceki bir güncellemesi tamamlanmadı (durum ${status}, son adım ${phase}). Şu komutla devam edin:\n  ${cmd}`,
		stateOtherTarget: (path) => `Tamamlanmamış önceki güncelleme ${path} içindi. Önce o güncellemeyi bitirin veya geri yükleyin (docs/operations/onprem-upgrade.tr.md).`,
		nothingToResume: "Devam edilecek tamamlanmamış bir güncelleme yok. --resume olmadan çalıştırın.",
		alreadyComplete: "Bu güncelleme zaten tamamlanmış; aşağıdaki kontroller kurulu sürümü doğrular.",
		smokeReceipt: "Güncelleme kaydı kurulu sürümle eşleşmiyor.",
		smokeDoctor: "Sağlık kontrolü kaydı yok, başarısız ya da bu çalıştırmadan eski.",
		smokeDashboard: (status) => `Panel kendi sayfasıyla yanıt vermedi (${status}).`,
		childFailed: (label, code) => `${label} ${code} koduyla çıktı. Kendi mesajları yukarıda.`,
		childNoStart: (label) => `${label} başlatılamadı.`,
	},
};

class StageError extends Error {
	constructor(message, details = {}) {
		super(message);
		this.name = "StageError";
		Object.assign(this, details);
	}
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const inside = (child, parent) => child === parent || child.startsWith(`${parent}${sep}`);
const quoteArg = (value) => (/^[A-Za-z0-9_./:=@%+-]+$/.test(String(value)) ? String(value) : `'${String(value).replaceAll("'", "'\\''")}'`);
const commandText = (argv) => argv.map(quoteArg).join(" ");

function realOrResolved(path) {
	try {
		return realpathSync(path);
	} catch {
		return resolve(path);
	}
}

function versionOf(summary) {
	const tag = typeof summary?.dashboard_image === "string" ? summary.dashboard_image.split(":").at(-1) : null;
	return tag && tag !== summary.dashboard_image ? tag : (summary?.source_commit ?? "?").slice(0, 12);
}

export function parseOptions(argv, env = process.env) {
	const { values } = parseArgs({
		args: argv,
		allowPositionals: false,
		options: {
			to: { type: "string" },
			current: { type: "string" },
			contract: { type: "string" },
			"key-file": { type: "string" },
			"backup-root": { type: "string" },
			backup: { type: "string" },
			"recovery-journal": { type: "string" },
			"recovery-output": { type: "string" },
			"max-backup-age-hours": { type: "string" },
			"dry-run": { type: "boolean", default: false },
			resume: { type: "boolean", default: false },
			lang: { type: "string" },
			help: { type: "boolean", default: false },
		},
	});
	return {
		to: values.to ? resolve(values.to) : null,
		current: resolve(values.current ?? env.AIDR_DEPLOYMENT_DIR ?? DEFAULTS.current),
		contract: resolve(values.contract ?? DEFAULTS.contract),
		keyFile: resolve(values["key-file"] ?? DEFAULTS.keyFile),
		backupRoot: resolve(values["backup-root"] ?? DEFAULTS.backupRoot),
		backup: values.backup ? resolve(values.backup) : null,
		recoveryJournal: resolve(values["recovery-journal"] ?? DEFAULTS.recoveryJournal),
		recoveryOutput: values["recovery-output"] ? resolve(values["recovery-output"]) : null,
		maxBackupAgeHours: values["max-backup-age-hours"] ?? null,
		dryRun: values["dry-run"],
		resume: values.resume,
		help: values.help,
		lang: selectLanguage(values.lang, env),
		explicit: new Set(Object.keys(values).filter((name) => values[name] !== undefined && values[name] !== false)),
	};
}

/** Reasons the upgrade must not start. Pure file-system checks; nothing is written. */
export function refusalReasons(options) {
	const m = MESSAGES[options.lang].problem;
	const label = MESSAGES[options.lang].label;
	const problems = [];
	if (!options.to) return [m.missingTo];
	const current = realOrResolved(options.current);
	const target = realOrResolved(options.to);
	if (current === target) problems.push(m.sameDir);
	else if (inside(current, target) || inside(target, current)) problems.push(m.nested);
	if (!existsSync(join(options.current, "deployment.json"))) problems.push(m.missingCurrent(options.current));
	if (current !== target) {
		if (!existsSync(join(options.to, "deployment.json"))) problems.push(m.missingTarget(options.to));
		else if (!options.resume && ["doctor-evidence.json", STATE_DIR].some((name) => existsSync(join(options.to, name)))) problems.push(m.targetLive(options.to));
	}
	if (options.maxBackupAgeHours !== null) {
		const hours = Number(options.maxBackupAgeHours);
		if (!Number.isFinite(hours) || hours <= 0 || hours > 168) problems.push(m.badAge);
	}
	if (!existsSync(options.contract)) problems.push(m.missingFile(label.contract, options.contract, "--contract"));
	if (!existsSync(options.keyFile)) problems.push(m.missingFile(label.key, options.keyFile, "--key-file"));
	if (options.resume && options.backup) problems.push(m.resumeWithBackup);
	else if (options.backup && !existsSync(join(options.backup, "backup.json"))) problems.push(m.missingFile(label.backup, join(options.backup, "backup.json"), "--backup"));
	else if (!options.resume && !options.backup && !existsSync(options.backupRoot)) problems.push(m.missingDir(options.backupRoot));
	return problems;
}

function upgradeArgs(options, action, backup) {
	return [
		action,
		"--current", options.current,
		"--target", options.to,
		...(action === "check" ? [] : ["--backup", backup, "--key-file", options.keyFile]),
		"--contract", options.contract,
		...(action !== "check" && options.recoveryOutput ? ["--recovery-output", options.recoveryOutput] : []),
		...(action !== "check" && options.maxBackupAgeHours !== null ? ["--max-backup-age-hours", options.maxBackupAgeHours] : []),
		...(["apply", "resume"].includes(action) ? ["--maintenance"] : []),
	];
}

function developmentInstall(options) {
	try {
		return readJson(join(options.current, "deployment.json")).development === true;
	} catch {
		return false;
	}
}

/** The ordered steps with the exact child command each one runs (null when it runs inside another step). */
export function buildPlan(options, { scriptsDir = here, backup = null, stamp = new Date() } = {}) {
	const backupDir = options.backup ?? backup ?? join(options.backupRoot, `aidr-pre-upgrade-${stamp.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z")}`);
	const node = process.execPath;
	const upgrade = join(scriptsDir, "deployment-upgrade.mjs");
	const backupTool = join(scriptsDir, "deployment-backup.mjs");
	const doctor = [node, join(scriptsDir, "deployment-doctor.mjs"), "--deployment", options.current, "--online", ...(developmentInstall(options) ? ["--development"] : [])];
	const reuse = Boolean(options.backup) || options.resume;
	return {
		backupDir,
		steps: [
			{ stage: "check", argv: options.resume ? null : [node, upgrade, ...upgradeArgs(options, "check", backupDir)] },
			{ stage: "backup", argv: reuse ? null : [node, backupTool, "backup", "--deployment", options.current, "--output", backupDir, "--key-file", options.keyFile, "--recovery-journal", options.recoveryJournal, "--maintenance"] },
			{ stage: "verify", argv: options.resume ? null : [node, backupTool, "verify", "--backup", backupDir, "--key-file", options.keyFile] },
			{ stage: "preflight", argv: options.resume ? null : [node, upgrade, ...upgradeArgs(options, "preflight", backupDir)] },
			{ stage: "apply", argv: [node, upgrade, ...upgradeArgs(options, options.resume ? "resume" : "apply", backupDir)] },
			{ stage: "restart", argv: null, inside: "apply" },
			{ stage: "doctor", argv: doctor },
			{ stage: "smoke", argv: null },
		],
	};
}

function selfCommand(options, extra = [], drop = []) {
	const args = ["node", "scripts/onprem-upgrade.mjs", "--to", options.to];
	const map = [
		["current", options.current],
		["contract", options.contract],
		["key-file", options.keyFile],
		["backup-root", options.backupRoot],
		["recovery-journal", options.recoveryJournal],
		["recovery-output", options.recoveryOutput],
		["max-backup-age-hours", options.maxBackupAgeHours],
		["lang", options.explicit.has("lang") ? options.lang : null],
	];
	for (const [flag, value] of map) {
		if (value !== null && value !== undefined && options.explicit.has(flag) && !drop.includes(flag)) args.push(`--${flag}`, value);
	}
	return commandText([...args, ...extra]);
}

export function runChildProcess(argv, { capture = false, env = process.env } = {}) {
	return new Promise((resolveChild) => {
		// stderr is passed through to the operator and its tail kept, so the
		// failure summary can quote the tool's own reason.
		const child = spawn(argv[0], argv.slice(1), { stdio: ["ignore", capture ? "pipe" : "inherit", "pipe"], env });
		let stdout = "";
		let stderr = "";
		if (capture) {
			child.stdout.setEncoding("utf8");
			child.stdout.on("data", (chunk) => {
				if (stdout.length < 1024 * 1024) stdout += chunk;
			});
		}
		child.stderr.setEncoding("utf8");
		child.stderr.on("data", (chunk) => {
			process.stderr.write(chunk);
			stderr = `${stderr}${chunk}`.slice(-16 * 1024);
		});
		child.on("error", () => resolveChild({ code: null, started: false, stdout, stderr }));
		child.on("close", (code, signal) => resolveChild({ code: code ?? signal, started: true, stdout, stderr }));
	});
}

/** The last `Error: ...` line a Node tool printed: its own reason for stopping. */
function errorReason(stderr) {
	const lines = String(stderr ?? "").split(/\r?\n/).map((line) => line.trim());
	const reason = lines.filter((line) => /^[A-Za-z]*Error: /.test(line)).at(-1);
	return reason ? reason.replace(/^[A-Za-z]*Error: /, "").slice(0, 400) : null;
}

function writeJsonAtomic(path, value) {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.${process.pid}.tmp`;
	writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
	renameSync(temporary, path);
}

function lockHeld(stateDir) {
	const lock = join(stateDir, "operation.lock");
	if (!existsSync(lock)) return false;
	try {
		const owner = readJson(lock);
		if (!Number.isInteger(owner.pid)) return false;
		process.kill(owner.pid, 0);
		return true;
	} catch (error) {
		return error?.code === "EPERM";
	}
}

/** Move a completed earlier upgrade's records under .aidr-upgrade/history/ so a new preflight can start. */
function archiveCompletedState(stateDir, completedAt) {
	const label = String(completedAt ?? new Date().toISOString()).replace(/[^0-9A-Za-z]/g, "");
	let destination = join(stateDir, "history", label);
	for (let index = 1; existsSync(destination); index += 1) destination = join(stateDir, "history", `${label}-${index}`);
	mkdirSync(destination, { recursive: true, mode: 0o700 });
	for (const name of readdirSync(stateDir)) {
		if (name === "history" || name === "operation.lock") continue;
		renameSync(join(stateDir, name), join(destination, name));
	}
	return destination;
}

function upgradeState(options) {
	const path = join(options.current, STATE_DIR, "state.json");
	return existsSync(path) ? readJson(path) : null;
}

/** Map the upgrade tool's recorded state after a failed apply to the step that failed and what is safe now. */
function classifyApplyFailure(state) {
	if (!state) return { stage: "apply", situation: "pre-commit" };
	if (state.interrupted_by && !state.requires_restore) return { stage: "apply", situation: "interrupted" };
	if (state.last_completed_phase === "migration_running") return { stage: "apply", situation: "unknown-commit" };
	if (!state.requires_restore) return { stage: "apply", situation: "pre-commit" };
	const reason = String(state.last_error ?? "");
	if (reason.includes("online deployment doctor")) return { stage: "doctor", situation: "post-commit" };
	if (reason.includes("target service start")) return { stage: "restart", situation: "post-commit" };
	return { stage: "apply", situation: "post-commit" };
}

async function smoke(options, context, deps, t) {
	const failures = [];
	const installedPath = join(options.current, "deployment.json");
	const receiptPath = join(options.current, STATE_DIR, "upgrade-receipt.json");
	try {
		const receipt = readJson(receiptPath);
		const installed = readFileSync(installedPath);
		const manifest = JSON.parse(installed.toString("utf8"));
		if (
			receipt.installed_manifest_sha256 !== sha256(installed) ||
			(context.target && receipt.target_manifest_sha256 !== context.target.manifest_sha256) ||
			(context.target && manifest.source_commit !== context.target.source_commit) ||
			manifest.upgrade?.target_manifest_sha256 !== receipt.target_manifest_sha256
		) failures.push(t.smokeReceipt);
	} catch {
		failures.push(t.smokeReceipt);
	}
	try {
		const evidence = readJson(join(options.current, "doctor-evidence.json"));
		if (evidence.passed !== true || evidence.online !== true || !(Date.parse(evidence.checked_at) >= context.doctorStartedAt - 1000)) failures.push(t.smokeDoctor);
	} catch {
		failures.push(t.smokeDoctor);
	}
	try {
		const { dashboard_url: dashboardUrl } = readJson(installedPath);
		const response = await deps.fetch(new URL("/", dashboardUrl).href, { redirect: "manual", signal: AbortSignal.timeout(10_000) });
		const type = response.headers.get("content-type") ?? "";
		if (response.status !== 200 || !type.toLowerCase().includes("text/html")) failures.push(t.smokeDashboard(`HTTP ${response.status}`));
	} catch (error) {
		failures.push(t.smokeDashboard(error?.name ?? "no answer"));
	}
	if (failures.length) throw new StageError(failures.join(" "));
}

/**
 * Run the upgrade. `deps` lets tests replace the child runner, fetch, output and
 * the scripts directory; the defaults run the real tools.
 */
export async function runUpgrade(options, deps = {}) {
	const t = MESSAGES[options.lang];
	const out = deps.out ?? ((line) => process.stdout.write(`${line}\n`));
	const runChild = deps.runChild ?? runChildProcess;
	const env = deps.env ?? process.env;
	const scriptsDir = deps.scriptsDir ?? here;
	const resolvedDeps = { fetch: deps.fetch ?? globalThis.fetch };
	const now = deps.now ?? (() => Date.now());

	const problems = refusalReasons(options);
	if (problems.length) {
		out(t.problemsHeader);
		for (const problem of problems) out(`  - ${problem}`);
		return { status: "refused", exitCode: 2, problems };
	}

	// A resume must use exactly the backup the interrupted preflight bound.
	let resumeBackup = null;
	if (options.resume) {
		try {
			resumeBackup = upgradeState(options)?.paths?.backup ?? null;
		} catch {
			resumeBackup = null;
		}
	}
	const plan = buildPlan(options, { scriptsDir, backup: resumeBackup, stamp: new Date(now()) });
	const total = STAGES.length;
	const labelOf = (stage) => t.stage[stage];
	if (options.dryRun) {
		out(t.dryRunHeader);
		plan.steps.forEach((step, index) => {
			out(`  ${index + 1}. ${labelOf(step.stage)}`);
			if (step.argv) out(`     ${commandText(step.argv)}`);
			else if (step.inside) out(`     (${t.insideApply})`);
			else if (step.stage === "backup") out(`     (${options.resume ? t.resumeSkip : t.reuseBackup(plan.backupDir)})`);
			else if (["check", "verify", "preflight"].includes(step.stage)) out(`     (${t.resumeSkip})`);
		});
		out(t.dryRunFooter);
		return { status: "dry-run", exitCode: 0, plan };
	}

	let interrupted = null;
	const onSignal = (signal) => {
		interrupted ??= signal;
	};
	process.on("SIGINT", onSignal);
	process.on("SIGTERM", onSignal);

	const stateDir = join(options.current, STATE_DIR);
	const receiptPath = join(stateDir, RECEIPT_NAME);
	const startedAt = new Date(now()).toISOString();
	const results = [];
	const context = { target: null, current: null, backupDir: plan.backupDir, doctorStartedAt: 0 };
	let failure = null;
	let finalStage = null;

	const child = async (stage, argv, capture = false) => {
		const label = argv[1].split(/[\\/]/).at(-1);
		const result = await runChild(argv, { capture, env });
		if (!result.started) throw new StageError(t.childNoStart(label));
		if (result.code !== 0) {
			const reason = errorReason(result.stderr);
			throw new StageError(reason ? `${label}: ${reason}` : t.childFailed(label, result.code));
		}
		return result.stdout ?? "";
	};

	try {
		for (const [index, step] of plan.steps.entries()) {
			finalStage = step.stage;
			if (interrupted) throw new StageError(t.interrupted, { interrupted: true });
			out(t.running(index + 1, total, labelOf(step.stage)));
			const stageStart = new Date(now()).toISOString();
			let status = "passed";
			if (step.stage === "check" && options.resume) {
				// Once files are installed the live manifest is the target's, so the
				// pre-upgrade check no longer applies; `resume` rechecks its own
				// bindings (target, contract and backup hashes) from the saved state.
				if (lockHeld(stateDir)) throw new StageError(t.stateBusy, { situation: "unchanged" });
				const state = upgradeState(options);
				if (!state) throw new StageError(t.nothingToResume, { situation: "unchanged" });
				if (state.paths?.target !== options.to) throw new StageError(t.stateOtherTarget(state.paths?.target), { situation: "unchanged" });
				const target = readJson(join(options.to, "deployment.json"));
				context.target = { manifest_sha256: state.target_manifest_sha256, source_commit: target.source_commit, dashboard_image: target.dashboard_image ?? null, migrations: target.migrations?.length ?? null };
				out(t.skipped(state.status === "complete" ? t.alreadyComplete : t.resumeSkip));
				status = "skipped";
			} else if (step.stage === "check") {
				const summary = JSON.parse((await child("check", step.argv, true)).trim().split(/\r?\n/).at(-1));
				context.current = summary.current;
				context.target = summary.target;
				out(t.versions(versionOf(summary.current), versionOf(summary.target), summary.new_migrations.length));
				const state = summary.upgrade_state;
				if (lockHeld(stateDir)) throw new StageError(t.stateBusy, { situation: "unchanged" });
				if (state && state.status === "complete") {
					out(t.archived(archiveCompletedState(stateDir, upgradeState(options)?.completed_at)));
				} else if (state) {
					if (state.target && state.target !== options.to) throw new StageError(t.stateOtherTarget(state.target), { situation: "unchanged" });
					throw new StageError(t.stateUnfinished(state.status, state.last_completed_phase, selfCommand(options, ["--resume"], ["backup-root"])), { situation: "unchanged" });
				}
			} else if (!step.argv && step.stage === "restart") {
				const state = upgradeState(options);
				if (state?.status !== "complete") throw new StageError(t.childFailed("deployment-upgrade.mjs", state?.status ?? "?"), { situation: "post-commit" });
				out(t.skipped(t.insideApply));
				status = "passed-in-apply";
			} else if (step.stage === "smoke") {
				await smoke(options, context, resolvedDeps, t);
			} else if (!step.argv) {
				out(t.skipped(step.stage === "backup" && !options.resume ? t.reuseBackup(plan.backupDir) : t.resumeSkip));
				status = "skipped";
			} else {
				if (step.stage === "doctor") context.doctorStartedAt = now();
				try {
					await child(step.stage, step.argv);
				} catch (error) {
					if (step.stage === "apply") {
						const classified = classifyApplyFailure(upgradeState(options));
						finalStage = classified.stage;
						error.situation = classified.situation;
						if (classified.stage !== "apply") results.push({ stage: "apply", status: "passed", started_at: stageStart, finished_at: new Date(now()).toISOString() });
						if (classified.stage === "doctor") results.push({ stage: "restart", status: "passed-in-apply", started_at: stageStart, finished_at: new Date(now()).toISOString() });
					}
					throw error;
				}
			}
			if (status === "passed") out(t.ok);
			results.push({ stage: step.stage, status, started_at: stageStart, finished_at: new Date(now()).toISOString() });
		}
	} catch (error) {
		failure = { stage: finalStage, message: error.message, situation: error.situation ?? null, interrupted: Boolean(error.interrupted || interrupted) };
	} finally {
		process.off("SIGINT", onSignal);
		process.off("SIGTERM", onSignal);
	}

	const receipt = {
		schema_version: 1,
		kind: "aidr-onprem-upgrade-receipt",
		status: failure ? "failed" : "complete",
		started_at: startedAt,
		finished_at: new Date(now()).toISOString(),
		current: options.current,
		target: options.to,
		backup: context.backupDir,
		from: context.current,
		to: context.target,
		resumed: options.resume,
		stages: results,
		...(failure ? { failed_stage: failure.stage, reason: failure.message, interrupted: failure.interrupted } : {}),
		upgrade_receipt_sha256: existsSync(join(stateDir, "upgrade-receipt.json")) ? sha256(readFileSync(join(stateDir, "upgrade-receipt.json"))) : null,
		scope: "Local upgrade orchestration only. Administrator sign-in, enrollment, policy enforcement, audit export and traffic cutover are separate acceptance steps.",
	};
	let receiptWritten = null;
	if (existsSync(join(options.current, "deployment.json"))) {
		try {
			writeJsonAtomic(receiptPath, receipt);
			receiptWritten = receiptPath;
		} catch {
			// The installation directory may be read-only for this operator; the console output remains.
		}
	}

	if (!failure) {
		out(t.success(receiptWritten ?? "-"));
		return { status: "complete", exitCode: 0, receipt };
	}
	printFailure(options, plan, failure, t, out);
	if (receiptWritten) out(t.receiptAt(receiptWritten));
	return { status: "failed", exitCode: failure.interrupted ? 130 : 1, receipt, failure };
}

function printFailure(options, plan, failure, t, out) {
	const index = STAGES.indexOf(failure.stage);
	out(t.failedAt(index + 1, STAGES.length, t.stage[failure.stage]));
	out(t.reason(failure.message));
	out(t.installation);
	const resume = selfCommand(options, ["--resume"], ["backup-root"]);
	const doctor = commandText(["node", "scripts/deployment-doctor.mjs", "--deployment", options.current, "--online"]);
	const restoreCommand = commandText([
		"node", "scripts/deployment-upgrade.mjs", "recover",
		"--current", options.current, "--target", options.to,
		"--backup", plan.backupDir, "--key-file", options.keyFile, "--contract", options.contract,
		...(options.recoveryOutput ? ["--recovery-output", options.recoveryOutput] : []),
		"--recovery-runtime", t.recoveryRuntime, "--maintenance",
	]);
	const rollbackPlan = join(options.current, STATE_DIR, "rollback-plan.json");
	const lines = [];
	if (failure.situation === "unchanged") {
		// The reason already names the next step (resume, wait, or finish the other upgrade).
		lines.push(t.unchanged);
	} else if (failure.stage === "check") {
		lines.push(t.unchanged, t.nextStep, t.rerun(selfCommand(options)));
	} else if (failure.stage === "backup") {
		lines.push(t.backupUnchanged, t.nextStep, t.backupServices(commandText(["node", "scripts/deployment-backup.mjs", "recover-services", "--deployment", options.current, "--recovery-journal", options.recoveryJournal])), t.rerun(selfCommand(options)));
	} else if (failure.stage === "verify") {
		lines.push(t.unchanged, t.badBackup(plan.backupDir), t.nextStep, t.rerun(selfCommand(options, [], ["backup"])));
	} else if (failure.stage === "preflight") {
		lines.push(t.unchanged, t.nextStep, t.rerunWithBackup(selfCommand(options, ["--backup", plan.backupDir], ["backup", "backup-root"])));
	} else if (failure.interrupted || failure.situation === "interrupted") {
		lines.push(t.interrupted, t.nextStep, t.resume(resume));
	} else if (["apply", "restart", "doctor"].includes(failure.stage) && failure.situation === "pre-commit") {
		lines.push(t.preCommit, t.nextStep, t.resume(resume));
	} else if (failure.situation === "unknown-commit") {
		lines.push(t.unknownCommit, t.nextStep, t.restore(restoreCommand, rollbackPlan), t.noAutoRestore);
	} else if (["apply", "restart"].includes(failure.stage) || (failure.stage === "doctor" && failure.situation === "post-commit")) {
		lines.push(t.postCommit, t.nextStep, t.tryResumeFirst(resume), t.restore(restoreCommand, rollbackPlan), t.noAutoRestore);
	} else {
		lines.push(t.installedButUnhealthy, t.nextStep, t.rerunDoctor(doctor), t.smokeOnly(resume), t.restore(restoreCommand, rollbackPlan), t.noAutoRestore);
	}
	for (const line of lines.filter(Boolean)) out(line);
}

async function main() {
	let options;
	try {
		options = parseOptions(process.argv.slice(2));
	} catch (error) {
		const t = MESSAGES[selectLanguage(null)];
		process.stderr.write(`${error.message}\n${t.usage}\n`);
		process.exitCode = 2;
		return;
	}
	if (options.help) {
		process.stdout.write(`${MESSAGES[options.lang].usage}\n`);
		return;
	}
	const result = await runUpgrade(options);
	process.exitCode = result.exitCode;
}

const invokedPath = process.argv[1] ? realOrResolved(process.argv[1]) : null;
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) await main();

export { classifyApplyFailure };
