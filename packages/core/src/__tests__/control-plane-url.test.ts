import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import { controlPlaneUrl } from "../clients/control-plane-url.js";
import { ConfigSchema } from "../types.js";

afterEach(() => vi.unstubAllGlobals());
describe("control plane deployment routes", () => {
	it.each([
		["https://aidr.example", "https://aidr.example/v1/ingest"],
		["https://aidr.example/v1/", "https://aidr.example/v1/ingest"],
		["https://project.supabase.co/functions/v1", "https://project.supabase.co/functions/v1/ingest"],
		["http://127.0.0.1:8000/functions/v1/", "http://127.0.0.1:8000/functions/v1/ingest"],
	])("resolves %s", (base, expected) => {
		expect(controlPlaneUrl(base, "ingest")).toBe(expected);
	});
	it("uses the configured Supabase route for native device authorization", async () => {
		const fetcher = vi
			.fn()
			.mockResolvedValue(new Response(JSON.stringify({ device_code: "device" })));
		vi.stubGlobal("fetch", fetcher);
		const config = ConfigSchema.parse({
			control_plane: { endpoint: "https://tenant.example/functions/v1" },
		});
		const client = new ControlPlaneClient(config.control_plane, "");
		expect((await client.deviceStart()).ok).toBe(true);
		expect(fetcher.mock.calls[0]?.[0]).toBe("https://tenant.example/functions/v1/device-start");
	});
	it("does not send device data to an unprovisioned default host", async () => {
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const client = new ControlPlaneClient(ConfigSchema.parse({}).control_plane, "");
		expect(await client.deviceStart()).toEqual({ ok: false, error: "missing_endpoint" });
		expect(fetcher).not.toHaveBeenCalled();
	});
	it("rejects plaintext control-plane endpoints", () => {
		const config = {
			...ConfigSchema.parse({}).control_plane,
			endpoint: "http://control.example.test",
		};
		expect(() => new ControlPlaneClient(config, "token")).toThrow(/must use HTTPS/);
	});
	it("allows loopback HTTP only with an explicit development opt-in", () => {
		const config = {
			...ConfigSchema.parse({}).control_plane,
			endpoint: "http://127.0.0.1:8000/functions/v1",
		};
		expect(() => new ControlPlaneClient(config, "token")).toThrow(/allow_insecure_loopback/);
		expect(
			() => new ControlPlaneClient({ ...config, allow_insecure_loopback: true }, "token"),
		).not.toThrow();
		expect(
			() =>
				new ControlPlaneClient(
					{ ...config, endpoint: "http://127.attacker.test", allow_insecure_loopback: true },
					"token",
				),
		).toThrow(/must use HTTPS/);
	});
});
