import { describe, expect, it } from "vitest";
import { readDeviceCode } from "../_shared/auth.ts";

describe("device poll credential selection", () => {
	it("uses the device code when the browser SDK sends a session JWT", async () => {
		const request = new Request("https://aidr.test/device-poll", {
			method: "POST", headers: { Authorization: "Bearer browser-jwt" },
			body: JSON.stringify({ device_code: "device-secret" }),
		});
		expect(await readDeviceCode(request)).toBe("device-secret");
	});
	it("supports native bearer device codes", async () => {
		expect(await readDeviceCode(new Request("https://aidr.test", {
			method: "POST", headers: { Authorization: "Bearer native-device" }, body: "{}",
		}))).toBe("native-device");
	});
	it.each(["", 123, null, "x".repeat(1025)])("rejects an invalid explicit code without falling back to a JWT", async (code) => {
		expect(await readDeviceCode(new Request("https://aidr.test", {
			method: "POST", headers: { Authorization: "Bearer jwt" }, body: JSON.stringify({ device_code: code }),
		}))).toBeNull();
	});
});
