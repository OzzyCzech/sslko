import { describe, expect, it } from "vitest";
import { CertificateErrorCode, getCertificateInfo } from "../src/index.js";

describe("getCertificateInfo", () => {
	it("invalid certificate information", async () => {
		const info = await getCertificateInfo("expired.badssl.com");

		expect(info.valid).toBe(false);
		expect(info.error).toBeDefined();
		expect(info.code).toBeDefined();
		expect(info.code).toBe(CertificateErrorCode.CERT_HAS_EXPIRED);
	});

	it("valid certificate information", async () => {
		const info = await getCertificateInfo("google.com");

		expect(info.valid).toBe(true);
		expect(info.error).toBeUndefined();
		expect(info.code).toBeUndefined();
		expect(info.subject).toBeDefined();
		expect(info.issuer).toBeDefined();
		expect(info.pubkey).toBeDefined();
		expect(info.raw).toBeDefined();
		expect(info.valid_from).toBeInstanceOf(Date);
		expect(info.valid_to).toBeInstanceOf(Date);
		expect(info.days_left).toBeGreaterThanOrEqual(0);
		expect(info.days_total).toBeGreaterThan(0);
	});
});
