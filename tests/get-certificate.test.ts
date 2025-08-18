import { describe, expect, it } from "vitest";
import { CertificateErrorCode, getCertificate } from "../src/index.js";

describe("getCertificate", () => {
	it("invalid certificate information", async () => {
		const info = await getCertificate("expired.badssl.com");

		expect(info.valid).toBe(false);
		expect(info.error).toBeDefined();
		expect(info.code).toBeDefined();
		expect(info.code).toBe(CertificateErrorCode.CERT_HAS_EXPIRED);
	});

	it("valid certificate information", async () => {
		const info = await getCertificate("google.com");

		expect(info.valid).toBe(true);
		expect(info.error).toBeUndefined();
		expect(info.code).toBeUndefined();
		expect(info.subject).toBeDefined();
		expect(info.issuer).toBeDefined();
		expect(info.pubkey).toBeDefined();
		expect(info.raw).toBeDefined();
		expect(info.validFrom).toBeInstanceOf(Date);
		expect(info.validTo).toBeInstanceOf(Date);
		expect(info.daysLeft).toBeGreaterThanOrEqual(0);
		expect(info.daysTotal).toBeGreaterThan(0);
	});
});
