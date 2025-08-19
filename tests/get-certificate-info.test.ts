import { describe, expect, it } from "vitest";
import { getCertificateInfo } from "../src/index.js";

describe("getCertificateInfo", () => {
	it("expired certificate", async () => {
		const cert = await getCertificateInfo("expired.badssl.com");

		expect(cert.valid).toBe(false);
		expect(cert.expired).toBe(true);
		expect(cert.validToDate).toBeDefined();
		expect(cert.validFromDate).toBeDefined();
		expect(cert.subject).toBeDefined();
		expect(cert.issuer).toBeDefined();
		expect(cert.subjectaltname).toBeDefined();
		expect(cert.raw).toBeDefined();
		expect(cert.errors).toBeDefined();
		expect(cert.errors.length).toBeGreaterThan(0);
	});

	it("invalid host certificate", async () => {
		const cert = await getCertificateInfo("wrong.host.badssl.com");
		expect(cert.valid).toBe(false);
		expect(cert.errors).toBeDefined();
		expect(cert.errors.length).toBeGreaterThan(0);
	});

	it("self-signed certificate", async () => {
		const cert = await getCertificateInfo("self-signed.badssl.com");

		expect(cert.valid).toBe(false);
		expect(cert.errors.length).toBeGreaterThan(0);
		expect(cert.validToDate).toBeDefined();
		expect(cert.validFromDate).toBeDefined();
		expect(cert.subject).toBeDefined();
		expect(cert.issuer).toBeDefined();
		expect(cert.subjectaltname).toBeDefined();
	});

	it("valid certificate", async () => {
		const cert = await getCertificateInfo("google.com");

		expect(cert.valid).toBe(true);
		expect(cert.expired).toBe(false);
		expect(cert.errors.length).toBe(0);
		expect(cert.validToDate).toBeDefined();
		expect(cert.validFromDate).toBeDefined();
		expect(cert.subject).toBeDefined();
		expect(cert.issuer).toBeDefined();
		expect(cert.subjectaltname).toBeDefined();
	});
});
