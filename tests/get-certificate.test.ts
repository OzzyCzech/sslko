import type { DetailedPeerCertificate } from "node:tls";
import { describe, expect, it } from "vitest";
import { getCertificate } from "../src/index.js";

describe("getCertificateInfo", () => {
	it("invalid certificate information", async () => {
		const cert = (await getCertificate(
			"expired.badssl.com",
		)) as DetailedPeerCertificate;

		expect(cert.valid_to).toBeDefined();
		expect(cert.valid_from).toBeDefined();
		expect(cert.subject).toBeDefined();
		expect(cert.issuer).toBeDefined();
		expect(cert.subjectaltname).toBeDefined();
		expect(cert.raw).toBeDefined();
	});

	it("reject invalid certificate", async () => {
		try {
			await getCertificate("expired.badssl.com", {
				rejectUnauthorized: true,
			});
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe("CERT_HAS_EXPIRED");
			expect(e.message).toContain("certificate has expired");
		}
	});

	it("reject due timeout", async () => {
		try {
			await getCertificate("google.com", {
				timeout: 1, // Set a very short timeout
			});
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe("TIMEOUT");
			expect(e.message).toContain(
				"Failed to connect to google.com:443 within 1ms",
			);
		}
	});
});
