import { describe, expect, it } from "vitest";
import { CertificateErrorCode, getCertificateWithTls } from "../src/index.js";

describe("getCertificate", () => {
	it("expired certificate", async () => {
		try {
			await getCertificateWithTls("expired.badssl.com");
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe(CertificateErrorCode.CERT_HAS_EXPIRED);
			expect(e.message).toContain("certificate has expired");
		}
	});

	it("revoked certificate", async () => {
		try {
			await getCertificateWithTls("revoked.badssl.com");
		} catch (error) {
			console.log(error);
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe(CertificateErrorCode.CERT_HAS_EXPIRED);
			expect(e.message).toContain("certificate has expired");
		}
	});

	it("should timeouted", async () => {
		try {
			await getCertificateWithTls("expired.badssl.com", { timeout: 1 });
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe(CertificateErrorCode.TIMEOUT);
			expect(e.message).toContain("Connection timed out");
		}
	});

	it("http only (no certificate)", async () => {
		try {
			await getCertificateWithTls("neverssl.com");
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(e.code).toBe(CertificateErrorCode.CERT_ERROR);
			expect(e.message).toContain("No certificate information available");
		}
	});

	it("valid certificate", async () => {
		const cert = await getCertificateWithTls("google.com");
		expect(cert).toBeDefined();
		expect(cert.subject).toBeDefined();
		expect(cert.issuer).toBeDefined();
		expect(cert.valid_from).toBeDefined();
		expect(cert.valid_to).toBeDefined();
		expect(cert.subjectaltname).toBeDefined();
	});
});
