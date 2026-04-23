import { describe, expect, it } from "bun:test";
import type { DetailedPeerCertificate } from "node:tls";
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
		// RFC 5737 TEST-NET-1 — guaranteed not to route, so the timeout
		// fires before any TLS handshake can race us.
		// Node 25+ may reject the IP immediately with ERR_INVALID_ARG_VALUE.
		try {
			await getCertificate("192.0.2.1", {
				timeout: 50,
			});
			expect.unreachable("should have thrown");
		} catch (error) {
			const e = error as { code?: string; message?: string };
			expect(["TIMEOUT", "ERR_INVALID_ARG_VALUE"]).toContain(e.code);
		}
	});
});
