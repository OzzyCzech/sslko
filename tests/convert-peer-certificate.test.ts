import { describe, expect, it } from "bun:test";
import type { DetailedPeerCertificate } from "node:tls";
import { convertPeerCertificate } from "../src/index.js";

function makeCert(
	overrides: Record<string, unknown> = {},
): DetailedPeerCertificate {
	return {
		subject: { CN: "example.com" },
		issuer: { CN: "Test CA" },
		valid_from: "Jan 1 00:00:00 2025 GMT",
		valid_to: "Dec 31 23:59:59 2026 GMT",
		subjectaltname: "DNS:example.com, DNS:www.example.com",
		pubkey: Buffer.from("test-pubkey"),
		raw: Buffer.from("test-raw"),
		fingerprint: "AA:BB:CC",
		fingerprint256: "AA:BB:CC:DD",
		serialNumber: "01",
		...overrides,
	} as unknown as DetailedPeerCertificate;
}

describe("convertPeerCertificate", () => {
	it("converts dates from strings to Date objects", () => {
		const result = convertPeerCertificate(makeCert());
		expect(result.validFromDate).toBeInstanceOf(Date);
		expect(result.validToDate).toBeInstanceOf(Date);
		expect(result.validFromDate.getFullYear()).toBe(2025);
		expect(result.validToDate.getFullYear()).toBe(2026);
	});

	it("calculates daysTotal correctly", () => {
		const result = convertPeerCertificate(
			makeCert({
				valid_from: "Jan 1 00:00:00 2025 GMT",
				valid_to: "Jan 11 00:00:00 2025 GMT",
			}),
		);
		expect(result.daysTotal).toBe(10);
	});

	it("marks expired certificates", () => {
		const result = convertPeerCertificate(
			makeCert({
				valid_to: "Jan 1 00:00:00 2020 GMT",
			}),
		);
		expect(result.expired).toBe(true);
		expect(result.daysLeft).toBeLessThan(0);
	});

	it("marks non-expired certificates", () => {
		const result = convertPeerCertificate(
			makeCert({
				valid_to: "Jan 1 00:00:00 2099 GMT",
			}),
		);
		expect(result.expired).toBe(false);
		expect(result.daysLeft).toBeGreaterThan(0);
	});

	it("extracts DNS SANs into validFor", () => {
		const result = convertPeerCertificate(
			makeCert({
				subjectaltname: "DNS:a.com, DNS:b.com, IP Address:1.2.3.4",
			}),
		);
		expect(result.validFor).toEqual(["a.com", "b.com", "1.2.3.4"]);
	});

	it("handles missing subjectaltname", () => {
		const result = convertPeerCertificate(
			makeCert({ subjectaltname: undefined }),
		);
		expect(result.validFor).toBeUndefined();
	});

	it("converts pubkey and raw to base64", () => {
		const result = convertPeerCertificate(makeCert());
		expect(result.pubkey).toBe(Buffer.from("test-pubkey").toString("base64"));
		expect(result.raw).toBe(Buffer.from("test-raw").toString("base64"));
	});

	it("handles non-Buffer pubkey and raw", () => {
		const result = convertPeerCertificate(
			makeCert({
				pubkey: "not-a-buffer" as unknown as Buffer,
				raw: "not-a-buffer" as unknown as Buffer,
			}),
		);
		expect(result.pubkey).toBeUndefined();
		expect(result.raw).toBeUndefined();
	});

	it("removes issuerCertificate to avoid circular references", () => {
		const cert = makeCert();
		cert.issuerCertificate = cert; // circular
		const result = convertPeerCertificate(cert);
		expect("issuerCertificate" in result).toBe(false);
	});
});
