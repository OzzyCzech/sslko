import { describe, expect, it } from "bun:test";
import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import {
	checkCertificateSecurity,
	isSelfSignedCertificate,
	validateCertificateStructure,
} from "../src/index.js";

function makeCert(
	overrides: Partial<PeerCertificate> = {},
): PeerCertificate {
	return {
		subject: { CN: "example.com" },
		issuer: { CN: "Test CA", O: "Test CA Inc" },
		valid_from: "Jan 1 00:00:00 2025 GMT",
		valid_to: "Dec 31 23:59:59 2026 GMT",
		subjectaltname: "DNS:example.com",
		fingerprint: "AA:BB:CC",
		fingerprint256: "AA:BB:CC:DD",
		serialNumber: "01",
		...overrides,
	} as unknown as PeerCertificate;
}

describe("isSelfSignedCertificate", () => {
	it("detects self-signed certificate", () => {
		const cert = makeCert({
			subject: { CN: "Self", O: "Org", OU: undefined, C: "US", ST: "CA", L: "LA" },
			issuer: { CN: "Self", O: "Org", OU: undefined, C: "US", ST: "CA", L: "LA" },
		});
		expect(isSelfSignedCertificate(cert)).toBe(true);
	});

	it("returns false when CN matches but O differs", () => {
		const cert = makeCert({
			subject: { CN: "example.com", O: "My Company" },
			issuer: { CN: "example.com", O: "Different CA" },
		});
		expect(isSelfSignedCertificate(cert)).toBe(false);
	});

	it("returns false for normal CA-signed certificate", () => {
		const cert = makeCert({
			subject: { CN: "example.com", O: "My Company" },
			issuer: { CN: "DigiCert", O: "DigiCert Inc" },
		});
		expect(isSelfSignedCertificate(cert)).toBe(false);
	});

	it("returns false when subject is missing", () => {
		const cert = makeCert({ subject: undefined as unknown as PeerCertificate["subject"] });
		expect(isSelfSignedCertificate(cert)).toBe(false);
	});

	it("returns false when issuer is missing", () => {
		const cert = makeCert({ issuer: undefined as unknown as PeerCertificate["issuer"] });
		expect(isSelfSignedCertificate(cert)).toBe(false);
	});
});

describe("validateCertificateStructure", () => {
	it("returns no warnings for valid certificate", () => {
		expect(validateCertificateStructure(makeCert())).toEqual([]);
	});

	it("warns about missing subject", () => {
		const cert = makeCert({ subject: undefined as unknown as PeerCertificate["subject"] });
		const warnings = validateCertificateStructure(cert);
		expect(warnings).toContain("Certificate is missing subject information");
	});

	it("warns about missing CN", () => {
		const cert = makeCert({ subject: { CN: undefined as unknown as string } });
		const warnings = validateCertificateStructure(cert);
		expect(warnings).toContain("Certificate does not have a Common Name (CN)");
	});

	it("warns about missing issuer", () => {
		const cert = makeCert({ issuer: undefined as unknown as PeerCertificate["issuer"] });
		const warnings = validateCertificateStructure(cert);
		expect(warnings).toContain("Certificate is missing issuer information");
	});

	it("warns about missing SANs", () => {
		const cert = makeCert({ subjectaltname: undefined });
		const warnings = validateCertificateStructure(cert);
		expect(warnings).toContain(
			"Certificate does not have Subject Alternative Names (SANs)",
		);
	});

	it("accumulates multiple warnings", () => {
		const cert = makeCert({
			subject: undefined as unknown as PeerCertificate["subject"],
			issuer: undefined as unknown as PeerCertificate["issuer"],
			subjectaltname: undefined,
		});
		expect(validateCertificateStructure(cert).length).toBe(3);
	});
});

describe("checkCertificateSecurity", () => {
	it("returns no warnings for secure certificate", () => {
		expect(checkCertificateSecurity(makeCert())).toEqual([]);
	});

	it("warns about weak RSA key size", () => {
		const cert = {
			...makeCert(),
			// 1024-bit key = 256 hex chars
			modulus: "AA".repeat(128),
			exponent: "0x10001",
		} as unknown as DetailedPeerCertificate;
		const warnings = checkCertificateSecurity(cert);
		expect(warnings.length).toBe(1);
		expect(warnings[0]).toContain("weak RSA key size");
		expect(warnings[0]).toContain("1024");
	});

	it("accepts strong RSA key size", () => {
		const cert = {
			...makeCert(),
			// 2048-bit key = 512 hex chars
			modulus: "AA".repeat(256),
			exponent: "0x10001",
		} as unknown as DetailedPeerCertificate;
		expect(checkCertificateSecurity(cert)).toEqual([]);
	});

	it("warns about SHA1 signature algorithm", () => {
		const cert = {
			...makeCert(),
			signatureAlgorithm: "sha1WithRSAEncryption",
		} as unknown as DetailedPeerCertificate;
		const warnings = checkCertificateSecurity(cert);
		expect(warnings.length).toBe(1);
		expect(warnings[0]).toContain("weak signature algorithm");
	});

	it("warns about MD5 signature algorithm", () => {
		const cert = {
			...makeCert(),
			signatureAlgorithm: "md5WithRSAEncryption",
		} as unknown as DetailedPeerCertificate;
		const warnings = checkCertificateSecurity(cert);
		expect(warnings[0]).toContain("md5WithRSAEncryption");
	});

	it("accepts SHA256 signature algorithm", () => {
		const cert = {
			...makeCert(),
			signatureAlgorithm: "sha256WithRSAEncryption",
		} as unknown as DetailedPeerCertificate;
		expect(checkCertificateSecurity(cert)).toEqual([]);
	});
});
