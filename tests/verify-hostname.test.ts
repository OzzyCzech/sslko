import { describe, expect, it } from "bun:test";
import type { DetailedPeerCertificate } from "node:tls";
import { verifyHostname } from "../src/index.js";

describe("verifyHostname", () => {
	it("exact hostname match", async () => {
		const result = verifyHostname("exact.match.com", {
			subject: {
				CN: "exact.match.com",
			},
		} as DetailedPeerCertificate);
		expect(result).toBe(true);
	});

	it("wildcard match", async () => {
		const cert = {
			subjectaltname: "DNS:*.wildcard.com",
		} as DetailedPeerCertificate;

		expect(verifyHostname("sub.wildcard.com", cert)).toBe(true);
		expect(verifyHostname("sub.sub.wildcard.com", cert)).toBe(false);
		expect(verifyHostname("wildcard.com", cert)).toBe(false);
		expect(verifyHostname("google.com", cert)).toBe(false);
	});

	it("multiple domains", () => {
		const cert = {
			subjectaltname: "DNS:google.com, DNS:youtube.com, DNS:ozana.cz",
		} as DetailedPeerCertificate;

		expect(verifyHostname("google.com", cert)).toBe(true);
		expect(verifyHostname("youtube.com", cert)).toBe(true);
		expect(verifyHostname("ozana.cz", cert)).toBe(true);
		expect(verifyHostname("example.com", cert)).toBe(false);
	});

	it("match IP addresses in SANs", () => {
		const cert = {
			subjectaltname: "DNS:google.com, IP Address:192.168.1.1",
		} as DetailedPeerCertificate;

		expect(verifyHostname("google.com", cert)).toBe(true);
		expect(verifyHostname("192.168.1.1", cert)).toBe(true);
		expect(verifyHostname("10.0.0.1", cert)).toBe(false);
	});
});
