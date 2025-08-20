import type { DetailedPeerCertificate } from "node:tls";
import { describe, expect, it } from "vitest";
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

	it("support IP addresses", () => {
		const cert = {
			subjectaltname: "DNS:google.com, IP Address: 192.168.1.1",
		} as DetailedPeerCertificate;

		expect(verifyHostname("google.com", cert)).toBe(true);
		expect(verifyHostname("192.168.1.1", cert)).toBe(true);
		expect(verifyHostname("192.168.1.2", cert)).toBe(false);
	});

	it("support IPv6 addresses", () => {
		const cert = {
			subjectaltname: "DNS:example.com, IP Address: ::1",
		} as DetailedPeerCertificate;

		expect(verifyHostname("example.com", cert)).toBe(true);
		expect(verifyHostname("::1", cert)).toBe(true);
		expect(verifyHostname("::2", cert)).toBe(false);
	});

	it("IP addresses don't match wildcards", () => {
		const cert = {
			subjectaltname: "DNS:*.example.com",
		} as DetailedPeerCertificate;

		expect(verifyHostname("sub.example.com", cert)).toBe(true);
		expect(verifyHostname("192.168.1.1", cert)).toBe(false);
	});
});
