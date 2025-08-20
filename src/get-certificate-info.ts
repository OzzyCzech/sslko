import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import { convertPeerCertificate } from "./convert-peer-certificate.js";
import { getCertificate } from "./get-certificate.js";
import type { CertificateInfo, GetCertificateOptions } from "./types.js";

/**
 * Verifies if the given hostname matches the Common Name (CN) or Subject Alternative Names (SANs) of the certificate.
 *
 * @param host The hostname to check.
 * @param cert The certificate to getCertificateInfo against.
 * @returns `true` if the hostname matches, otherwise `false`.
 */
export function verifyHostname(
	host: string,
	cert: PeerCertificate | DetailedPeerCertificate,
): boolean {
	const isHostnameMatch = (certName: string, host: string): boolean => {
		if (certName === host) return true;

		// Wildcard match
		if (
			certName.startsWith("*.") &&
			host.split(".").length === certName.split(".").length
		) {
			const certDomain = certName.substring(2);
			const hostDomain = host.split(".").slice(1).join(".");
			return hostDomain === certDomain;
		}

		return false;
	};

	if (cert.subject?.CN && isHostnameMatch(cert.subject.CN, host)) {
		return true;
	}

	if (cert.subjectaltname) {
		const altNames = cert.subjectaltname
			.split(", ")
			.filter((n) => n.startsWith("DNS:"))
			.map((n) => n.substring(4));
		if (altNames.some((dnsName) => isHostnameMatch(dnsName, host))) {
			return true;
		}
	}

	return false;
}

/**
 * Default options for the getCertificate function.
 */
const DefaultOptions: Partial<GetCertificateOptions> = {
	port: 443, // Default port for HTTPS
	timeout: 5000, // Default timeout of 10 seconds
	rejectUnauthorized: false, // We'll do our own verification
};

/**
 * Retrieves information about a certificate for a given host.
 *
 * @example Retrieve certificate info for example.com
 * ```typescript
 * import { getCertificateInfo } from "sslko";
 * const info = await getCertificateInfo("example.com");
 * console.log(info);
 * ```
 *
 * @example Retrieve expired certificate info for expired.badssl.com
 * ```typescript
 * import { getCertificateInfo } from "sslko";
 * const info = await getCertificateInfo("expired.badssl.com");
 * console.log(info);
 * ```
 *
 * Will return an object with `valid: false` and an error message.
 */
export async function getCertificateInfo(
	host: string,
	options: Partial<GetCertificateOptions> = {},
): Promise<CertificateInfo> {
	const certificate = (await getCertificate(host, {
		...DefaultOptions,
		...options,
		detailed: true, // Always return DetailedPeerCertificate for info
	})) as DetailedPeerCertificate;

	const results: CertificateInfo = {
		valid: true,
		...convertPeerCertificate(certificate),
		errors: [],
		warnings: [],
	};

	if (certificate.issuerCertificate) {
		results.issuerCertificate = convertPeerCertificate(
			certificate.issuerCertificate as DetailedPeerCertificate,
		);
	}

	if (!certificate.subject || !certificate.subject.CN) {
		// Dates verification
		results.warnings.push("Certificate does not have a Common Name (CN)");
	}

	if (Date.now() < results.validFromDate.getTime()) {
		results.valid = false;
		results.errors.push("Certificate is not yet valid");
	}

	// Check if the certificate is expired
	if (Date.now() > results.validToDate.getTime()) {
		results.valid = false;
		results.expired = true;
		results.errors.push("Certificate has expired");
	}

	// Host verification
	if (!verifyHostname(host, certificate)) {
		results.valid = false;
		results.errors.push(
			`Hostname "${host}" does not match the certificate's Common Name (CN) or Subject Alternative Names (SANs)`,
		);
	}

	// Reject self-signed certificates
	if (
		certificate.subject &&
		certificate.issuer &&
		certificate.subject.CN === certificate.issuer.CN
	) {
		results.valid = false;
		results.errors.push("Certificate is self-signed");
	}

	return results;
}
