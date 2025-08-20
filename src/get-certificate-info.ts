import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import {
	DEFAULT_HTTPS_PORT,
	DEFAULT_TIMEOUT_MS,
	DNS_PREFIX,
	IP_ADDRESS_PREFIX,
	WILDCARD_PREFIX,
} from "./constants.js";
import { convertPeerCertificate } from "./convert-peer-certificate.js";
import { getCertificate } from "./get-certificate.js";
import type { CertificateInfo, GetCertificateOptions } from "./types.js";

/**
 * Checks if a string is a valid IPv4 address.
 * @param ip The string to check
 * @returns true if the string is a valid IPv4 address
 */
function isValidIPv4(ip: string): boolean {
	const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
	if (!ipv4Regex.test(ip)) return false;

	const parts = ip.split(".");
	return parts.every((part) => {
		const num = parseInt(part, 10);
		return num >= 0 && num <= 255;
	});
}

/**
 * Checks if a string is a valid IPv6 address.
 * @param ip The string to check
 * @returns true if the string is a valid IPv6 address
 */
function isValidIPv6(ip: string): boolean {
	// Simplified IPv6 validation - handles most common cases
	const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
	return ipv6Regex.test(ip) || ip.includes("::");
}

/**
 * Checks if a string is an IP address (IPv4 or IPv6).
 * @param address The string to check
 * @returns true if the string is an IP address
 */
function isIPAddress(address: string): boolean {
	return isValidIPv4(address) || isValidIPv6(address);
}

/**
 * Verifies if the given hostname matches the Common Name (CN) or Subject Alternative Names (SANs) of the certificate.
 * This function supports both domain names and IP addresses, including wildcard domain matching.
 *
 * @param host The hostname or IP address to check
 * @param certificate The certificate to validate against
 * @returns `true` if the hostname matches, otherwise `false`
 *
 * @example
 * ```typescript
 * const isValid = verifyHostname("example.com", certificate);
 * const isIPValid = verifyHostname("192.168.1.1", certificate);
 * const isWildcardValid = verifyHostname("sub.example.com", wildcardCert);
 * ```
 */
export function verifyHostname(
	host: string,
	certificate: PeerCertificate | DetailedPeerCertificate,
): boolean {
	/**
	 * Checks if a certificate name matches the given host.
	 * Supports exact matching, wildcard matching for domains, and IP address matching.
	 */
	const isHostnameMatch = (certName: string, host: string): boolean => {
		// Exact match
		if (certName === host) return true;

		// If host is an IP address, only exact match is valid
		if (isIPAddress(host)) return false;

		// Wildcard match for domains only
		if (
			certName.startsWith(WILDCARD_PREFIX) &&
			host.split(".").length === certName.split(".").length
		) {
			const certDomain = certName.substring(WILDCARD_PREFIX.length);
			const hostDomain = host.split(".").slice(1).join(".");
			return hostDomain === certDomain;
		}

		return false;
	};

	// Check Common Name (CN)
	if (
		certificate.subject?.CN &&
		isHostnameMatch(certificate.subject.CN, host)
	) {
		return true;
	}

	// Check Subject Alternative Names (SANs)
	if (certificate.subjectaltname) {
		const altNames = certificate.subjectaltname
			.split(", ")
			.map((name) => {
				if (name.startsWith(DNS_PREFIX)) {
					return { type: "dns", value: name.substring(DNS_PREFIX.length) };
				}
				if (name.startsWith(IP_ADDRESS_PREFIX)) {
					return {
						type: "ip",
						value: name.substring(IP_ADDRESS_PREFIX.length).trim(),
					};
				}
				return null;
			})
			.filter(
				(name): name is { type: "dns" | "ip"; value: string } => name !== null,
			);

		// For IP addresses, only check IP Address SANs
		if (isIPAddress(host)) {
			return altNames
				.filter((name) => name.type === "ip")
				.some((name) => name.value === host);
		}

		// For domain names, only check DNS SANs
		return altNames
			.filter((name) => name.type === "dns")
			.some((name) => isHostnameMatch(name.value, host));
	}

	return false;
}

/**
 * Checks if a certificate is approaching expiration within a given number of days.
 * @param validToDate The certificate expiration date
 * @param warningDays Number of days before expiration to warn (default: 30)
 * @returns true if the certificate expires within the warning period
 */
export function isCertificateNearExpiry(
	validToDate: Date,
	warningDays = 30,
): boolean {
	const warningTime = warningDays * 24 * 60 * 60 * 1000; // Convert days to milliseconds
	return validToDate.getTime() - Date.now() <= warningTime;
}

/**
 * Checks if a certificate appears to be self-signed by comparing subject and issuer.
 * @param certificate The certificate to check
 * @returns true if the certificate appears to be self-signed
 */
export function isSelfSignedCertificate(
	certificate: PeerCertificate | DetailedPeerCertificate,
): boolean {
	if (!certificate.subject || !certificate.issuer) {
		return false;
	}

	// Compare Common Names
	if (certificate.subject.CN && certificate.issuer.CN) {
		return certificate.subject.CN === certificate.issuer.CN;
	}

	// If no CN, compare the entire subject/issuer objects
	return (
		JSON.stringify(certificate.subject) === JSON.stringify(certificate.issuer)
	);
}

/**
 * Default options for the getCertificateInfo function.
 */
const DefaultOptions: Partial<GetCertificateOptions> = {
	port: DEFAULT_HTTPS_PORT, // Default port for HTTPS
	timeout: DEFAULT_TIMEOUT_MS, // Default timeout of 5 seconds
	rejectUnauthorized: false, // We'll do our own verification
};

/**
 * Retrieves comprehensive information about a certificate for a given host.
 * This function fetches the certificate and performs various validation checks
 * including expiration, hostname matching, and self-signed detection.
 *
 * @param host The hostname or IP address to retrieve certificate information for
 * @param options Optional configuration for the connection and validation
 * @returns Promise resolving to detailed certificate information with validation results
 *
 * @example Retrieve certificate info for example.com
 * ```typescript
 * import { getCertificateInfo } from "sslko";
 * const info = await getCertificateInfo("example.com");
 * console.log(`Valid: ${info.valid}, Days left: ${info.daysLeft}`);
 * ```
 *
 * @example Retrieve expired certificate info for expired.badssl.com
 * ```typescript
 * import { getCertificateInfo } from "sslko";
 * const info = await getCertificateInfo("expired.badssl.com");
 * if (!info.valid) {
 *   console.log(`Errors: ${info.errors.join(", ")}`);
 * }
 * ```
 *
 * @example Check certificate for custom port
 * ```typescript
 * import { getCertificateInfo } from "sslko";
 * const info = await getCertificateInfo("example.com", { port: 8443 });
 * ```
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
		results.warnings.push("Certificate does not have a Common Name (CN)");
	}

	// Check if certificate is not yet valid
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

	// Check if certificate is approaching expiration (within 30 days)
	if (!results.expired && isCertificateNearExpiry(results.validToDate, 30)) {
		results.warnings.push(`Certificate expires in ${results.daysLeft} days`);
	}

	// Host verification
	if (!verifyHostname(host, certificate)) {
		results.valid = false;
		results.errors.push(
			`Hostname "${host}" does not match the certificate's Common Name (CN) or Subject Alternative Names (SANs)`,
		);
	}

	// Check for self-signed certificates
	if (isSelfSignedCertificate(certificate)) {
		results.valid = false;
		results.errors.push("Certificate is self-signed");
	}

	return results;
}
