import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import {
	DEFAULT_PORT,
	DEFAULT_TIMEOUT,
	MIN_RSA_KEY_SIZE,
} from "./constants.js";
import { convertPeerCertificate } from "./convert-peer-certificate.js";
import { getCertificate } from "./get-certificate.js";
import type { CertificateInfo, GetCertificateOptions } from "./types.js";

/**
 * Verifies if the given hostname matches the Common Name (CN) or Subject Alternative Names (SANs) of the certificate.
 *
 * @param host The hostname to check.
 * @param certificate The certificate to getCertificateInfo against.
 * @returns `true` if the hostname matches, otherwise `false`.
 */
export function verifyHostname(
	host: string,
	certificate: PeerCertificate | DetailedPeerCertificate,
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

	if (
		certificate.subject?.CN &&
		isHostnameMatch(certificate.subject.CN, host)
	) {
		return true;
	}

	if (certificate.subjectaltname) {
		const altNames = certificate.subjectaltname
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
	port: DEFAULT_PORT, // Default port for HTTPS
	timeout: DEFAULT_TIMEOUT, // Default timeout of 10 seconds
	rejectUnauthorized: false, // We'll do our own verification
};

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
 * Validates the basic structure and content of a certificate.
 * @param certificate The certificate to validate
 * @returns An array of validation warning messages (empty if valid)
 */
export function validateCertificateStructure(
	certificate: PeerCertificate | DetailedPeerCertificate,
): string[] {
	const warnings: string[] = [];

	// Check for missing essential fields
	if (!certificate.subject) {
		warnings.push("Certificate is missing subject information");
	} else if (!certificate.subject.CN) {
		warnings.push("Certificate does not have a Common Name (CN)");
	}

	if (!certificate.issuer) {
		warnings.push("Certificate is missing issuer information");
	}

	if (!certificate.subjectaltname) {
		warnings.push("Certificate does not have Subject Alternative Names (SANs)");
	}

	return warnings;
}

/**
 * Checks for security weaknesses in a certificate's cryptographic properties.
 * @param certificate The certificate to analyze for security issues
 * @returns An array of security warning messages
 */
export function checkCertificateSecurity(
	certificate: PeerCertificate | DetailedPeerCertificate,
): string[] {
	const warnings: string[] = [];

	// Check RSA key size if available (modulus and exponent are available on DetailedPeerCertificate)
	if (
		"modulus" in certificate &&
		certificate.modulus &&
		"exponent" in certificate &&
		certificate.exponent
	) {
		try {
			// Modulus is typically in hex format, convert to estimate bit length
			const modulusHex = certificate.modulus.replace(/:/g, "");
			const keyBits = modulusHex.length * 4; // Each hex char is 4 bits

			if (keyBits < MIN_RSA_KEY_SIZE) {
				warnings.push(
					`Certificate uses weak RSA key size: ${keyBits} bits (minimum recommended: ${MIN_RSA_KEY_SIZE} bits)`,
				);
			}
		} catch {
			// Ignore parsing errors for modulus
		}
	}

	/** Weak signature algorithms that should be flagged */
	const weekSignatures = [
		"md5WithRSAEncryption",
		"sha1WithRSAEncryption",
		"md5WithRSA",
		"sha1WithRSA",
	] as const;

	// Check for weak signature algorithm
	if (
		"signatureAlgorithm" in certificate &&
		typeof certificate.signatureAlgorithm === "string" &&
		weekSignatures.includes(
			certificate.signatureAlgorithm as (typeof weekSignatures)[number],
		)
	) {
		warnings.push(
			`Certificate uses weak signature algorithm: ${certificate.signatureAlgorithm}`,
		);
	}

	return warnings;
}

/**
 * Retrieves information about a certificate for a given host.
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
		issuerCertificate: convertPeerCertificate(
			certificate.issuerCertificate as DetailedPeerCertificate,
		),
		errors: [],
		warnings: [],
	};

	// Check if certificate is not yet valid
	if (Date.now() < results.validFromDate.getTime()) {
		results.valid = false;
		results.errors.push("Certificate is not yet valid");
	}

	// Check if certificate is approaching expiration (within 30 days)
	if (!results.expired && results.daysLeft > 0 && results.daysLeft <= 30) {
		results.warnings.push(`Certificate expires in ${results.daysLeft} days`);
	}

	if (!certificate.issuer) {
		results.warnings.push("Certificate is missing issuer information");
	}

	// Check if the certificate is expired
	if (Date.now() > results.validToDate.getTime()) {
		results.valid = false;
		results.expired = true;
		results.errors.push("Certificate has expired");
	}

	// Unusually short validity period check
	if (results.daysTotal < 1) {
		results.warnings.push(
			"Certificate has an unusually short validity period (less than 1 day)",
		);
	}

	// Unusually long validity period check
	if (results.daysTotal > 398) {
		results.warnings.push(
			`Certificate has an unusually long validity period (${results.daysTotal} days, max recommended: 398)`,
		);
	}

	// Validate certificate structure and add any warnings
	const structureWarnings = validateCertificateStructure(certificate);
	results.warnings.push(...structureWarnings);

	// Check for security weaknesses
	const securityWarnings = checkCertificateSecurity(certificate);
	results.warnings.push(...securityWarnings);

	// Host verification
	if (!verifyHostname(host, certificate)) {
		results.valid = false;
		results.errors.push(
			`Hostname "${host}" does not match the certificate's Common Name (CN) or Subject Alternative Names (SANs)`,
		);
	}

	// Check if the certificate is self-signed
	if (isSelfSignedCertificate(certificate)) {
		results.valid = false;
		results.errors.push("Certificate is self-signed");
	}

	return results;
}
