import type { DetailedPeerCertificate } from "node:tls";
import {
	DNS_PREFIX,
	IP_ADDRESS_PREFIX,
	MILLISECONDS_PER_DAY,
} from "./constants.js";
import type { PeerCertificateConverted } from "./types.js";

/**
 * Calculates the number of days between two dates.
 * @param validFrom The start date of certificate validity
 * @param validTo The end date of certificate validity
 * @returns The total number of days the certificate is valid
 */
function getDaysTotal(validFrom: Date, validTo: Date): number {
	return Math.ceil(
		Math.abs(validFrom.getTime() - validTo.getTime()) / MILLISECONDS_PER_DAY,
	);
}

/**
 * Calculates the number of days remaining until the certificate expires.
 * @param validTo The expiration date of the certificate
 * @returns The number of days left until expiration (can be negative if already expired)
 */
function getDaysLeft(validTo: Date): number {
	return Math.ceil((validTo.getTime() - Date.now()) / MILLISECONDS_PER_DAY);
}

/**
 * Converts a Node.js DetailedPeerCertificate to a cleaner, more usable format.
 * This function transforms the raw certificate data into a more developer-friendly structure
 * with computed fields for expiration status, days remaining, and formatted dates.
 *
 * @param certificate The detailed peer certificate from Node.js TLS
 * @returns A converted certificate object with enhanced fields
 */
export function convertPeerCertificate(
	certificate: DetailedPeerCertificate,
): PeerCertificateConverted {
	const { valid_from, valid_to, pubkey, raw, ...rest } = certificate;

	// Remove issuerCertificate to avoid circular reference
	delete (rest as Partial<typeof rest>).issuerCertificate;

	return {
		validFromDate: new Date(valid_from),
		validToDate: new Date(valid_to),
		expired: new Date(valid_to).getTime() < Date.now(),
		daysLeft: getDaysLeft(new Date(valid_to)),
		daysTotal: getDaysTotal(new Date(valid_from), new Date(valid_to)),
		validFor: certificate.subjectaltname
			? certificate.subjectaltname
					.replace(new RegExp(`${DNS_PREFIX}|${IP_ADDRESS_PREFIX}`, "g"), "")
					.split(", ")
			: undefined,
		pubkey: Buffer.isBuffer(pubkey) ? pubkey.toString("base64") : undefined,
		raw: Buffer.isBuffer(raw) ? raw.toString("base64") : undefined,
		...rest,
	};
}
