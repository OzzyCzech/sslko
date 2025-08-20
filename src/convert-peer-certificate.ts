import type { DetailedPeerCertificate } from "node:tls";
import { DAY_IN_MILLISECOND } from "./constants.js";
import type { PeerCertificateConverted } from "./types.js";

/**
 * Calculates the number of days between two dates.
 * @param validFrom
 * @param validTo
 */
function getDaysTotal(validFrom: Date, validTo: Date): number {
	return Math.ceil(
		Math.abs(validFrom.getTime() - validTo.getTime()) / DAY_IN_MILLISECOND,
	);
}

/**
 * Calculates the number of days remaining until the certificate expires.
 * - can be negative if the certificate is already expired
 * @param validTo
 */
function getDaysLeft(validTo: Date): number {
	return Math.ceil((validTo.getTime() - Date.now()) / DAY_IN_MILLISECOND);
}

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
			? certificate.subjectaltname.replace(/DNS:|IP Address:/g, "").split(", ")
			: undefined,
		pubkey: Buffer.isBuffer(pubkey) ? pubkey.toString("base64") : undefined,
		raw: Buffer.isBuffer(raw) ? raw.toString("base64") : undefined,
		...rest,
	};
}
