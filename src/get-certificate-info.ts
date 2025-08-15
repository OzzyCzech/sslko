import {
	CertificateError,
	type CertificateErrorCode,
	getCertificate,
	type Options,
} from "./get-certificate";

export interface CertificateInfo {
	valid: boolean;
	validFor?: string[];
	error?: string;
	code?: CertificateErrorCode | string;
	expired?: boolean;
	subject?: {
		common_name?: string;
		country?: string;
		state_or_province?: string;
		locality?: string;
		organization?: string;
		organizational_unit?: string;
	};
	issuer?: {
		common_name?: string;
		country?: string;
		state_or_province?: string;
		locality?: string;
		organization?: string;
		organizational_unit?: string;
	};

	valid_from?: Date;
	valid_to?: Date;
	days_left?: number;
	days_total?: number;

	pubkey?: string | null;
	raw?: string | null;

	// biome-ignore lint/suspicious/noExplicitAny: Allow any additional properties
	[key: string]: any;
}

/**
 * Calculates the number of days between two dates.
 * @param validFrom
 * @param validTo
 */
function getDaysBetween(validFrom: Date, validTo: Date): number {
	return Math.ceil(Math.abs(validFrom.getTime() - validTo.getTime()) / 8.64e7);
}

/**
 * Calculates the number of days remaining until the certificate expires.
 * - can be negative if the certificate is already expired
 * @param validFrom
 * @param validTo
 */
function getDaysRemaining(validFrom: Date, validTo: Date): number {
	const daysRemaining = getDaysBetween(validFrom, validTo);
	return validTo.getTime() < Date.now() ? -daysRemaining : daysRemaining;
}

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
 *
 *
 * @param host
 * @param options
 */
export async function getCertificateInfo(
	host: string,
	options: Partial<Options> = {},
): Promise<CertificateInfo> {
	try {
		const {
			subject,
			raw,
			issuer,
			subjectaltname,
			valid_from,
			valid_to,
			pubkey,
			...rest
		} = await getCertificate(host, options);
		const validFrom = new Date(valid_from);
		const validTo = new Date(valid_to);

		const daysLeft = getDaysRemaining(validFrom, validTo);
		const daysTotal = getDaysBetween(validFrom, validTo);

		return {
			valid: true,
			validFor: subjectaltname
				? subjectaltname.replace(/DNS:|IP Address:/g, "").split(", ")
				: [],
			expired: validTo < new Date(),
			subject: {
				common_name: subject?.CN,
				country: subject?.C,
				state_or_province: subject?.ST,
				locality: subject?.L,
				organization: subject?.O,
				organizational_unit: subject?.OU,
			},
			issuer: {
				common_name: issuer?.CN,
				country: issuer?.C,
				state_or_province: issuer?.ST,
				locality: issuer?.L,
				organization: issuer?.O,
				organizational_unit: issuer?.OU,
			},

			valid_from: validFrom,
			valid_to: validTo,
			days_left: daysLeft,
			days_total: daysTotal,

			pubkey: Buffer.isBuffer(pubkey) ? pubkey.toString("base64") : null,
			raw: Buffer.isBuffer(raw) ? raw.toString("base64") : null,

			...rest,
		};
	} catch (error) {
		if (error instanceof CertificateError) {
			return {
				valid: false,
				error: error.message,
				code: error.code,
			};
		} else {
			return {
				valid: false,
				error: "An unexpected error occurred while retrieving the certificate.",
			};
		}
	}
}
