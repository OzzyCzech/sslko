import type { X509Certificate } from "node:crypto";
import type { DetailedPeerCertificate, PeerCertificate } from "node:tls";
import type { CertificateErrorCode } from "./certificate-error.js";

/**
 * Calculates the number of days between two dates.
 * @param validFrom
 * @param validTo
 */
function getDaysTotal(validFrom: Date, validTo: Date): number {
	return Math.ceil(Math.abs(validFrom.getTime() - validTo.getTime()) / 8.64e7);
}

/**
 * Calculates the number of days remaining until the certificate expires.
 * - can be negative if the certificate is already expired
 * @param validTo
 */
function getDaysLeft(validTo: Date): number {
	return Math.ceil((validTo.getTime() - Date.now()) / 8.64e7);
}

export interface SubjectMetadata {
	common_name?: string;
	country?: string;
	state_or_province?: string;
	locality?: string;
	organization?: string;
	organizational_unit?: string;
}

export interface CertificateInfo {
	valid: boolean;

	// Invalid certificate properties
	error?: string;
	code?: CertificateErrorCode | string;

	// Certificate properties
	expired?: boolean;
	validFor?: string[];
	subject?: SubjectMetadata;
	issuer?: SubjectMetadata;

	validFrom?: Date;
	validTo?: Date;
	daysLeft?: number;
	daysTotal?: number;

	pubkey?: string | null;
	raw?: string | null;

	// biome-ignore lint/suspicious/noExplicitAny: Allow any additional properties
	[key: string]: any;
}

export function fromPeerCertificate(
	certificate: PeerCertificate | DetailedPeerCertificate,
): CertificateInfo {
	const {
		subject,
		raw,
		issuer,
		subjectaltname,
		valid_from,
		valid_to,
		pubkey,
		...rest
	} = certificate;
	const validFrom = new Date(valid_from);
	const validTo = new Date(valid_to);

	const daysLeft = getDaysLeft(validTo);
	const daysTotal = getDaysTotal(validFrom, validTo);

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

		validFrom: validFrom,
		validTo: validTo,
		daysLeft: daysLeft,
		daysTotal: daysTotal,

		pubkey: Buffer.isBuffer(pubkey) ? pubkey.toString("base64") : null,
		raw: Buffer.isBuffer(raw) ? raw.toString("base64") : null,

		...rest,
	};
}

export function fromX509Certificate(
	certificate: X509Certificate,
): CertificateInfo {
	const validFrom = new Date(certificate.validFrom);
	const validTo = new Date(certificate.validTo);

	const daysLeft = Math.ceil(
		(validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
	);
	const daysTotal = Math.ceil(
		(validTo.getTime() - validFrom.getTime()) / (1000 * 60 * 60 * 24),
	);

	return {
		valid: true,
		subject: certificate.subject,
		issuer: certificate.issuer,
		validFrom: validFrom,
		validTo: validTo,
		daysLeft: daysLeft,
		daysTotal: daysTotal,
		pubkey: certificate.publicKey?.toString("base64") || null,
		raw: certificate.raw.toString("base64"),
	};
}
