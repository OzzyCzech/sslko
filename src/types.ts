import type { DetailedPeerCertificate, TLSSocketOptions } from "node:tls";
import type { CertificateErrorCode } from "./certificate-error.js";

/**
 * GetCertificateOptions for the getCertificate function.
 */
export type GetCertificateOptions = TLSSocketOptions & {
	/** The port to connect to. */
	port?: number;
	/** The timeout for the connection in milliseconds. */
	timeout?: number;
	/** If true, returns a DetailedPeerCertificate with additional information.*/
	detailed?: boolean;
};

/**
 * CertificateDates contains the dates and status of a certificate.
 */
export interface CertificateDates {
	/** The date when the certificate becomes valid. */
	validFromDate: Date;
	/** The date when the certificate expires. */
	validToDate: Date;
	/** The total number of days the certificate is valid. */
	daysTotal: number;
	/** The number of days left until the certificate expires. */
	daysLeft: number;
	/** A boolean indicating if the certificate is expired. */
	expired: boolean;
}

/**
 * DetailedPeerCertificateConverted is a simplified version of DetailedPeerCertificate
 * with only the necessary fields for certificate information.
 */
export interface PeerCertificateConverted
	extends Omit<DetailedPeerCertificate, "valid_from" | "valid_to" | "raw" | "pubkey" | "issuerCertificate">,
		CertificateDates {
	/** The raw certificate in base64 format. */
	raw?: string;
	/** The public key in base64 format. */
	pubkey?: string;
	/** The list of valid subject alternative names (SANs) for the certificate. */
	validFor?: string[];
}

/**
 * CertificateInfo extends PeerCertificateConverted
 * and includes additional fields for validation status, errors, and warnings.
 * It also includes the issuer certificate if available.
 */
export interface CertificateInfo extends PeerCertificateConverted {
	/** Indicates if the certificate is valid. */
	valid: boolean;
	/** List of errors encountered during certificate validation. */
	errors: string[];
	/** List of warnings encountered during certificate validation. */
	warnings: string[];
	/** The error code if the certificate validation failed. */
	errorCode?: CertificateErrorCode | string;
	/** The issuer certificate, if available. */
	issuerCertificate?: PeerCertificateConverted;
}
