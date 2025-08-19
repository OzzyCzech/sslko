import type { DetailedPeerCertificate, TLSSocketOptions } from "node:tls";
import type { CertificateErrorCode } from "./certificate-error.js";

/**
 * GetCertificateOptions for the getCertificate function.
 *
 * - `port`: The port to connect to (default is 443).
 * - `timeout`: The timeout for the connection in milliseconds (default is 5000).
 * - `detailed`: If true, returns a DetailedPeerCertificate with additional information (default is false).
 */
export type GetCertificateOptions = TLSSocketOptions & {
	port?: number;
	timeout?: number;
	detailed?: boolean;
};

export interface CertificateDates {
	validFromDate: Date;
	validToDate: Date;
	daysTotal: number;
	daysLeft: number;
	expired?: boolean;
}

export interface CertificateRawData {
	raw?: string;
	pubkey?: string;
}

export interface PeerCertificateConverted
	extends Omit<
			DetailedPeerCertificate,
			"valid_from" | "valid_to" | "raw" | "pubkey" | "issuerCertificate"
		>,
		CertificateDates,
		CertificateRawData {
	validFor?: string[];
}

export interface CertificateInfo extends PeerCertificateConverted {
	valid: boolean;
	errors: string[];
	warnings: string[];
	errorCode?: CertificateErrorCode | string;
	issuerCertificate?: PeerCertificateConverted;
}
