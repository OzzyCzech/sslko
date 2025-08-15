import type {
	ConnectionOptions,
	DetailedPeerCertificate,
	PeerCertificate,
	TLSSocket,
} from "node:tls";
import * as tls from "node:tls";

/**
 * Enum for certificate error codes.
 * These codes are used to identify specific errors that can occur when fetching SSL/TLS certificates.
 * @see https://nodejs.org/api/tls.html#x509-certificate-error-codes
 */
export const CertificateErrorCode = {
	TIMEOUT: "TIMEOUT",
	INVALID_PORT: "INVALID_PORT",
	CERT_ERROR: "CERT_ERROR",
	MISSING_CERTIFICATE: "MISSING_CERTIFICATE",

	// default error codes from Node.js TLS module
	UNABLE_TO_GET_ISSUER_CERT: "UNABLE_TO_GET_ISSUER_CERT",
	UNABLE_TO_GET_CRL: "UNABLE_TO_GET_CRL",
	UNABLE_TO_DECRYPT_CERT_SIGNATURE: "UNABLE_TO_DECRYPT_CERT_SIGNATURE",
	UNABLE_TO_DECRYPT_CRL_SIGNATURE: "UNABLE_TO_DECRYPT_CRL_SIGNATURE",
	UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY: "UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY",
	CERT_SIGNATURE_FAILURE: "CERT_SIGNATURE_FAILURE",
	CRL_SIGNATURE_FAILURE: "CRL_SIGNATURE_FAILURE",
	CERT_NOT_YET_VALID: "CERT_NOT_YET_VALID",
	CERT_HAS_EXPIRED: "CERT_HAS_EXPIRED",
	CRL_NOT_YET_VALID: "CRL_NOT_YET_VALID",
	CRL_HAS_EXPIRED: "CRL_HAS_EXPIRED",
	ERROR_IN_CERT_NOT_BEFORE_FIELD: "ERROR_IN_CERT_NOT_BEFORE_FIELD",
	ERROR_IN_CERT_NOT_AFTER_FIELD: "ERROR_IN_CERT_NOT_AFTER_FIELD",
	ERROR_IN_CRL_LAST_UPDATE_FIELD: "ERROR_IN_CRL_LAST_UPDATE_FIELD",
	ERROR_IN_CRL_NEXT_UPDATE_FIELD: "ERROR_IN_CRL_NEXT_UPDATE_FIELD",
	OUT_OF_MEM: "OUT_OF_MEM",
	DEPTH_ZERO_SELF_SIGNED_CERT: "DEPTH_ZERO_SELF_SIGNED_CERT",
	SELF_SIGNED_CERT_IN_CHAIN: "SELF_SIGNED_CERT_IN_CHAIN",
	UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
	UNABLE_TO_VERIFY_LEAF_SIGNATURE: "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
	CERT_CHAIN_TOO_LONG: "CERT_CHAIN_TOO_LONG",
	CERT_REVOKED: "CERT_REVOKED",
	INVALID_CA: "INVALID_CA",
	PATH_LENGTH_EXCEEDED: "PATH_LENGTH_EXCEEDED",
	INVALID_PURPOSE: "INVALID_PURPOSE",
	CERT_UNTRUSTED: "CERT_UNTRUSTED",
	CERT_REJECTED: "CERT_REJECTED",
	HOSTNAME_MISMATCH: "HOSTNAME_MISMATCH",
};

export type CertificateErrorCode = keyof typeof CertificateErrorCode;

export class CertificateError extends Error {
	code: CertificateErrorCode | string;

	constructor(
		message: string,
		code: string | CertificateErrorCode = CertificateErrorCode.CERT_ERROR,
	) {
		super(message);
		this.name = "CertificateError";
		this.code = code;

		// Fix the prototype chain (important for instanceof checks)
		Object.setPrototypeOf(this, CertificateError.prototype);
	}
}

/**
 * Options for the getCertificate function.
 *
 * - `port`: The port to connect to (default is 443).
 * - `timeout`: The timeout for the connection in milliseconds (default is 10000).
 * - `detailed`: If true, returns a DetailedPeerCertificate with additional information (default is false).
 */
export type Options = ConnectionOptions & {
	detailed?: boolean;
};

const DefaultOptions: Partial<Options> = {
	port: 443, // Default port for HTTPS
	timeout: 5000, // 5 seconds
	detailed: false, // get PeerCertificate by default
};

/**
 * Fetches the SSL/TLS certificate from a given host and port.
 *
 * @param host The hostname to connect to.
 * @param options Optional parameters to configure the connection.
 * @throws {CertificateError} If the connection times out or if there is an error retrieving the certificate.
 *
 * @example Return a PeerCertificate object:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com');
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificate object with a custom port:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { port: 8443 });
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificateDetailed object:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { detailed: true });
 * console.log(cert);
 * ```
 */
export async function getCertificate(
	host: string,
	options: Partial<Options> = {},
): Promise<PeerCertificate | DetailedPeerCertificate> {
	const { timeout, detailed, port, ...rest } = {
		...{ host, servername: host },
		...DefaultOptions,
		...options,
	};

	if (port && (port < 1 || port > 65535)) {
		throw new CertificateError(
			"Invalid port number. Port must be between 1 and 65535.",
			CertificateErrorCode.INVALID_PORT,
		);
	}

	const socket: TLSSocket = tls.connect({ ...rest, port, timeout });

	return await new Promise((resolve, reject) => {
		if (timeout) {
			socket.setTimeout(timeout, () => {
				socket.destroy();
				reject(
					new CertificateError(
						"Connection timed out",
						CertificateErrorCode.TIMEOUT,
					),
				);
			});
		}

		socket.on("secureConnect", () => {
			// @see https://github.com/oven-sh/bun/issues/21902 - Bun always failed when detailed = false
			const cert = detailed
				? socket.getPeerCertificate(true)
				: socket.getPeerCertificate();
			socket.end();

			if (!cert || !cert.valid_to || !cert.valid_from || !cert.subjectaltname) {
				return reject(
					new CertificateError(
						"No certificate information available",
						CertificateErrorCode.MISSING_CERTIFICATE,
					),
				);
			}

			resolve(cert);
		});

		socket.on("error", (error: NodeJS.ErrnoException) => {
			const message = error?.message || "Unknown error";
			const code =
				(error?.code as CertificateErrorCode) ||
				CertificateErrorCode.CERT_ERROR;
			reject(new CertificateError(message, code));
		});
	});
}
