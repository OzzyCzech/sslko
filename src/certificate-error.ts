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

/**
 * Custom error class for handling certificate-related errors.
 * Extends the standard Error class with additional certificate-specific error codes.
 *
 * @example
 * ```typescript
 * import { CertificateError, CertificateErrorCode } from "sslko";
 *
 * try {
 *   // Some certificate operation
 * } catch (error) {
 *   if (error instanceof CertificateError) {
 *     console.log(`Certificate error: ${error.code} - ${error.message}`);
 *   }
 * }
 * ```
 */
export class CertificateError extends Error {
	/** The specific error code identifying the type of certificate error */
	code: CertificateErrorCode | string;

	/**
	 * Creates a new CertificateError instance.
	 * @param message Human-readable error message describing the issue
	 * @param code Error code identifying the specific type of certificate error
	 */
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
