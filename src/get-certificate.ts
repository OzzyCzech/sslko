import { CertificateError } from "./certificate-error.js";
import {
	type CertificateInfo,
	fromPeerCertificate,
} from "./certificate-info.js";
import type { OpenSSLOptions } from "./with-openssl.js";
import { getCertificateWithTls, type TlsOptions } from "./with-tls.js";

/**
 * Retrieves information about a certificate for a given host.
 *
 * @example Retrieve certificate info for example.com
 * ```typescript
 * import { getCertificate } from "sslko";
 * const info = await getCertificate("example.com");
 * console.log(info);
 * ```
 *
 * @example Retrieve expired certificate info for expired.badssl.com
 * ```typescript
 * import { getCertificate } from "sslko";
 * const info = await getCertificate("expired.badssl.com");
 * console.log(info);
 * ```
 *
 * Will return an object with `valid: false` and an error message.
 *
 * @param host
 * @param options
 */
export async function getCertificate(
	host: string,
	options: Partial<TlsOptions | OpenSSLOptions> = {},
): Promise<CertificateInfo> {
	try {
		// TODO add support for OpenSSL as an alternative method
		const certificate = await getCertificateWithTls(host, options);
		return fromPeerCertificate(certificate);
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
