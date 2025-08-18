import type {
	ConnectionOptions,
	DetailedPeerCertificate,
	PeerCertificate,
	TLSSocket,
} from "node:tls";
import * as tls from "node:tls";
import { CertificateError, CertificateErrorCode } from "./certificate-error.js";

/**
 * TlsOptions for the getCertificate function.
 *
 * - `port`: The port to connect to (default is 443).
 * - `timeout`: The timeout for the connection in milliseconds (default is 10000).
 * - `detailed`: If true, returns a DetailedPeerCertificate with additional information (default is false).
 */
export type TlsOptions = ConnectionOptions & {
	detailed?: boolean;
};

/**
 * Default options for the getCertificate function.
 */
const DefaultOptions: Partial<TlsOptions> = {
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
 * const cert = await getCertificateWithTls('example.com');
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificate object with a custom port:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificateWithTls('example.com', { port: 8443 });
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificateDetailed object:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificateWithTls('example.com', { detailed: true });
 * console.log(cert);
 * ```
 */
export async function getCertificateWithTls(
	host: string,
	options: Partial<TlsOptions> = {},
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
