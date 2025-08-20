import type {
	DetailedPeerCertificate,
	PeerCertificate,
	TLSSocket,
} from "node:tls";
import * as tls from "node:tls";
import { CertificateError, CertificateErrorCode } from "./certificate-error.js";
import {
	DEFAULT_HTTPS_PORT,
	DEFAULT_TIMEOUT_MS,
	MAX_PORT,
	MIN_PORT,
} from "./constants.js";
import type { GetCertificateOptions } from "./types.js";

/**
 * Default options for the getCertificate function.
 */
const DefaultOptions: Partial<GetCertificateOptions> = {
	port: DEFAULT_HTTPS_PORT, // Default port for HTTPS
	timeout: DEFAULT_TIMEOUT_MS, // Default timeout of 5 seconds
	rejectUnauthorized: false, // We'll do our own verification
	detailed: true, // Return a DetailedPeerCertificate by default
};

/**
 * Fetches the SSL/TLS certificate from a given host and port.
 *
 * @param host The hostname to connect to.
 * @param options Optional parameters to configure the connection.
 * @throws {CertificateError} If the connection times out or if there is an error retrieving the certificate.
 *
 * @example Return a PeerCertificateDetailed object:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com');
 * console.log(cert);
 * ```
 *
 * @example Let Node.js getCertificateInfo the certificate for you:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { rejectUnauthorized: true });
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificateDetailed object with a custom port:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { port: 8443 });
 * console.log(cert);
 * ```
 *
 * @example Return a PeerCertificate object:
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { detailed: false });
 * console.log(cert);
 * ```
 *
 * @example Enable trace - useful for debugging:
 *
 * When enabled, TLS packet trace information is written to `stderr`. This can be used to debug TLS connection problems.
 *
 * ```typescript
 * import { getCertificate } from 'sslko';
 * const cert = await getCertificate('example.com', { enableTrace: true });
 * ```
 */
export async function getCertificate(
	host: string,
	options: Partial<GetCertificateOptions> = {},
): Promise<DetailedPeerCertificate | PeerCertificate> {
	const { timeout, detailed, port, ...rest } = {
		...{ host, servername: host },
		...DefaultOptions,
		...options,
	};

	if (port && (port < MIN_PORT || port > MAX_PORT)) {
		throw new CertificateError(
			`Invalid port number. Port must be between ${MIN_PORT} and ${MAX_PORT}.`,
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
						`Failed to connect to ${host}:${port} within ${timeout}ms`,
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

			// empty certificate check
			if (!cert || Object.keys(cert).length === 0) {
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
