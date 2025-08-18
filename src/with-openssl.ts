import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";

/**
 * Fetches the PEM certificate for a given host and port using OpenSSL.
 * @param host hostname or IP address of the server
 * @param port port number (default is 443)
 * @param timeout timeout in milliseconds (default is 5000)
 */
export function fetchPemCertificate(
	host: string,
	port: number = 443,
	timeout: number = 5000,
) {
	const result = spawnSync(
		"openssl",
		["s_client", "-connect", `${host}:${port}`, "-servername", host],
		{ input: "", encoding: "utf8", timeout: timeout },
	);

	if (result.error) throw result.error;

	// Pipe into x509
	const pem = spawnSync(
		"openssl",
		["x509", "-in", "/dev/stdin", "-outform", "PEM"],
		{ input: result.stdout, encoding: "utf8", timeout: timeout },
	);

	if (pem.error) throw pem.error;
	if (pem.status !== 0) throw new Error(pem.stderr);

	return pem.stdout;
}

/**
 * TlsOptions for the getCertificate function.
 *
 * - `port`: The port to connect to (default is 443).
 * - `timeout`: The timeout for the connection in milliseconds (default is 10000).
 * - `detailed`: If true, returns a DetailedPeerCertificate with additional information (default is false).
 */
export type OpenSSLOptions = {
	port: number;
	timeout: number;
};

const DefaultOptions = {
	port: 443, // Default port for HTTPS
	timeout: 5000, // 5 seconds
};

export async function getServerCertificateWithOpenSSL(
	host: string,
	options: Partial<OpenSSLOptions> = {},
): Promise<X509Certificate> {
	const { timeout, port } = {
		...DefaultOptions,
		...options,
	};

	return await new Promise((resolve, reject) => {
		try {
			const pem = fetchPemCertificate(host, port, timeout);
			resolve(new X509Certificate(pem));
		} catch (error) {
			reject(error);
		}
	});
}
