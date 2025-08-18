import { spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";

function getCertificateWithOpenSSL(host) {
	const result = spawnSync(
		"openssl",
		["s_client", "-connect", `${host}:443`, "-servername", host],
		{ input: "", encoding: "utf8" },
	);

	if (result.error) throw result.error;

	// Pipe into x509
	const pem = spawnSync(
		"openssl",
		["x509", "-in", "/dev/stdin", "-outform", "PEM"],
		{ input: result.stdout, encoding: "utf8" },
	);

	if (pem.error) throw pem.error;
	if (pem.status !== 0) throw new Error(pem.stderr);

	return pem.stdout;
}

const pem = getCertificateWithOpenSSL("expired.badssl.com");
const cert = new X509Certificate(pem);
console.log(cert);

/*
getCertificate("expired.badssl.com")
	.then((pem) => {
		const cert = new X509Certificate(pem);

		console.log(cert);
	})
	.catch(console.error);
*/

// getCertificate("ozana.cz")
// 	.then((pem) => {
// 		const cert = new X509Certificate(pem);
//
// 		console.log(cert);
//
// 		// console.log({
// 		// 	subject: cert.subject,
// 		// 	issuer: cert.issuer,
// 		// 	validFrom: cert.validFrom,
// 		// 	validTo: cert.validTo,
// 		// 	fingerprint: cert.fingerprint,
// 		// 	serialNumber: cert.serialNumber,
// 		// });
// 	})
// 	.catch(console.error);
//
// getCertificate("wikidi.cz")
// 	.then((pem) => {
// 		const cert = new X509Certificate(pem);
//
// 		cert.checkIP();
// 		console.log(cert);
//
// 		// console.log({
// 		// 	subject: cert.subject,
// 		// 	issuer: cert.issuer,
// 		// 	validFrom: cert.validFrom,
// 		// 	validTo: cert.validTo,
// 		// 	fingerprint: cert.fingerprint,
// 		// 	serialNumber: cert.serialNumber,
// 		// });
// 	})
// 	.catch(console.error);
