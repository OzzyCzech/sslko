/**
 * Constants used throughout the SSL certificate validation library.
 */

/** Default HTTPS port */
export const DEFAULT_HTTPS_PORT = 443;

/** Default connection timeout in milliseconds */
export const DEFAULT_TIMEOUT_MS = 5000;

/** Minimum valid port number */
export const MIN_PORT = 1;

/** Maximum valid port number */
export const MAX_PORT = 65535;

/** Milliseconds in a day for date calculations */
export const MILLISECONDS_PER_DAY = 8.64e7;

/** Common certificate validity periods */
export const CERTIFICATE_PERIODS = {
	/** 30 days in milliseconds */
	THIRTY_DAYS: 30 * MILLISECONDS_PER_DAY,
	/** 90 days in milliseconds */
	NINETY_DAYS: 90 * MILLISECONDS_PER_DAY,
	/** 1 year in milliseconds */
	ONE_YEAR: 365 * MILLISECONDS_PER_DAY,
	/** 2 years in milliseconds */
	TWO_YEARS: 2 * 365 * MILLISECONDS_PER_DAY,
} as const;

/** DNS prefix for Subject Alternative Names */
export const DNS_PREFIX = "DNS:";

/** IP Address prefix for Subject Alternative Names */
export const IP_ADDRESS_PREFIX = "IP Address:";

/** Wildcard prefix for domain matching */
export const WILDCARD_PREFIX = "*.";

/** Weak signature algorithms that should be flagged */
export const WEAK_SIGNATURE_ALGORITHMS = [
	"md5WithRSAEncryption",
	"sha1WithRSAEncryption",
	"md5WithRSA",
	"sha1WithRSA",
] as const;

/** Minimum recommended RSA key sizes */
export const MIN_RSA_KEY_SIZE = 2048;
