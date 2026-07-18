<?php
/**
 * Best-effort agent ID extraction for the verification log — telemetry only;
 * the signature verifier on the API side is the authority.
 *
 * Faithful PHP port of extractAgentIdHint() in
 * shopify-app/app/routes/proxy.verify.tsx.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Agent_Hint {

	/**
	 * Web Bot Auth requests carry the agent operator's origin in
	 * Signature-Agent (e.g. "https://chatgpt.com") — a far better dashboard
	 * label than the key thumbprint in keyid, which rotates and means nothing
	 * to a merchant. TAP requests have no Signature-Agent, so they keep using
	 * keyid (the agent ID).
	 *
	 * @param array $headers Lower-cased header map.
	 * @return string|null
	 */
	public static function extract( array $headers ) {
		$sig_agent = isset( $headers['signature-agent'] ) ? $headers['signature-agent'] : null;
		if ( is_string( $sig_agent ) && '' !== $sig_agent ) {
			// Matches both wire forms: "https://origin" and sig1="https://origin".
			if ( preg_match( '/"(https:\/\/[^"]+)"/', $sig_agent, $m ) ) {
				$origin = self::https_origin( $m[1] );
				if ( null !== $origin ) {
					return $origin;
				}
				// fall through to keyid
			}
		}
		$sig_input = isset( $headers['signature-input'] ) ? $headers['signature-input'] : null;
		if ( ! is_string( $sig_input ) || '' === $sig_input ) {
			return null;
		}
		if ( preg_match( '/keyid="([^"]+)"/', $sig_input, $m ) ) {
			return $m[1];
		}
		return null;
	}

	/**
	 * Lower-cased https origin of a URL, mirroring `new URL(u).origin` in JS:
	 * scheme://host, default port (443) omitted, non-default port kept.
	 *
	 * @param string $url Candidate URL.
	 * @return string|null Null when the URL doesn't parse to an https origin.
	 */
	private static function https_origin( $url ) {
		$parts = parse_url( $url );
		if ( false === $parts || ! isset( $parts['scheme'], $parts['host'] ) ) {
			return null;
		}
		$scheme = strtolower( $parts['scheme'] );
		if ( 'https' !== $scheme ) {
			return null;
		}
		$origin = 'https://' . strtolower( $parts['host'] );
		if ( isset( $parts['port'] ) && 443 !== (int) $parts['port'] ) {
			$origin .= ':' . (int) $parts['port'];
		}
		return $origin;
	}
}
