<?php
/**
 * Best-effort labels read off an incoming agent request, for the verification
 * log. Telemetry only: the signature verifier on the API side is the authority
 * on what a request actually is, and these are what we can say about a request
 * that never got that far.
 *
 * They matter most on failures. A trusted verdict carries its own protocol and
 * identity, but a rejected or unverifiable one carries neither, so without
 * these a non-verified row reads "something did not go through" with no way to
 * tell a malformed Web Bot Auth request from an expired Visa TAP one.
 *
 * Faithful PHP port of shopify-app/app/lib/request-hints.ts
 * (extractAgentIdHint + sniffProtocolHint).
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
	 * Which protocol the request was *attempting*, mirroring the sniff rules in
	 * the API's MultiProtocolVerifier. Null when nothing recognisable was sent,
	 * or when the request carries two protocols at once, which the verifier
	 * rejects as ambiguous rather than picking one.
	 *
	 * @param array $headers Lower-cased header map.
	 * @return string|null 'web-bot-auth' | 'visa-tap' | 'ava-tap' | 'ap2' | null
	 */
	public static function sniff_protocol( array $headers ) {
		$has_sig_input = array_key_exists( 'signature-input', $headers );
		$sig_input     = $has_sig_input ? (string) $headers['signature-input'] : '';
		$has_http_sig  = $has_sig_input && array_key_exists( 'signature', $headers );
		$has_ap2       = array_key_exists( 'ap2-checkout-mandate', $headers )
			|| array_key_exists( 'ap2-attestation', $headers );

		if ( $has_http_sig && $has_ap2 ) {
			return null;
		}
		if ( $has_http_sig ) {
			if ( preg_match( '/[;\s]tag="web-bot-auth"/', $sig_input )
				|| array_key_exists( 'signature-agent', $headers ) ) {
				return 'web-bot-auth';
			}
			if ( preg_match( '/[;\s]tag="(agent-browser-auth|agent-payer-auth)"/', $sig_input ) ) {
				return 'visa-tap';
			}
			// No tag and no Signature-Agent: AVA's own TAP-style profile.
			return 'ava-tap';
		}
		if ( $has_ap2 ) {
			return 'ap2';
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
