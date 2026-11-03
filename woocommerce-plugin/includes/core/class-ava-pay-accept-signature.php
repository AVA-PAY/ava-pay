<?php
/**
 * The Accept-Signature value this site sends to unsigned and unverified
 * callers (draft-ietf-webbotauth-httpsig-protocol-01 Section 5.3, RFC 9421
 * Section 5): an origin that expects a signature SHOULD request one, SHOULD
 * include the request on a refusal, and MAY send it on a success to say a
 * signed request would be treated differently. We send it on the ping and on
 * every response whose verification outcome is not trusted, and never on a
 * trusted one.
 *
 * MIRROR of the Shopify twin's canonical definition
 * (shopify-app/app/lib/accept-signature.ts), byte for byte; the API suite's
 * tests/accept-signature.test.ts reads both sources and fails on drift.
 * Change the TypeScript first, then this file. The rationale for each
 * component and parameter lives with the TypeScript definition.
 *
 * Pure core class: no WordPress calls, unit-tested in PHPUnit.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Accept_Signature {

	const HEADER = 'Accept-Signature';

	const VALUE = 'sig1=("@authority" "content-digest" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"';

	/**
	 * The header value to attach for a given verification outcome, or null to
	 * send nothing: the request goes to callers we did not verify (unsigned,
	 * failed, inconclusive) and is withheld from trusted ones.
	 *
	 * @param bool $trusted Whether the verification outcome was trusted.
	 * @return string|null
	 */
	public static function for_outcome( $trusted ) {
		return $trusted ? null : self::VALUE;
	}
}
