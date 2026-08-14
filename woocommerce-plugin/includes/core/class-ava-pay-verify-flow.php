<?php
/**
 * The verify orchestration — the trust boundary, minus I/O.
 *
 * PHP port of the action() branching in
 * shopify-app/app/routes/proxy.verify.tsx: given the merchant settings, the
 * outcome of the AVA Pay /verify call, and the incoming request headers, it
 * decides (a) the VerificationEvent row to record, (b) the JSON response to
 * send, and (c) the discount percentage to mint a coupon for. The REST
 * controller does the I/O; every decision lives here so it is unit-testable
 * without WordPress.
 *
 * One deliberate divergence from that twin, as of plugin 0.2.0: the untrusted
 * branch splits on the API's `conclusive` flag (see decide()). The Shopify
 * route still collapses every untrusted verdict to 'agent_blocked'; this
 * plugin leads on that fix and the Shopify app follows in its own pass.
 *
 * Failure mode unchanged: if AVA Pay is unreachable, or the agent fails
 * verification, or the verifier could not complete its checks, we fail closed
 * (allow: false, outcome 'error' / 'failed' / 'unverifiable'). Storefront JS
 * treats any of those as "no discount, proceed normally" and never blocks the
 * customer.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Verify_Flow {

	/**
	 * Storefront reason for a verdict the verifier could not complete. Never
	 * 'agent_blocked': we did not block this agent, we failed to check it.
	 */
	const REASON_UNVERIFIABLE = 'verification_unavailable';

	/**
	 * @param array $settings Merchant settings (see AVA_Pay_Policy).
	 * @param array $call     API client result:
	 *                        {ok: true, result: array} | {ok: false, error: string}.
	 * @param array $headers  Lower-cased incoming request headers.
	 * @return array {
	 *     @type array $event    VerificationEvent row (outcome, reason, platform,
	 *                           protocol, identity_only, discount_pct). The caller
	 *                           adds discount_code after minting.
	 *     @type array $response Body for the storefront: {allow, reason}.
	 *     @type int   $mint_discount_pct Coupon percentage to mint (0 = none).
	 * }
	 */
	public static function decide( array $settings, array $call, array $headers ) {
		$platform_hint = AVA_Pay_Agent_Hint::extract( $headers );
		// What the request was attempting. A rejected or unverifiable verdict
		// carries no protocol of its own, so without this a non-verified row
		// cannot be told apart from any other.
		$protocol_hint = AVA_Pay_Agent_Hint::sniff_protocol( $headers );

		if ( empty( $call['ok'] ) ) {
			$reason = 'ava_' . ( isset( $call['error'] ) ? $call['error'] : 'network' );
			return array(
				'event'             => array(
					'outcome'  => 'error',
					'platform' => $platform_hint,
					'protocol' => $protocol_hint,
					'reason'   => $reason,
				),
				'response'          => array(
					'allow'  => false,
					'reason' => $reason,
				),
				'mint_discount_pct' => 0,
			);
		}

		$result = is_array( $call['result'] ) ? $call['result'] : array();

		if ( empty( $result['trusted'] ) ) {
			$typed_reason = ( isset( $result['reason'] ) && is_string( $result['reason'] ) ) ? $result['reason'] : null;

			// An untrusted verdict is either "we checked and rejected it" or
			// "we never managed to check", and telling a merchant we blocked an
			// agent when we could not reach a trust root is a claim we cannot
			// support. Both stay allow:false; only the story changes.
			//
			// A separate outcome value rather than an overloaded 'failed' with
			// a distinguishing reason: the reason column already carries the
			// typed API reason (which is what makes the row diagnosable), and
			// the vocabulary of could-not-check reasons will grow, so any
			// later reader counting real rejections would have to know the
			// full list. The outcome answers it directly.
			if ( ! self::is_conclusive( $result ) ) {
				return array(
					'event'             => array(
						'outcome'  => 'unverifiable',
						'platform' => $platform_hint,
						'protocol' => $protocol_hint,
						'reason'   => $typed_reason,
					),
					'response'          => array(
						'allow'  => false,
						'reason' => self::REASON_UNVERIFIABLE,
					),
					'mint_discount_pct' => 0,
				);
			}

			return array(
				'event'             => array(
					'outcome'  => 'failed',
					'platform' => $platform_hint,
					'protocol' => $protocol_hint,
					'reason'   => $typed_reason,
				),
				'response'          => array(
					'allow'  => false,
					'reason' => 'agent_blocked',
				),
				'mint_discount_pct' => 0,
			);
		}

		$agent    = ( isset( $result['agent'] ) && is_array( $result['agent'] ) ) ? $result['agent'] : null;
		$platform = ( null !== $agent && isset( $agent['id'] ) && is_string( $agent['id'] ) )
			? $agent['id']
			: $platform_hint;
		if ( isset( $result['protocol'] ) && is_string( $result['protocol'] ) ) {
			$protocol = $result['protocol'];
		} elseif ( null !== $agent && isset( $agent['protocol'] ) && is_string( $agent['protocol'] ) ) {
			$protocol = $agent['protocol'];
		} else {
			$protocol = $protocol_hint;
		}

		$identity_only = ! ( isset( $result['mandate'] ) && is_array( $result['mandate'] ) );

		$decision = AVA_Pay_Policy::apply_merchant_policy( $settings, $result, $platform );

		if ( empty( $decision['allow'] ) ) {
			return array(
				'event'             => array(
					'outcome'       => 'policy_blocked',
					'platform'      => $platform,
					'protocol'      => $protocol,
					'reason'        => $decision['reason'],
					'identity_only' => $identity_only,
				),
				'response'          => array(
					'allow'  => false,
					'reason' => $decision['reason'],
				),
				'mint_discount_pct' => 0,
			);
		}

		return array(
			'event'             => array(
				'outcome'       => 'verified',
				'platform'      => $platform,
				'protocol'      => $protocol,
				'reason'        => null,
				'identity_only' => $identity_only,
				'discount_pct'  => $decision['discountPct'],
			),
			'response'          => array(
				'allow'  => true,
				'reason' => 'verified',
			),
			'mint_discount_pct' => (int) $decision['discountPct'],
		);
	}

	/**
	 * Did the verifier complete its checks?
	 *
	 * `conclusive` is additive on the API's VerificationResult: false ONLY on
	 * could-not-check paths (a trust root was unreachable, e.g.
	 * directory_unavailable or key_directory_unavailable), true when the
	 * request was definitively rejected. Absent reads as true, matching the
	 * API's own forward-compatibility rule, so verdicts minted or cached
	 * before the field existed keep their old meaning instead of silently
	 * becoming "could not check".
	 *
	 * A present but non-boolean value is malformed, not a signal, and is read
	 * the same way as absent. Either way the caller still fails closed; this
	 * only decides what we tell the merchant.
	 *
	 * @param array $result Decoded VerificationResult.
	 * @return bool
	 */
	public static function is_conclusive( array $result ) {
		if ( array_key_exists( 'conclusive', $result ) && is_bool( $result['conclusive'] ) ) {
			return $result['conclusive'];
		}
		return true;
	}

	/**
	 * Headers that must NEVER be forwarded to the verification API. The
	 * Shopify twin passes all headers too, but Shopify's app proxy strips
	 * cookies before the app sees them — WordPress does not, and the
	 * storefront embed calls the endpoint same-origin, so without this
	 * denylist logged-in WP/Woo session cookies (and any Authorization
	 * header WP synthesizes) would ship off-site inside the /verify payload.
	 * None of these are ever part of an agent's signature base.
	 */
	const SENSITIVE_HEADERS = array( 'cookie', 'authorization', 'x-wp-nonce' );

	/**
	 * Drop credential-bearing headers before the map leaves the site.
	 *
	 * @param array $headers Lower-cased header map.
	 * @return array Same map minus SENSITIVE_HEADERS.
	 */
	public static function strip_sensitive_headers( array $headers ) {
		foreach ( self::SENSITIVE_HEADERS as $name ) {
			unset( $headers[ $name ] );
		}
		return $headers;
	}

	/**
	 * Config problems that make the canonical signed URL unusable for
	 * RFC 9421 verification. Agents sign the documented
	 * https://…/wp-json/… form; if the site cannot produce that URL the
	 * signature base recomputes differently and EVERY verification fails
	 * with invalid_signature — so we fail loud at the config surface
	 * instead of leaving bare failure rows.
	 *
	 * @param string $signed_url The URL the REST layer will present to the API.
	 * @return string[] Problem codes: 'plain_permalinks', 'not_https'. Empty = signable.
	 */
	public static function signed_url_problems( $signed_url ) {
		$problems = array();
		if ( false !== strpos( (string) $signed_url, 'rest_route=' ) ) {
			$problems[] = 'plain_permalinks';
		}
		$scheme = parse_url( (string) $signed_url, PHP_URL_SCHEME );
		if ( 'https' !== strtolower( (string) $scheme ) ) {
			$problems[] = 'not_https';
		}
		return $problems;
	}

	/**
	 * Interpret an HTTP response from AVA Pay /verify. Port of the
	 * status/body handling in AvaPayClient.verify() (shopify-app
	 * lib/ava.server.ts): 200 and 403 are the only statuses with valid
	 * verification bodies; anything else is bad_response. A body that fails
	 * to parse maps to 'network', matching the TS client where res.json()
	 * throwing lands in the generic network catch.
	 *
	 * @param int    $status HTTP status code.
	 * @param string $body   Raw response body.
	 * @return array {ok: true, result: array} | {ok: false, error: string, status?: int}
	 */
	public static function interpret_api_response( $status, $body ) {
		if ( 200 !== $status && 403 !== $status ) {
			return array(
				'ok'     => false,
				'error'  => 'bad_response',
				'status' => (int) $status,
			);
		}
		$decoded = json_decode( (string) $body, true );
		if ( json_last_error() !== JSON_ERROR_NONE || ! is_array( $decoded ) ) {
			return array(
				'ok'    => false,
				'error' => 'network',
			);
		}
		return array(
			'ok'     => true,
			'result' => $decoded,
		);
	}
}
