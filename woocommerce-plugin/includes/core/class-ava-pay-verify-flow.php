<?php
/**
 * The verify orchestration — the trust boundary, minus I/O.
 *
 * Faithful PHP port of the action() branching in
 * shopify-app/app/routes/proxy.verify.tsx: given the merchant settings, the
 * outcome of the AVA Pay /verify call, and the incoming request headers, it
 * decides (a) the VerificationEvent row to record, (b) the JSON response to
 * send, and (c) the discount percentage to mint a coupon for. The REST
 * controller does the I/O; every decision lives here so it is unit-testable
 * without WordPress.
 *
 * Failure mode unchanged from the Shopify app: if AVA Pay is unreachable or
 * the agent fails verification, we fail closed (allow: false, outcome
 * 'error'/'failed'). Storefront JS treats that as "no discount, proceed
 * normally" — never blocks the customer.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Verify_Flow {

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

		if ( empty( $call['ok'] ) ) {
			$reason = 'ava_' . ( isset( $call['error'] ) ? $call['error'] : 'network' );
			return array(
				'event'             => array(
					'outcome'  => 'error',
					'platform' => $platform_hint,
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
			return array(
				'event'             => array(
					'outcome'  => 'failed',
					'platform' => $platform_hint,
					'reason'   => ( isset( $result['reason'] ) && is_string( $result['reason'] ) ) ? $result['reason'] : null,
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
			$protocol = null;
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
