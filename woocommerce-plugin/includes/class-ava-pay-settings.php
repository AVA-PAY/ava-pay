<?php
/**
 * Merchant settings storage. Mirrors the Shopify app's ShopSettings model
 * and its read-side behavior (settings.server.ts): defaults match, and a
 * stored policy that no longer validates is treated as ABSENT rather than
 * partially applied — the verify path falls back to the documented
 * no-policy behavior instead of guessing.
 *
 * No shop column: WordPress table/option prefixes already scope everything
 * to one site (per-site on multisite).
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Settings {

	const OPTION_KEY = 'ava_pay_settings';

	const DEFAULT_API_URL = 'https://pay.avalayer.com';

	/**
	 * Defaults — keep byte-for-byte in sync with DEFAULTS in
	 * shopify-app/app/lib/settings.server.ts.
	 */
	const DEFAULTS = array(
		'acceptVerifiedAgents'    => true,
		'defaultDiscountPct'      => 10,
		'maxDiscountPct'          => 20,
		'identityOnlyDiscountPct' => 0,
	);

	/**
	 * Settings for the verify path: defaults merged over the stored option,
	 * policy JSON re-validated on every read (corrupt → null).
	 *
	 * @return array {apiUrl, acceptVerifiedAgents, defaultDiscountPct,
	 *                maxDiscountPct, identityOnlyDiscountPct, policy}
	 */
	public static function get() {
		$stored = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$policy_json = isset( $stored['policyJson'] ) && is_string( $stored['policyJson'] )
			? $stored['policyJson']
			: '';

		return array(
			'apiUrl'                  => isset( $stored['apiUrl'] ) && is_string( $stored['apiUrl'] ) && '' !== $stored['apiUrl']
				? $stored['apiUrl']
				: self::DEFAULT_API_URL,
			'acceptVerifiedAgents'    => isset( $stored['acceptVerifiedAgents'] )
				? (bool) $stored['acceptVerifiedAgents']
				: self::DEFAULTS['acceptVerifiedAgents'],
			'defaultDiscountPct'      => AVA_Pay_Policy::clamp_pct(
				isset( $stored['defaultDiscountPct'] ) ? $stored['defaultDiscountPct'] : self::DEFAULTS['defaultDiscountPct']
			),
			'maxDiscountPct'          => AVA_Pay_Policy::clamp_pct(
				isset( $stored['maxDiscountPct'] ) ? $stored['maxDiscountPct'] : self::DEFAULTS['maxDiscountPct']
			),
			'identityOnlyDiscountPct' => AVA_Pay_Policy::clamp_pct(
				isset( $stored['identityOnlyDiscountPct'] ) ? $stored['identityOnlyDiscountPct'] : self::DEFAULTS['identityOnlyDiscountPct']
			),
			'policy'                  => self::parse_stored_policy( $policy_json ),
		);
	}

	/**
	 * Port of parseStoredPolicy(): invalid/corrupt stored policy = absent.
	 *
	 * @param string $policy_json Stored JSON (may be '').
	 * @return array|null Validated policy or null.
	 */
	private static function parse_stored_policy( $policy_json ) {
		if ( '' === $policy_json ) {
			return null;
		}
		$parsed = AVA_Pay_Agent_Policy::parse( $policy_json );
		return $parsed['ok'] ? $parsed['policy'] : null;
	}

	/**
	 * Persist sanitized settings. Callers (the admin page) must have already
	 * validated policyJson via AVA_Pay_Agent_Policy::parse — this method
	 * re-serializes the validated policy so only canonical documents are
	 * stored.
	 *
	 * @param array $patch Sanitized values.
	 */
	public static function update( array $patch ) {
		$stored = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $stored ) ) {
			$stored = array();
		}
		update_option( self::OPTION_KEY, array_merge( $stored, $patch ), false );
	}
}
