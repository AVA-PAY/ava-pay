<?php
/**
 * Pure decision logic combining merchant settings, the optional per-platform
 * policy document, and a /verify result.
 *
 * Faithful PHP port of shopify-app/app/lib/policy.ts (applyMerchantPolicy).
 * Covered by the golden-file parity test — change the TS first, regenerate,
 * then port.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Policy {

	/**
	 * Port of applyMerchantPolicy().
	 *
	 * @param array $settings {
	 *     Merchant settings.
	 *     @type bool       $acceptVerifiedAgents
	 *     @type int        $defaultDiscountPct
	 *     @type int        $maxDiscountPct
	 *     @type int        $identityOnlyDiscountPct Discount tier for identity-only
	 *           verified agents (trusted but carrying no buyer mandate, e.g.
	 *           Web Bot Auth). 0 — the default — admits them with no discount.
	 *     @type array|null $policy Validated per-platform policy, or null.
	 * }
	 * @param array       $result   Decoded /verify response (trusted branch keys:
	 *                              trusted, mandate, discount, agent, protocol).
	 * @param string|null $platform Canonical agent platform.
	 * @return array {allow: true, discountPct: int, reason: 'verified'}
	 *             | {allow: false, reason: string}
	 */
	public static function apply_merchant_policy( array $settings, array $result, $platform = null ) {
		if ( empty( $settings['acceptVerifiedAgents'] ) ) {
			return array(
				'allow'  => false,
				'reason' => 'merchant_disabled',
			);
		}
		if ( empty( $result['trusted'] ) ) {
			return array(
				'allow'  => false,
				'reason' => 'agent_blocked',
			);
		}

		$rule = ! empty( $settings['policy'] )
			? AVA_Pay_Agent_Policy::resolve_rule( $settings['policy'], $platform )
			: null;

		// A mandate is only meaningful as an object; anything else counts as
		// absent (the TS side can't receive a non-object mandate at all).
		$mandate = ( isset( $result['mandate'] ) && is_array( $result['mandate'] ) ) ? $result['mandate'] : null;

		if ( null !== $rule ) {
			if ( 'block' === $rule['action'] ) {
				return array(
					'allow'  => false,
					'reason' => 'blocked_by_policy',
				);
			}
			// Challenge = this platform must come back with buyer authorization.
			// Mandate-backed requests pass; identity-only ones get a typed retry hint.
			if ( 'challenge' === $rule['action'] && null === $mandate ) {
				return array(
					'allow'  => false,
					'reason' => 'challenge_required',
				);
			}
			// Spend rule: refuse mandates authorizing more than the platform cap.
			if (
				isset( $rule['maxSpendMinor'] )
				&& null !== $mandate
				&& isset( $mandate['maxAmountMinor'] )
				&& is_numeric( $mandate['maxAmountMinor'] )
				&& $mandate['maxAmountMinor'] > $rule['maxSpendMinor']
			) {
				return array(
					'allow'  => false,
					'reason' => 'spend_limit_exceeded',
				);
			}
		}

		// The effective cap is the intersection of the global cap and the rule cap.
		$cap_pct = ( null !== $rule && isset( $rule['maxDiscountPct'] ) )
			? min( $settings['maxDiscountPct'], $rule['maxDiscountPct'] )
			: $settings['maxDiscountPct'];

		// Identity-only trust proves who the agent is, not that a buyer
		// authorized spending. Admit it — that's the point of verification —
		// but discounts come only from the merchant's explicit identity-only
		// tier. Neither a verifier discount hint nor a platform offer is
		// honored without a mandate.
		if ( null === $mandate ) {
			$pct = max( 0, min( $settings['identityOnlyDiscountPct'], $cap_pct ) );
			return array(
				'allow'       => true,
				'discountPct' => (int) $pct,
				'reason'      => 'verified',
			);
		}

		// Mandate-backed: platform offer > verifier hint > merchant default.
		// A PRESENT discount key always takes the hint branch, even when its
		// value is null/garbage — matching the TS `result.discount !==
		// undefined` check, where JSON null yields Math.round(null*100) = 0.
		// Falling back to defaultDiscountPct here would grant MORE than the
		// reference implementation for the same response.
		if ( null !== $rule && isset( $rule['offerDiscountPct'] ) ) {
			$base_pct = $rule['offerDiscountPct'];
		} elseif ( array_key_exists( 'discount', $result ) ) {
			$base_pct = is_numeric( $result['discount'] ) ? (int) round( $result['discount'] * 100 ) : 0;
		} else {
			$base_pct = $settings['defaultDiscountPct'];
		}
		$final_pct = max( 0, min( $base_pct, $cap_pct ) );
		return array(
			'allow'       => true,
			'discountPct' => (int) $final_pct,
			'reason'      => 'verified',
		);
	}

	/**
	 * Port of clampPct().
	 *
	 * @param mixed $n Candidate percentage.
	 * @return int 0–100.
	 */
	public static function clamp_pct( $n ) {
		if ( ! is_numeric( $n ) || ! is_finite( (float) $n ) ) {
			return 0;
		}
		return (int) max( 0, min( 100, round( (float) $n ) ) );
	}
}
