<?php
/**
 * One-time coupon minting — the WooCommerce twin of
 * shopify-app/app/lib/discount.server.ts (createOneTimeDiscount).
 *
 * Coupons are percent-type, single-use (usage_limit 1, once per user),
 * individual-use (no stacking, matching Shopify's non-combinable
 * DiscountCodeBasic), and expire after 24 hours. Codes are canonically
 * lowercase "ava-XXXXXXXX" because WooCommerce normalizes coupon codes with
 * wc_format_coupon_code; the code doubles as the attribution join key in
 * the events tables.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Coupons {

	/** Same unambiguous alphabet as the Shopify app's randomCode(), lowercased. */
	const CODE_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

	const CODE_LENGTH = 8;

	const EXPIRY_SECONDS = DAY_IN_SECONDS;

	/**
	 * Mint a single-use percentage coupon. Returns null (never throws) when
	 * the percentage is zero, WooCommerce is unavailable, or creation fails —
	 * the verify response then simply carries no discount, exactly like the
	 * Shopify path when discount creation errors.
	 *
	 * @param int $percentage 1–100.
	 * @return array|null {code: string, percentage: int}
	 */
	public static function mint( $percentage ) {
		$percentage = (int) $percentage;
		if ( $percentage <= 0 ) {
			return null;
		}
		if ( ! class_exists( 'WC_Coupon' ) ) {
			return null;
		}

		$code = AVA_Pay_Commerce::AVA_DISCOUNT_PREFIX . self::random_code();

		try {
			$coupon = new WC_Coupon();
			$coupon->set_code( $code );
			$coupon->set_discount_type( 'percent' );
			$coupon->set_amount( $percentage );
			$coupon->set_usage_limit( 1 );
			$coupon->set_usage_limit_per_user( 1 );
			$coupon->set_individual_use( true );
			$coupon->set_date_expires( time() + (int) apply_filters( 'ava_pay_coupon_expiry', self::EXPIRY_SECONDS ) );
			$coupon->set_description( sprintf( 'AVA Pay verified agent (%s)', $code ) );
			$saved = $coupon->save();
		} catch ( Throwable $e ) {
			// Throwable, not Exception: an engine Error (e.g. a TypeError
			// from a conflicting plugin's coupon filter) must degrade to
			// "no discount", never 500 the verify request before its event
			// is recorded.
			self::log( 'Coupon creation failed: ' . $e->getMessage() );
			return null;
		}

		if ( ! $saved ) {
			self::log( 'Coupon creation failed: save() returned 0 for ' . $code );
			return null;
		}

		return array(
			'code'       => $code,
			'percentage' => $percentage,
		);
	}

	private static function random_code() {
		$alphabet = self::CODE_ALPHABET;
		$max      = strlen( $alphabet ) - 1;
		$s        = '';
		for ( $i = 0; $i < self::CODE_LENGTH; $i++ ) {
			$s .= $alphabet[ wp_rand( 0, $max ) ];
		}
		return $s;
	}

	private static function log( $message ) {
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->error( $message, array( 'source' => 'ava-pay' ) );
		}
	}
}
