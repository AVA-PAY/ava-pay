<?php
/**
 * Pure helpers for attributing WooCommerce orders back to verified agent
 * traffic. Port of shopify-app/app/lib/commerce.ts, adjusted for one
 * WooCommerce reality: Woo normalizes coupon codes to lowercase
 * (wc_format_coupon_code), so the AVA prefix match is case-insensitive and
 * minted codes are canonically lowercase ("ava-…") rather than Shopify's
 * uppercase "AVA-…".
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Commerce {

	/** Canonical (lowercase, Woo-normalized) minted-coupon prefix. */
	const AVA_DISCOUNT_PREFIX = 'ava-';

	/**
	 * First AVA-minted discount code on an order's coupon list, if any.
	 * Port of findAvaDiscountCode(); input is a flat list of code strings
	 * (WC_Order::get_coupon_codes() shape) rather than Shopify's
	 * {code: string}[] webhook shape.
	 *
	 * @param array|null $codes Coupon code strings.
	 * @return string|null Canonical lowercase code.
	 */
	public static function find_ava_discount_code( $codes ) {
		foreach ( (array) $codes as $code ) {
			if ( ! is_string( $code ) ) {
				continue;
			}
			$normalized = strtolower( $code );
			if ( 0 === strpos( $normalized, self::AVA_DISCOUNT_PREFIX ) ) {
				return $normalized;
			}
		}
		return null;
	}

	/**
	 * WooCommerce sends money as decimal strings/floats. Convert to integer
	 * minor units; null for absent/malformed values (never NaN into the
	 * database). Port of toMinorUnits().
	 *
	 * @param string|int|float|null $amount Decimal amount.
	 * @return int|null
	 */
	public static function to_minor_units( $amount ) {
		if ( null === $amount || '' === $amount ) {
			return null;
		}
		if ( ! is_numeric( $amount ) ) {
			return null;
		}
		$n = (float) $amount;
		if ( ! is_finite( $n ) ) {
			return null;
		}
		return (int) round( $n * 100 );
	}
}
