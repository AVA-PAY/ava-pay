<?php
/**
 * Commerce funnel recording — the WooCommerce twin of the Shopify
 * checkouts/orders webhooks. Attribution happens via the AVA-minted coupon
 * code found on the cart/order, joined back to the verification event that
 * minted it.
 *
 * Funnel shape:
 *   'checkout' — an AVA coupon was applied to a cart (session-scoped; the
 *                closest Woo analog to Shopify's checkout-created webhook)
 *   'order'    — an order was placed
 *
 * Both are deduplicated on (kind, source_id), so repeated hook fires
 * (status transitions, re-applied coupons) can't double-count — the same
 * guarantee the Shopify app gets from upsert-keyed webhook handling.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Orders {

	public static function register() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}
		add_action( 'woocommerce_applied_coupon', array( __CLASS__, 'on_coupon_applied' ), 10, 1 );
		// Classic checkout and Store API (block checkout) both funnel here.
		add_action( 'woocommerce_checkout_order_processed', array( __CLASS__, 'on_order' ), 10, 1 );
		add_action( 'woocommerce_store_api_checkout_order_processed', array( __CLASS__, 'on_order' ), 10, 1 );
	}

	/**
	 * @param string $coupon_code Code as applied to the cart.
	 */
	public static function on_coupon_applied( $coupon_code ) {
		$code = AVA_Pay_Commerce::find_ava_discount_code( array( $coupon_code ) );
		if ( null === $code || ! function_exists( 'WC' ) || ! WC()->session ) {
			return;
		}

		$attribution = AVA_Pay_Events::find_verification_by_code( $code );

		AVA_Pay_Events::record_commerce_event(
			array(
				'kind'          => 'checkout',
				// One funnel row per storefront session per code.
				'source_id'     => WC()->session->get_customer_id() . ':' . $code,
				'discount_code' => $code,
				'platform'      => $attribution ? $attribution['platform'] : null,
				'protocol'      => $attribution ? $attribution['protocol'] : null,
			)
		);
	}

	/**
	 * @param int|WC_Order $order_or_id Order (Store API hook) or order id (classic hook).
	 */
	public static function on_order( $order_or_id ) {
		$order = $order_or_id instanceof WC_Order ? $order_or_id : wc_get_order( $order_or_id );
		if ( ! $order ) {
			return;
		}

		$code        = AVA_Pay_Commerce::find_ava_discount_code( $order->get_coupon_codes() );
		$attribution = null !== $code ? AVA_Pay_Events::find_verification_by_code( $code ) : null;

		// Only orders that touched AVA traffic are interesting; skip the rest
		// so the table doesn't mirror the whole store.
		if ( null === $code ) {
			return;
		}

		AVA_Pay_Events::record_commerce_event(
			array(
				'kind'          => 'order',
				'source_id'     => (string) $order->get_id(),
				'order_name'    => (string) $order->get_order_number(),
				'total_minor'   => AVA_Pay_Commerce::to_minor_units( $order->get_total() ),
				'currency'      => $order->get_currency(),
				'discount_code' => $code,
				'platform'      => $attribution ? $attribution['platform'] : null,
				'protocol'      => $attribution ? $attribution['protocol'] : null,
			)
		);
	}
}
