<?php
/**
 * Storefront embed loader. Mirrors the Shopify app-proxy embed
 * (proxy.embed[.js].tsx): the script only matters on page loads where an
 * agent arrived with signature material in the URL query, so it is enqueued
 * only when those parameters are present — every other visitor pays zero
 * bytes.
 *
 * Production note: real protocol-speaking agents do NOT need this script —
 * they call /wp-json/ava-pay/v1/verify-agent directly with their signed
 * request. This path is for storefronts where the agent has been redirected
 * through a regular page load (e.g. for testing, or for older agents that
 * hint via URL params).
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Frontend {

	/** Headers the agent's signature requires, passed as URL params. */
	const SIG_PARAMS = array( 'signature', 'signature-input', 'content-digest', 'x-ava-mandate' );

	public static function register() {
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'maybe_enqueue' ) );
	}

	public static function maybe_enqueue() {
		if ( ! self::request_has_signature_params() ) {
			return;
		}

		wp_enqueue_script(
			'ava-pay-embed',
			AVA_PAY_WC_PLUGIN_URL . 'assets/js/ava-pay-embed.js',
			array(),
			AVA_PAY_WC_VERSION,
			true
		);
		wp_localize_script(
			'ava-pay-embed',
			'avaPayEmbed',
			array(
				// rest_url() keeps this working under plain permalinks too.
				'endpoint'     => rest_url( AVA_Pay_Rest::NAMESPACE_V1 . AVA_Pay_Rest::ROUTE ),
				'storeApiCart' => rest_url( 'wc/store/v1/cart' ),
			)
		);
	}

	private static function request_has_signature_params() {
		// Detection only — the values are read (and signature-verified) later,
		// never trusted here. phpcs:ignore WordPress.Security.NonceVerification.Recommended
		foreach ( self::SIG_PARAMS as $param ) {
			if ( isset( $_GET[ $param ] ) ) {
				return true;
			}
		}
		return false;
	}
}
