<?php
/**
 * Plugin Name: AVA Pay for WooCommerce
 * Plugin URI: https://avalayer.com
 * Description: Verify AI shopping agents (Visa TAP, Web Bot Auth, AP2) on your WooCommerce store. Set the rules, admit trusted agents, optionally mint one-time coupons, and see the traffic.
 * Version: 0.1.0
 * Author: AVA Layer
 * Author URI: https://avalayer.com
 * License: MIT
 * Text Domain: ava-pay-for-woocommerce
 *
 * WP 6.5 minimum is deliberate: it's the first release that enforces
 * `Requires Plugins`, so the plugin can never activate without WooCommerce
 * and silently show no settings screen.
 * Requires at least: 6.5
 * Requires PHP: 7.4
 * Requires Plugins: woocommerce
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AVA_PAY_WC_VERSION', '0.1.0' );
define( 'AVA_PAY_WC_PLUGIN_FILE', __FILE__ );
define( 'AVA_PAY_WC_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'AVA_PAY_WC_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Pure decision logic (no WordPress dependencies — also loaded by PHPUnit).
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-agent-policy.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-policy.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-agent-hint.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-commerce.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-verify-flow.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/core/class-ava-pay-rate-limiter.php';

// WordPress/WooCommerce integration layer.
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-settings.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-events.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-api-client.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-coupons.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-rest.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-orders.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-frontend.php';
require_once AVA_PAY_WC_PLUGIN_DIR . 'includes/class-ava-pay-admin.php';

register_activation_hook( __FILE__, array( 'AVA_Pay_Events', 'install' ) );

// dbDelta re-runs on version bumps (new columns land without reactivation).
add_action(
	'plugins_loaded',
	static function () {
		if ( get_option( 'ava_pay_db_version' ) !== AVA_PAY_WC_VERSION ) {
			AVA_Pay_Events::install();
		}
	}
);

add_action(
	'before_woocommerce_init',
	static function () {
		if ( class_exists( \Automattic\WooCommerce\Utilities\FeaturesUtil::class ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__, true );
		}
	}
);

add_action( 'rest_api_init', array( 'AVA_Pay_Rest', 'register_routes' ) );
add_action( 'init', array( 'AVA_Pay_Orders', 'register' ) );
add_action( 'init', array( 'AVA_Pay_Frontend', 'register' ) );
add_action( 'init', array( 'AVA_Pay_Admin', 'register' ) );
