<?php
/**
 * PHPUnit bootstrap — loads ONLY the pure core classes (includes/core/*),
 * which are WordPress-free by contract. The WP/WooCommerce integration layer
 * (REST controller, dbDelta storage, WC_Coupon minting, admin page) is thin
 * I/O around these classes and is exercised via wp-env (see the PR
 * QUICKSTART), not here.
 *
 * @package AVA_Pay
 */

define( 'AVA_PAY_TESTS', true );

$core = __DIR__ . '/../includes/core/';
require_once $core . 'class-ava-pay-agent-policy.php';
require_once $core . 'class-ava-pay-policy.php';
require_once $core . 'class-ava-pay-agent-hint.php';
require_once $core . 'class-ava-pay-commerce.php';
require_once $core . 'class-ava-pay-verify-flow.php';
require_once $core . 'class-ava-pay-rate-limiter.php';

/**
 * Shared fixture access.
 *
 * @param string $name Fixture file name.
 * @return array Decoded JSON (assoc).
 */
function ava_pay_load_fixture( $name ) {
	$path = __DIR__ . '/fixtures/' . $name;
	if ( ! is_file( $path ) ) {
		fwrite( STDERR, "Missing fixture {$path} — run the generators in woocommerce-plugin/scripts/ first.\n" );
		exit( 1 );
	}
	$decoded = json_decode( (string) file_get_contents( $path ), true );
	if ( ! is_array( $decoded ) ) {
		fwrite( STDERR, "Fixture {$path} is not valid JSON.\n" );
		exit( 1 );
	}
	return $decoded;
}
