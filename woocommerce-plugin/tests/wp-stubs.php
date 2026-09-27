<?php
/**
 * The few WordPress functions the integration-layer tests reach, as plain
 * stand-ins. Escapers use htmlspecialchars, which is what the real ones
 * reduce to for these inputs; the point of the view test is that every value
 * goes THROUGH an escaper, not to re-test WordPress's.
 *
 * Required by EventsTest and VisitsViewTest only; the pure-core suites never
 * see these.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'AVA_PAY_WC_VERSION' ) ) {
	define( 'AVA_PAY_WC_VERSION', '0.4.0' );
}
if ( ! defined( 'ARRAY_A' ) ) {
	define( 'ARRAY_A', 'ARRAY_A' );
}

$GLOBALS['ava_test_options'] = array();
$GLOBALS['ava_test_dbdelta'] = array();

function esc_html( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}
function esc_attr( $text ) {
	return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
}
function esc_url( $url ) {
	return htmlspecialchars( (string) $url, ENT_QUOTES, 'UTF-8' );
}
function __( $text, $domain = 'default' ) { // phpcs:ignore
	return $text;
}
function esc_html__( $text, $domain = 'default' ) {
	return esc_html( $text );
}
function esc_html_e( $text, $domain = 'default' ) {
	echo esc_html( $text );
}
function number_format_i18n( $number ) {
	return number_format( (float) $number );
}
function get_option( $name, $fallback = false ) {
	return array_key_exists( $name, $GLOBALS['ava_test_options'] ) ? $GLOBALS['ava_test_options'][ $name ] : $fallback;
}
function update_option( $name, $value, $autoload = null ) {
	$GLOBALS['ava_test_options'][ $name ] = $value;
	return true;
}

/** Records inserts; the event class needs nothing else from $wpdb here. */
final class Ava_Test_Wpdb {
	/** @var string */
	public $prefix = 'wp_';
	/** @var array<int,array{0:string,1:array}> */
	public $inserts = array();

	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci';
	}

	public function insert( $table, $row ) {
		$this->inserts[] = array( $table, $row );
		return 1;
	}
}
