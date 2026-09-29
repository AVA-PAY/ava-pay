<?php
/**
 * The few WordPress functions the integration-layer tests reach, as plain
 * stand-ins. Escapers use htmlspecialchars, which is what the real ones
 * reduce to for these inputs; the point of the view test is that every value
 * goes THROUGH an escaper, not to re-test WordPress's.
 *
 * Required by EventsTest, VisitsViewTest and ComingSoonNoticeTest only; the
 * pure-core suites never see these.
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
$GLOBALS['ava_test_cron']    = array();
$GLOBALS['ava_test_filters'] = array();
$GLOBALS['ava_test_can']     = true;
$GLOBALS['ava_test_hooks']   = array();

function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	$GLOBALS['ava_test_hooks'][] = array( $hook, $callback, $priority );
	return true;
}
function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	return add_action( $hook, $callback, $priority, $args );
}
function current_user_can( $capability ) {
	return 'manage_woocommerce' === $capability && $GLOBALS['ava_test_can'];
}
function wp_die( $message = '' ) {
	throw new RuntimeException( 'wp_die: ' . $message );
}
function admin_url( $path = '' ) {
	return 'https://shop.example/wp-admin/' . ltrim( (string) $path, '/' );
}
function rest_url( $path = '' ) {
	return 'https://shop.example/wp-json/' . ltrim( (string) $path, '/' );
}
function get_transient( $key ) {
	return get_option( '_transient_' . $key );
}
function set_transient( $key, $value, $ttl = 0 ) {
	return update_option( '_transient_' . $key, $value );
}
function get_date_from_gmt( $date, $format = 'Y-m-d H:i:s' ) {
	return gmdate( $format, strtotime( $date . ' UTC' ) );
}
function wp_nonce_field( $action ) {
	echo '<input type="hidden" name="_wpnonce" value="nonce" />';
}
function submit_button( $text ) {
	echo '<input type="submit" value="' . esc_attr( $text ) . '" />';
}
function checked( $value ) {
	if ( $value ) {
		echo ' checked="checked"';
	}
}
function esc_textarea( $text ) {
	return esc_html( $text );
}

function apply_filters( $hook, $value ) {
	return array_key_exists( $hook, $GLOBALS['ava_test_filters'] ) ? $GLOBALS['ava_test_filters'][ $hook ] : $value;
}
function wp_next_scheduled( $hook ) {
	return isset( $GLOBALS['ava_test_cron'][ $hook ] ) ? $GLOBALS['ava_test_cron'][ $hook ]['time'] : false;
}
function wp_schedule_event( $time, $recurrence, $hook ) {
	$GLOBALS['ava_test_cron'][ $hook ] = array(
		'time'       => $time,
		'recurrence' => $recurrence,
	);
	return true;
}
function wp_clear_scheduled_hook( $hook ) {
	unset( $GLOBALS['ava_test_cron'][ $hook ] );
	return 1;
}

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

/** Records inserts and queries; the event class needs nothing else from $wpdb here. */
final class Ava_Test_Wpdb {
	/** @var string */
	public $prefix = 'wp_';
	/** @var array<int,array{0:string,1:array}> */
	public $inserts = array();
	/** @var string[] Prepared SQL passed to query(). */
	public $queries = array();
	/** @var int[] Row counts query() returns, in order; 0 once exhausted. */
	public $query_results = array();

	/** Enough of prepare() to read back: %i and %s quoted, %d as int. */
	public function prepare( $sql, ...$args ) {
		$i = 0;
		return preg_replace_callback(
			'/%[isd]/',
			static function ( $m ) use ( &$i, $args ) {
				$v = $args[ $i++ ];
				if ( '%i' === $m[0] ) {
					return '`' . $v . '`';
				}
				return '%d' === $m[0] ? (string) (int) $v : "'" . addslashes( (string) $v ) . "'";
			},
			$sql
		);
	}

	public function query( $sql ) {
		$this->queries[] = $sql;
		return array() === $this->query_results ? 0 : array_shift( $this->query_results );
	}

	public function get_charset_collate() {
		return 'DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci';
	}

	/** No rows: the admin screens render their empty states. */
	public function get_results( $sql, $output = null ) {
		return array();
	}

	public function insert( $table, $row ) {
		$this->inserts[] = array( $table, $row );
		return 1;
	}
}
