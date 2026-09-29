<?php
/**
 * Pins what the Coming soon notice promises, against WooCommerce's own
 * classes: the placeholder is served from template_include, which WordPress
 * runs after template_redirect, so the page-visit gate (template_redirect,
 * priority 0) still records a signed visit in both modes; and a user with
 * manage_woocommerce always sees the real store.
 *
 * Loads Automattic\WooCommerce\Internal\ComingSoon\ComingSoonHelper and
 * ComingSoonRequestHandler from a WooCommerce checkout, found at
 * AVA_PAY_WC_SOURCE (CI downloads the same woocommerce.zip that
 * .wp-env.json installs, and fails if it is missing) or in a local wp-env
 * cache. Skipped without either.
 * If WooCommerce ever moves the placeholder to an earlier hook, this fails
 * and the notice wording ("Agents that visit are still listed") has to be
 * re-checked. The end-to-end proof in real WordPress is in the 0.4.1 PR body.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/wp-stubs.php';
require_once __DIR__ . '/../includes/class-ava-pay-settings.php';
require_once __DIR__ . '/../includes/class-ava-pay-page-visits.php';

if ( ! function_exists( 'is_404' ) ) {
	function is_404() {
		return false;
	}
}

final class ComingSoonGateTest extends TestCase {

	const HELPER  = 'Automattic\\WooCommerce\\Internal\\ComingSoon\\ComingSoonHelper';
	const HANDLER = 'Automattic\\WooCommerce\\Internal\\ComingSoon\\ComingSoonRequestHandler';

	/**
	 * Every hook WooCommerce's handler registers while the store is hidden.
	 * template_include serves the placeholder; the other three style it and
	 * none of them can end the request.
	 */
	const EXPECTED_HOOKS = array( 'after_setup_theme', 'template_include', 'wp_enqueue_scripts', 'wp_theme_json_data_theme' );

	/** @var string */
	private static $source = '';

	public static function setUpBeforeClass(): void {
		$candidates = array();
		$env        = getenv( 'AVA_PAY_WC_SOURCE' );
		$home       = getenv( 'HOME' );
		if ( is_string( $env ) && '' !== $env ) {
			$candidates[] = $env;
		} elseif ( is_string( $home ) && '' !== $home ) {
			$candidates = array_merge( $candidates, (array) glob( $home . '/.wp-env/*/woocommerce' ) );
		}
		foreach ( $candidates as $dir ) {
			if ( is_file( $dir . '/src/Internal/ComingSoon/ComingSoonRequestHandler.php' ) ) {
				self::$source = rtrim( $dir, '/' );
				break;
			}
		}
		if ( '' === self::$source ) {
			return;
		}
		if ( ! class_exists( self::HELPER, false ) ) {
			require_once self::$source . '/src/Internal/ComingSoon/ComingSoonHelper.php';
		}
		if ( ! class_exists( self::HANDLER, false ) ) {
			require_once self::$source . '/src/Internal/ComingSoon/ComingSoonRequestHandler.php';
		}
	}

	protected function setUp(): void {
		$env = getenv( 'AVA_PAY_WC_SOURCE' );
		if ( '' === self::$source && is_string( $env ) && '' !== $env ) {
			$this->fail( "AVA_PAY_WC_SOURCE is set but has no WooCommerce Coming soon classes: {$env}" );
		}
		if ( '' === self::$source ) {
			$this->markTestSkipped( 'No WooCommerce checkout: set AVA_PAY_WC_SOURCE to an unzipped woocommerce/ directory.' );
		}
		$GLOBALS['ava_test_options'] = array();
		$GLOBALS['ava_test_hooks']   = array();
		$GLOBALS['ava_test_can']     = false;
		$property                    = new ReflectionProperty( self::HANDLER, 'show_coming_soon' );
		$property->setValue( null, false );
	}

	/**
	 * Run WooCommerce's init() and its plugins_loaded callback, as WordPress
	 * would, and return what got hooked after that.
	 *
	 * @return array{0:object,1:array<int,array{0:string,1:mixed,2:int}>}
	 */
	private function boot( string $store_pages_only ): array {
		$GLOBALS['ava_test_options']['woocommerce_coming_soon']      = 'yes';
		$GLOBALS['ava_test_options']['woocommerce_store_pages_only'] = $store_pages_only;

		$helper  = self::HELPER;
		$handler = self::HANDLER;
		$handler = new $handler();
		$handler->init( new $helper() );

		$loaded = array_values(
			array_filter(
				$GLOBALS['ava_test_hooks'],
				static function ( $hook ) {
					return 'plugins_loaded' === $hook[0];
				}
			)
		);
		$this->assertCount( 1, $loaded, 'WooCommerce defers its Coming soon hooks to plugins_loaded' );

		$GLOBALS['ava_test_hooks'] = array();
		call_user_func( $loaded[0][1] );
		return array( $handler, $GLOBALS['ava_test_hooks'] );
	}

	public function test_placeholder_is_served_from_template_include_in_both_modes(): void {
		foreach ( array( 'no', 'yes' ) as $store_pages_only ) {
			list( $handler, $hooks ) = $this->boot( $store_pages_only );

			$names = array_column( $hooks, 0 );
			sort( $names );
			$this->assertSame( self::EXPECTED_HOOKS, $names, "store_pages_only={$store_pages_only}: WooCommerce's Coming soon hooks changed; re-check the notice wording" );
			$this->assertNotContains( 'template_redirect', $names );

			foreach ( $hooks as $hook ) {
				if ( 'template_include' === $hook[0] ) {
					$this->assertSame( array( $handler, 'handle_template_include' ), $hook[1] );
				}
			}
		}
	}

	public function test_page_visit_gate_runs_first(): void {
		// WordPress's template-loader.php fires template_redirect, then
		// filters template_include, so priority 0 on template_redirect is
		// ahead of anything the placeholder does.
		AVA_Pay_Page_Visits::register();
		$this->assertSame(
			array( array( 'template_redirect', array( 'AVA_Pay_Page_Visits', 'maybe_schedule' ), 0 ) ),
			$GLOBALS['ava_test_hooks']
		);
	}

	public function test_live_store_hooks_nothing(): void {
		$GLOBALS['ava_test_options']['woocommerce_coming_soon'] = 'no';
		$helper  = self::HELPER;
		$handler = self::HANDLER;
		( new $handler() )->init( new $helper() );
		$GLOBALS['ava_test_hooks'][0][1]();
		$this->assertSame( array( 'plugins_loaded' ), array_column( $GLOBALS['ava_test_hooks'], 0 ) );
	}

	public function test_store_managers_see_the_store_visitors_see_the_placeholder(): void {
		list( $handler ) = $this->boot( 'no' );
		$should_show     = new ReflectionMethod( self::HANDLER, 'should_show_coming_soon' );

		$GLOBALS['ava_test_can'] = true;
		$this->assertFalse( $should_show->invoke( $handler ), 'manage_woocommerce sees the real store' );

		$GLOBALS['ava_test_can'] = false;
		$this->assertTrue( $should_show->invoke( $handler ), 'a visitor who is not logged in gets the placeholder' );
	}
}
