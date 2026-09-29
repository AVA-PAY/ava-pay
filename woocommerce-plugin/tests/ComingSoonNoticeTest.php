<?php
/**
 * The Coming soon warning: which mode WooCommerce's options mean, and that
 * the notice appears on this plugin's two screens (rendered for real, the
 * settings page and Agent visits) with the right wording, and nowhere else.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/wp-stubs.php';
require_once __DIR__ . '/../includes/class-ava-pay-settings.php';
require_once __DIR__ . '/../includes/class-ava-pay-events.php';
require_once __DIR__ . '/../includes/class-ava-pay-rest.php';
require_once __DIR__ . '/../includes/class-ava-pay-page-visits.php';
require_once __DIR__ . '/../includes/class-ava-pay-visits-view.php';
require_once __DIR__ . '/../includes/class-ava-pay-coming-soon-notice.php';
require_once __DIR__ . '/../includes/class-ava-pay-admin.php';

final class ComingSoonNoticeTest extends TestCase {

	const SITE_TEXT    = 'Your store is in Coming soon mode. Visitors who are not logged in, including AI agents, see a placeholder page instead of your site.';
	const STORE_TEXT   = 'Your store is in Coming soon mode. Visitors who are not logged in, including AI agents, see a placeholder page instead of your store pages.';
	const LOGGED_IN    = 'You see the store normally because you are logged in.';
	const LISTED_HERE  = 'Agents that visit are still listed here, but they see the placeholder, not your products.';
	const LISTED_THERE = 'Agents that visit are still listed under Agent visits, but they see the placeholder, not your products.';
	const LINK         = '<a href="https://shop.example/wp-admin/admin.php?page=wc-settings&amp;tab=site-visibility">Set Site visibility to Live</a>.';

	protected function setUp(): void {
		$GLOBALS['ava_test_options'] = array();
		$GLOBALS['ava_test_can']     = true;
		$GLOBALS['ava_test_hooks']   = array();
		$GLOBALS['wpdb']             = new Ava_Test_Wpdb();
	}

	/**
	 * @param string|null $coming_soon      woocommerce_coming_soon, null = option absent.
	 * @param string|null $store_pages_only woocommerce_store_pages_only, null = option absent.
	 */
	private function options( $coming_soon, $store_pages_only ): void {
		foreach ( array( AVA_Pay_Coming_Soon::OPTION => $coming_soon, AVA_Pay_Coming_Soon::STORE_PAGES_ONLY_OPTION => $store_pages_only ) as $name => $value ) {
			if ( null === $value ) {
				unset( $GLOBALS['ava_test_options'][ $name ] );
			} else {
				$GLOBALS['ava_test_options'][ $name ] = $value;
			}
		}
	}

	private function settings_page(): string {
		ob_start();
		AVA_Pay_Admin::render_page();
		return (string) ob_get_clean();
	}

	private function visits_page(): string {
		ob_start();
		AVA_Pay_Admin::render_visits_page();
		return (string) ob_get_clean();
	}

	public function test_mode_reads_the_options_the_way_woocommerce_does(): void {
		$cases = array(
			array( 'yes', 'no', AVA_Pay_Coming_Soon::MODE_SITE ),
			array( 'yes', null, AVA_Pay_Coming_Soon::MODE_SITE ),
			array( 'yes', 'yes', AVA_Pay_Coming_Soon::MODE_STORE ),
			array( 'no', 'yes', null ),
			array( 'no', 'no', null ),
			array( null, null, null ),
			array( null, 'yes', null ),
			array( '', 'yes', null ),
			array( 'YES', 'yes', null ),
			array( '1', 'yes', null ),
		);
		foreach ( $cases as list( $coming_soon, $store_pages_only, $expected ) ) {
			$this->options( $coming_soon, $store_pages_only );
			$this->assertSame(
				$expected,
				AVA_Pay_Coming_Soon::mode( 'get_option' ),
				var_export( array( $coming_soon, $store_pages_only ), true )
			);
		}
	}

	public function test_whole_site_notice_on_both_screens(): void {
		$this->options( 'yes', 'no' );

		$settings = $this->settings_page();
		$this->assertStringContainsString( self::SITE_TEXT, $settings );
		$this->assertStringContainsString( self::LOGGED_IN, $settings );
		$this->assertStringContainsString( self::LISTED_THERE, $settings );
		$this->assertStringContainsString( self::LINK, $settings );
		$this->assertStringNotContainsString( self::STORE_TEXT, $settings );

		$visits = $this->visits_page();
		$this->assertStringContainsString( self::SITE_TEXT, $visits );
		$this->assertStringContainsString( self::LOGGED_IN, $visits );
		$this->assertStringContainsString( self::LISTED_HERE, $visits );
		$this->assertStringContainsString( self::LINK, $visits );
		$this->assertStringNotContainsString( self::STORE_TEXT, $visits );
	}

	public function test_store_pages_only_notice_on_both_screens(): void {
		$this->options( 'yes', 'yes' );

		$settings = $this->settings_page();
		$this->assertStringContainsString( self::STORE_TEXT, $settings );
		$this->assertStringContainsString( self::LISTED_THERE, $settings );
		$this->assertStringContainsString( self::LINK, $settings );
		$this->assertStringNotContainsString( self::SITE_TEXT, $settings );

		$visits = $this->visits_page();
		$this->assertStringContainsString( self::STORE_TEXT, $visits );
		$this->assertStringContainsString( self::LISTED_HERE, $visits );
		$this->assertStringContainsString( self::LINK, $visits );
		$this->assertStringNotContainsString( self::SITE_TEXT, $visits );
	}

	public function test_is_a_warning_notice(): void {
		$this->options( 'yes', 'yes' );
		foreach ( array( $this->settings_page(), $this->visits_page() ) as $html ) {
			$this->assertMatchesRegularExpression( '/<div class="notice notice-warning inline ava-pay-coming-soon">\s*<p>\s*Your store is in Coming soon mode\./', $html );
		}
	}

	public function test_absent_when_the_store_is_live(): void {
		$this->options( 'no', 'yes' );
		$this->assertNoNotice( $this->settings_page() );
		$this->assertNoNotice( $this->visits_page() );
	}

	public function test_absent_when_woocommerce_has_no_coming_soon_option(): void {
		$this->options( null, null );
		$this->assertNoNotice( $this->settings_page() );
		$this->assertNoNotice( $this->visits_page() );
	}

	public function test_settings_page_renders_the_rest_of_the_screen_too(): void {
		$this->options( 'yes', 'no' );
		$html = $this->settings_page();
		$this->assertStringContainsString( 'AVA Pay: Agent Trust Gateway', $html );
		$this->assertStringContainsString( 'name="ava_pay_verify_page_visits"', $html );
		$this->assertStringContainsString( 'Save settings', $html );
	}

	public function test_absent_on_a_non_plugin_admin_screen(): void {
		// The only place it can print is inside the two screens' render
		// callbacks: the admin class hooks nothing but its menu, and no file
		// in the plugin registers an admin-notices hook.
		AVA_Pay_Admin::register();
		$this->assertSame( array( 'admin_menu' ), array_column( $GLOBALS['ava_test_hooks'], 0 ) );

		$GLOBALS['ava_test_hooks'] = array();
		AVA_Pay_Page_Visits::register();
		$this->assertSame( array( 'template_redirect' ), array_column( $GLOBALS['ava_test_hooks'], 0 ) );

		$root  = dirname( __DIR__ );
		$files = array_merge(
			array( $root . '/ava-pay-for-woocommerce.php', $root . '/uninstall.php' ),
			glob( $root . '/includes/*.php' ),
			glob( $root . '/includes/core/*.php' )
		);
		foreach ( $files as $file ) {
			$this->assertDoesNotMatchRegularExpression(
				'/[\'"](?:all_|network_|user_)?admin_notices[\'"]/',
				(string) file_get_contents( $file ),
				basename( $file ) . ' hooks an admin notice'
			);
		}
	}

	public function test_nothing_without_the_capability(): void {
		$this->options( 'yes', 'no' );
		$GLOBALS['ava_test_can'] = false;
		ob_start();
		AVA_Pay_Coming_Soon_Notice::maybe_render( false );
		$this->assertSame( '', ob_get_clean() );
	}

	public function test_link_is_escaped(): void {
		ob_start();
		AVA_Pay_Coming_Soon_Notice::render( AVA_Pay_Coming_Soon::MODE_SITE, 'https://shop.example/"><script>x</script>', true );
		$html = (string) ob_get_clean();
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( 'href="https://shop.example/&quot;&gt;&lt;script&gt;x&lt;/script&gt;"', $html );
	}

	public function test_unknown_mode_renders_nothing(): void {
		ob_start();
		AVA_Pay_Coming_Soon_Notice::render( 'something-else', 'https://shop.example/', true );
		$this->assertSame( '', ob_get_clean() );
	}

	public function test_no_em_or_en_dashes(): void {
		ob_start();
		foreach ( array( AVA_Pay_Coming_Soon::MODE_SITE, AVA_Pay_Coming_Soon::MODE_STORE ) as $mode ) {
			AVA_Pay_Coming_Soon_Notice::render( $mode, 'https://shop.example/', true );
			AVA_Pay_Coming_Soon_Notice::render( $mode, 'https://shop.example/', false );
		}
		$html = (string) ob_get_clean();
		$this->assertStringNotContainsString( "\u{2014}", $html );
		$this->assertStringNotContainsString( "\u{2013}", $html );
	}

	private function assertNoNotice( string $html ): void {
		$this->assertStringNotContainsString( 'Coming soon', $html );
		$this->assertStringNotContainsString( 'site-visibility', $html );
	}
}
