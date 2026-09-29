<?php
/**
 * WooCommerce's "Coming soon" mode (WooCommerce, Settings, Site visibility),
 * read the way WooCommerce reads it. Inform only: this plugin never changes
 * the store's visibility and never lets anyone past the placeholder.
 *
 * Facts from WooCommerce's own source (11.1.2 and 11.2.0-beta.2, identical
 * here; Automattic\WooCommerce\Internal\ComingSoon\ComingSoonHelper):
 *
 * - woocommerce_coming_soon = 'yes' hides the store. Anything else is live.
 *   New installs get 'yes'; the 9.3.0 database update adds 'no' where it is
 *   missing. A WooCommerce without the feature has no such option, and
 *   absent means no notice.
 * - woocommerce_store_pages_only = 'yes' limits the placeholder to store
 *   pages (shop, cart, checkout, terms, products, product archives and
 *   taxonomies); anything else means the whole site.
 * - The placeholder is served from a template_include filter, which runs
 *   after template_redirect, so the page-visit gate (template_redirect,
 *   priority 0) still sees and records a signed visit. Shoppers with
 *   manage_woocommerce always see the real store. tests/ComingSoonGateTest
 *   pins all of this against WooCommerce's real classes when a WooCommerce
 *   checkout is available (CI downloads one).
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class AVA_Pay_Coming_Soon {

	const OPTION                  = 'woocommerce_coming_soon';
	const STORE_PAGES_ONLY_OPTION = 'woocommerce_store_pages_only';

	/** WooCommerce, Settings, Site visibility, relative to admin_url(). */
	const SETTINGS_PATH = 'admin.php?page=wc-settings&tab=site-visibility';

	const MODE_SITE  = 'site';
	const MODE_STORE = 'store';

	/**
	 * @param callable $get_option fn( string $name ): mixed, false when the
	 *                             option does not exist (get_option's default).
	 * @return string|null MODE_SITE, MODE_STORE, or null when the store is live
	 *                     or this WooCommerce has no Coming soon mode.
	 */
	public static function mode( callable $get_option ) {
		if ( 'yes' !== $get_option( self::OPTION ) ) {
			return null;
		}
		return 'yes' === $get_option( self::STORE_PAGES_ONLY_OPTION ) ? self::MODE_STORE : self::MODE_SITE;
	}
}
