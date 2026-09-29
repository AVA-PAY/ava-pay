<?php
/**
 * The "your store is in Coming soon mode" warning, shown on this plugin's own
 * two screens only (AVA Pay settings, Agent visits). Never hooked to
 * admin_notices: nothing appears on any other admin screen, and there is
 * nothing to dismiss. Inform only; the merchant decides when the store goes
 * live, in WooCommerce's own Site visibility settings.
 *
 * The wording follows what WooCommerce does (see AVA_Pay_Coming_Soon): the
 * placeholder is served after the page-visit gate has run, so signed visits
 * are still recorded while it is up, whichever mode is on.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Coming_Soon_Notice {

	/**
	 * Print the notice for the current Coming soon mode, or nothing when the
	 * store is live or the option does not exist.
	 *
	 * @param bool $on_visits_page True on Agent visits, where "listed here" is literal.
	 */
	public static function maybe_render( $on_visits_page ) {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			return;
		}
		self::render(
			AVA_Pay_Coming_Soon::mode( 'get_option' ),
			admin_url( AVA_Pay_Coming_Soon::SETTINGS_PATH ),
			$on_visits_page
		);
	}

	/**
	 * @param string|null $mode           AVA_Pay_Coming_Soon::mode() output.
	 * @param string      $settings_url   WooCommerce Site visibility settings.
	 * @param bool        $on_visits_page See maybe_render().
	 */
	public static function render( $mode, $settings_url, $on_visits_page ) {
		if ( AVA_Pay_Coming_Soon::MODE_SITE === $mode ) {
			$hidden = __( 'Your store is in Coming soon mode. Everyone except store managers, AI agents included, sees a placeholder page instead of your site.', 'ava-pay-for-woocommerce' );
		} elseif ( AVA_Pay_Coming_Soon::MODE_STORE === $mode ) {
			$hidden = __( 'Your store is in Coming soon mode. Everyone except store managers, AI agents included, sees a placeholder page instead of your store pages.', 'ava-pay-for-woocommerce' );
		} else {
			return;
		}
		$listed = $on_visits_page
			? __( 'Agents that visit are still listed here, but they see the placeholder, not your products.', 'ava-pay-for-woocommerce' )
			: __( 'Agents that visit are still listed under Agent visits, but they see the placeholder, not your products.', 'ava-pay-for-woocommerce' );
		?>
		<div class="notice notice-warning inline ava-pay-coming-soon">
			<p>
				<?php echo esc_html( $hidden ); ?>
				<?php esc_html_e( 'You see the store normally because you are a store manager.', 'ava-pay-for-woocommerce' ); ?>
				<?php echo esc_html( $listed ); ?>
				<a href="<?php echo esc_url( $settings_url ); ?>"><?php esc_html_e( 'Set Site visibility to Live', 'ava-pay-for-woocommerce' ); ?></a>.
			</p>
		</div>
		<?php
	}
}
