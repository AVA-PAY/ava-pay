<?php
/**
 * Settings page (WooCommerce → AVA Pay). Capability-gated to
 * manage_woocommerce, nonce-checked, everything sanitized on the way in and
 * escaped on the way out. Policy JSON is validated through the same strict
 * parser the verify path uses — invalid documents are rejected with the
 * parser's error, never silently repaired (parity with the Shopify
 * /app/policies editor). The textarea doubles as export: it always shows
 * the canonical serialized policy.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Admin {

	const PAGE_SLUG = 'ava-pay';
	const NONCE     = 'ava_pay_save_settings';

	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'add_menu' ) );
	}

	public static function add_menu() {
		add_submenu_page(
			'woocommerce',
			__( 'AVA Pay', 'ava-pay-for-woocommerce' ),
			__( 'AVA Pay', 'ava-pay-for-woocommerce' ),
			'manage_woocommerce',
			self::PAGE_SLUG,
			array( __CLASS__, 'render_page' )
		);
	}

	public static function render_page() {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You do not have permission to manage AVA Pay settings.', 'ava-pay-for-woocommerce' ) );
		}

		$notices = array();
		if ( 'POST' === ( isset( $_SERVER['REQUEST_METHOD'] ) ? $_SERVER['REQUEST_METHOD'] : '' ) ) {
			check_admin_referer( self::NONCE );
			$notices = self::handle_save();
		}

		$settings    = AVA_Pay_Settings::get();
		$policy_json = null !== $settings['policy']
			? AVA_Pay_Agent_Policy::serialize( $settings['policy'] )
			: '';

		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'AVA Pay — Agent Trust Gateway', 'ava-pay-for-woocommerce' ); ?></h1>
			<p>
				<?php esc_html_e( 'AI agents are already shopping your store. AVA Pay verifies which ones to trust, lets you set the rules, and records the traffic.', 'ava-pay-for-woocommerce' ); ?>
			</p>
			<?php foreach ( $notices as $notice ) : ?>
				<div class="notice notice-<?php echo esc_attr( $notice['type'] ); ?>"><p><?php echo esc_html( $notice['message'] ); ?></p></div>
			<?php endforeach; ?>

			<form method="post">
				<?php wp_nonce_field( self::NONCE ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="ava_pay_api_url"><?php esc_html_e( 'AVA Pay API URL', 'ava-pay-for-woocommerce' ); ?></label></th>
						<td>
							<input name="ava_pay_api_url" id="ava_pay_api_url" type="url" class="regular-text code"
								value="<?php echo esc_attr( $settings['apiUrl'] ); ?>" />
							<p class="description"><?php esc_html_e( 'The hosted verification API this store proxies signed agent requests to.', 'ava-pay-for-woocommerce' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Accept verified agents', 'ava-pay-for-woocommerce' ); ?></th>
						<td>
							<label>
								<input name="ava_pay_accept" type="checkbox" value="1" <?php checked( $settings['acceptVerifiedAgents'] ); ?> />
								<?php esc_html_e( 'Admit agents that pass cryptographic verification', 'ava-pay-for-woocommerce' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'When off, every agent is rejected (recorded as merchant_disabled).', 'ava-pay-for-woocommerce' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ava_pay_default_pct"><?php esc_html_e( 'Default discount %', 'ava-pay-for-woocommerce' ); ?></label></th>
						<td>
							<input name="ava_pay_default_pct" id="ava_pay_default_pct" type="number" min="0" max="100" step="1"
								value="<?php echo esc_attr( $settings['defaultDiscountPct'] ); ?>" />
							<p class="description"><?php esc_html_e( 'Applied to mandate-backed verified agents when no platform offer or verifier hint is present.', 'ava-pay-for-woocommerce' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ava_pay_max_pct"><?php esc_html_e( 'Maximum discount %', 'ava-pay-for-woocommerce' ); ?></label></th>
						<td>
							<input name="ava_pay_max_pct" id="ava_pay_max_pct" type="number" min="0" max="100" step="1"
								value="<?php echo esc_attr( $settings['maxDiscountPct'] ); ?>" />
							<p class="description"><?php esc_html_e( 'Hard cap, even if the verifier or a policy offer asks for more.', 'ava-pay-for-woocommerce' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ava_pay_identity_pct"><?php esc_html_e( 'Identity-only discount %', 'ava-pay-for-woocommerce' ); ?></label></th>
						<td>
							<input name="ava_pay_identity_pct" id="ava_pay_identity_pct" type="number" min="0" max="100" step="1"
								value="<?php echo esc_attr( $settings['identityOnlyDiscountPct'] ); ?>" />
							<p class="description"><?php esc_html_e( 'For agents that prove who they are but carry no buyer mandate (e.g. Web Bot Auth / ChatGPT). 0 = admit them with no discount. Raising this is an explicit opt-in.', 'ava-pay-for-woocommerce' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="ava_pay_policy_json"><?php esc_html_e( 'Agent platform policy (JSON)', 'ava-pay-for-woocommerce' ); ?></label></th>
						<td>
							<textarea name="ava_pay_policy_json" id="ava_pay_policy_json" class="large-text code" rows="12"
								placeholder='{"version": 1, "rules": [{"platform": "https://chatgpt.com", "action": "allow"}]}'><?php echo esc_textarea( $policy_json ); ?></textarea>
							<p class="description">
								<?php esc_html_e( 'Optional per-platform rules: allow/challenge/block, discount caps (maxDiscountPct), spend rules (maxSpendMinor), and agent-only offers (offerDiscountPct). Leave empty for default behavior. This document is portable — copy it out to export, paste to import.', 'ava-pay-for-woocommerce' ); ?>
							</p>
						</td>
					</tr>
				</table>
				<?php submit_button( __( 'Save settings', 'ava-pay-for-woocommerce' ) ); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Sanitize + persist. Returns admin notices.
	 *
	 * @return array<int,array{type:string,message:string}>
	 */
	private static function handle_save() {
		$notices = array();

		$api_url = isset( $_POST['ava_pay_api_url'] )
			? esc_url_raw( trim( wp_unslash( $_POST['ava_pay_api_url'] ) ), array( 'http', 'https' ) )
			: '';
		if ( '' === $api_url ) {
			$api_url = AVA_Pay_Settings::DEFAULT_API_URL;
		}

		$patch = array(
			'apiUrl'                  => $api_url,
			'acceptVerifiedAgents'    => ! empty( $_POST['ava_pay_accept'] ),
			'defaultDiscountPct'      => AVA_Pay_Policy::clamp_pct( isset( $_POST['ava_pay_default_pct'] ) ? wp_unslash( $_POST['ava_pay_default_pct'] ) : 0 ),
			'maxDiscountPct'          => AVA_Pay_Policy::clamp_pct( isset( $_POST['ava_pay_max_pct'] ) ? wp_unslash( $_POST['ava_pay_max_pct'] ) : 0 ),
			'identityOnlyDiscountPct' => AVA_Pay_Policy::clamp_pct( isset( $_POST['ava_pay_identity_pct'] ) ? wp_unslash( $_POST['ava_pay_identity_pct'] ) : 0 ),
		);

		$policy_json = isset( $_POST['ava_pay_policy_json'] )
			? trim( (string) wp_unslash( $_POST['ava_pay_policy_json'] ) )
			: '';

		if ( '' === $policy_json ) {
			$patch['policyJson'] = '';
		} else {
			$parsed = AVA_Pay_Agent_Policy::parse( $policy_json );
			if ( $parsed['ok'] ) {
				// Store the canonical serialization, not the raw input.
				$patch['policyJson'] = wp_json_encode( $parsed['policy'] );
			} else {
				$notices[] = array(
					'type'    => 'error',
					'message' => sprintf(
						/* translators: %s: policy validation error */
						__( 'Policy not saved: %s Other settings were saved.', 'ava-pay-for-woocommerce' ),
						$parsed['error']
					),
				);
			}
		}

		AVA_Pay_Settings::update( $patch );

		$notices[] = array(
			'type'    => 'success',
			'message' => __( 'AVA Pay settings saved.', 'ava-pay-for-woocommerce' ),
		);
		return $notices;
	}
}
