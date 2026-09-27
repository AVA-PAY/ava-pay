<?php
/**
 * Markup for WooCommerce, Agent visits. Prints only; AVA_Pay_Admin gathers
 * the data. Everything that came from a request (platform, protocol, reason,
 * path) is attacker-controlled until proven otherwise, so every value goes
 * through an escaper here, and the PHPUnit suite renders hostile strings
 * through this class to hold that.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Visits_View {

	/**
	 * @param array $report {
	 *     @type bool   $enabled      The page-visit setting.
	 *     @type string $settings_url AVA Pay settings page.
	 *     @type array  $periods      days => AVA_Pay_Visit_Report::summarize() output.
	 *     @type array  $recent       Rows {time, platform, protocol, outcome, reason, path}.
	 * }
	 */
	public static function render( array $report ) {
		$periods = isset( $report['periods'] ) ? $report['periods'] : array();
		$recent  = isset( $report['recent'] ) ? $report['recent'] : array();

		$seen = ! empty( $recent );
		foreach ( $periods as $rows ) {
			if ( ! empty( $rows ) ) {
				$seen = true;
			}
		}
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'AVA Pay: Agent visits', 'ava-pay-for-woocommerce' ); ?></h1>
			<p><?php esc_html_e( 'Page views by AI agents that signed their requests, and what verification found. Visits are observed only: nothing here blocks, redirects or discounts a page view.', 'ava-pay-for-woocommerce' ); ?></p>

			<?php if ( empty( $report['enabled'] ) ) : ?>
				<div class="notice notice-warning inline">
					<p>
						<?php esc_html_e( 'Verifying signed AI agent page visits is turned off, so no new visits are being recorded.', 'ava-pay-for-woocommerce' ); ?>
						<a href="<?php echo esc_url( isset( $report['settings_url'] ) ? $report['settings_url'] : '' ); ?>"><?php esc_html_e( 'Change this in AVA Pay settings.', 'ava-pay-for-woocommerce' ); ?></a>
					</p>
				</div>
			<?php endif; ?>

			<?php if ( ! $seen ) : ?>
				<div class="notice notice-info inline">
					<p><?php esc_html_e( 'No signed AI agent has visited your store yet.', 'ava-pay-for-woocommerce' ); ?></p>
					<p><?php esc_html_e( 'Most AI crawlers do not sign their requests, so they cannot be verified and do not appear here. ChatGPT\'s agent does sign its requests.', 'ava-pay-for-woocommerce' ); ?></p>
					<p><?php esc_html_e( 'If your store uses full-page caching, cached pages are served without running WordPress, so visits to those pages cannot be seen.', 'ava-pay-for-woocommerce' ); ?></p>
				</div>
			<?php else : ?>
				<?php foreach ( $periods as $days => $rows ) : ?>
					<h2>
						<?php
						printf(
							/* translators: %d: number of days */
							esc_html__( 'Last %d days', 'ava-pay-for-woocommerce' ),
							(int) $days
						);
						?>
					</h2>
					<?php self::render_counts( $rows ); ?>
				<?php endforeach; ?>

				<h2><?php esc_html_e( 'Recent visits', 'ava-pay-for-woocommerce' ); ?></h2>
				<?php self::render_recent( $recent ); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * @param array $rows AVA_Pay_Visit_Report::summarize() output.
	 */
	private static function render_counts( array $rows ) {
		if ( empty( $rows ) ) {
			echo '<p>' . esc_html__( 'No signed agent visits in this period.', 'ava-pay-for-woocommerce' ) . '</p>';
			return;
		}
		$labels = self::outcome_labels();
		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Platform', 'ava-pay-for-woocommerce' ); ?></th>
					<?php foreach ( AVA_Pay_Visit_Report::COLUMNS as $column ) : ?>
						<th scope="col" class="num"><?php echo esc_html( $labels[ $column ] ); ?></th>
					<?php endforeach; ?>
					<th scope="col" class="num"><?php esc_html_e( 'Total', 'ava-pay-for-woocommerce' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) : ?>
					<tr>
						<td><?php echo esc_html( self::platform_label( $row['platform'] ) ); ?></td>
						<?php foreach ( AVA_Pay_Visit_Report::COLUMNS as $column ) : ?>
							<td class="num"><?php echo esc_html( number_format_i18n( (int) $row['counts'][ $column ] ) ); ?></td>
						<?php endforeach; ?>
						<td class="num"><?php echo esc_html( number_format_i18n( (int) $row['total'] ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<p class="description"><?php esc_html_e( 'Not checked (budget): signed visits that were not verified because the agent or the site had reached its verification budget for the minute or the day. Days are counted in UTC.', 'ava-pay-for-woocommerce' ); ?></p>
		<?php
	}

	/**
	 * @param array $recent Rows {time, platform, protocol, outcome, reason, path}.
	 */
	private static function render_recent( array $recent ) {
		if ( empty( $recent ) ) {
			echo '<p>' . esc_html__( 'No visits recorded yet. Visits that were not checked because of the budget are counted above but not listed.', 'ava-pay-for-woocommerce' ) . '</p>';
			return;
		}
		$labels = self::outcome_labels();
		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th scope="col"><?php esc_html_e( 'Time', 'ava-pay-for-woocommerce' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Platform', 'ava-pay-for-woocommerce' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Outcome', 'ava-pay-for-woocommerce' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Reason', 'ava-pay-for-woocommerce' ); ?></th>
					<th scope="col"><?php esc_html_e( 'Path', 'ava-pay-for-woocommerce' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $recent as $row ) : ?>
					<tr>
						<td><?php echo esc_html( $row['time'] ); ?></td>
						<td>
							<?php echo esc_html( self::platform_label( $row['platform'] ) ); ?>
							<?php if ( '' !== (string) $row['protocol'] ) : ?>
								<br /><code><?php echo esc_html( $row['protocol'] ); ?></code>
							<?php endif; ?>
						</td>
						<td><?php echo esc_html( isset( $labels[ $row['outcome'] ] ) ? $labels[ $row['outcome'] ] : $row['outcome'] ); ?></td>
						<td>
							<?php if ( '' !== (string) $row['reason'] ) : ?>
								<code><?php echo esc_html( $row['reason'] ); ?></code>
							<?php endif; ?>
						</td>
						<td><code><?php echo esc_html( $row['path'] ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/** @return array<string,string> */
	private static function outcome_labels() {
		return array(
			'verified'     => __( 'Verified', 'ava-pay-for-woocommerce' ),
			'failed'       => __( 'Failed', 'ava-pay-for-woocommerce' ),
			'unverifiable' => __( 'Unverifiable', 'ava-pay-for-woocommerce' ),
			'error'        => __( 'Error', 'ava-pay-for-woocommerce' ),
			'not_checked'  => __( 'Not checked (budget)', 'ava-pay-for-woocommerce' ),
		);
	}

	/**
	 * @param string $platform Stored platform ('' when the request named none).
	 * @return string
	 */
	private static function platform_label( $platform ) {
		return '' === (string) $platform ? __( '(unknown)', 'ava-pay-for-woocommerce' ) : (string) $platform;
	}
}
