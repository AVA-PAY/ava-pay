<?php
/**
 * Event storage — the WooCommerce mirror of the Shopify app's Prisma models
 * (VerificationEvent + AgentCommerceEvent), feeding the future traffic view.
 *
 * Differences from the Prisma shapes, all deliberate:
 *   - no `shop` column (the WP table prefix scopes rows to one site),
 *   - integer autoincrement ids instead of cuids,
 *   - snake_case column names (MySQL convention).
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Events {

	public static function verification_table() {
		global $wpdb;
		return $wpdb->prefix . 'ava_pay_verification_events';
	}

	public static function commerce_table() {
		global $wpdb;
		return $wpdb->prefix . 'ava_pay_commerce_events';
	}

	/** Create/upgrade both tables via dbDelta. */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate    = $wpdb->get_charset_collate();
		$verification_table = self::verification_table();
		$commerce_table     = self::commerce_table();

		// outcome: 'verified' | 'failed' | 'policy_blocked' | 'error'
		//   failed         — the agent presented credentials that did not verify
		//   policy_blocked — verified, but merchant settings rejected it
		//   error          — the AVA Pay API was unreachable (failed closed)
		// reason: typed VerificationFailureReason, policy reason, or ava_* client error.
		dbDelta(
			"CREATE TABLE {$verification_table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				created_at DATETIME NOT NULL,
				protocol VARCHAR(32) NULL,
				platform VARCHAR(191) NULL,
				outcome VARCHAR(20) NOT NULL,
				reason VARCHAR(64) NULL,
				identity_only TINYINT(1) NOT NULL DEFAULT 0,
				discount_pct SMALLINT NULL,
				discount_code VARCHAR(64) NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY discount_code (discount_code)
			) {$charset_collate};"
		);

		// kind: 'checkout' | 'order'; source_id is the dedup key per kind
		// (order id / session id) so hook re-fires can't double-count —
		// the same guarantee the Shopify app gets from its upsert key.
		dbDelta(
			"CREATE TABLE {$commerce_table} (
				id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
				created_at DATETIME NOT NULL,
				kind VARCHAR(16) NOT NULL,
				source_id VARCHAR(191) NOT NULL,
				order_name VARCHAR(64) NULL,
				total_minor BIGINT NULL,
				currency VARCHAR(8) NULL,
				discount_code VARCHAR(64) NULL,
				platform VARCHAR(191) NULL,
				protocol VARCHAR(32) NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY kind_source (kind, source_id),
				KEY created_at (created_at)
			) {$charset_collate};"
		);

		// Autoloaded on purpose: plugins_loaded reads it on EVERY request to
		// decide whether dbDelta needs a re-run; non-autoloaded it would cost
		// an extra uncached SELECT per page load for a tiny string.
		update_option( 'ava_pay_db_version', AVA_PAY_WC_VERSION, true );
	}

	/**
	 * Record one verification event (one row per verify-agent request).
	 *
	 * @param array $event outcome (required), platform, protocol, reason,
	 *                     identity_only, discount_pct, discount_code.
	 */
	public static function record_verification( array $event ) {
		global $wpdb;
		$wpdb->insert(
			self::verification_table(),
			array(
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
				'protocol'      => isset( $event['protocol'] ) ? $event['protocol'] : null,
				'platform'      => isset( $event['platform'] ) ? self::truncate( $event['platform'], 191 ) : null,
				'outcome'       => $event['outcome'],
				'reason'        => isset( $event['reason'] ) ? self::truncate( $event['reason'], 64 ) : null,
				'identity_only' => ! empty( $event['identity_only'] ) ? 1 : 0,
				'discount_pct'  => isset( $event['discount_pct'] ) ? (int) $event['discount_pct'] : null,
				'discount_code' => isset( $event['discount_code'] ) ? self::truncate( $event['discount_code'], 64 ) : null,
			)
		);
	}

	/**
	 * Record a commerce funnel event, deduplicated on (kind, source_id): the
	 * unique index rejects duplicates, and a false insert is treated as
	 * already-recorded (matches the Shopify webhook upsert semantics under
	 * redelivery).
	 *
	 * @param array $event kind + source_id (required), order_name,
	 *                     total_minor, currency, discount_code, platform, protocol.
	 * @return bool True if a new row was recorded.
	 */
	public static function record_commerce_event( array $event ) {
		global $wpdb;

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM ' . self::commerce_table() . ' WHERE kind = %s AND source_id = %s',
				$event['kind'],
				$event['source_id']
			)
		);
		if ( null !== $existing ) {
			return false;
		}

		// The unique key still guards the SELECT→INSERT race; suppress the
		// duplicate-key error rather than surfacing it to the checkout flow.
		$suppress = $wpdb->suppress_errors();
		$inserted = $wpdb->insert(
			self::commerce_table(),
			array(
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
				'kind'          => $event['kind'],
				'source_id'     => self::truncate( $event['source_id'], 191 ),
				'order_name'    => isset( $event['order_name'] ) ? self::truncate( $event['order_name'], 64 ) : null,
				'total_minor'   => isset( $event['total_minor'] ) ? (int) $event['total_minor'] : null,
				'currency'      => isset( $event['currency'] ) ? self::truncate( $event['currency'], 8 ) : null,
				'discount_code' => isset( $event['discount_code'] ) ? self::truncate( $event['discount_code'], 64 ) : null,
				'platform'      => isset( $event['platform'] ) ? self::truncate( $event['platform'], 191 ) : null,
				'protocol'      => isset( $event['protocol'] ) ? $event['protocol'] : null,
			)
		);
		$wpdb->suppress_errors( $suppress );

		return false !== $inserted;
	}

	/**
	 * Attribution join: latest verification event that minted this discount
	 * code → platform/protocol. Mirrors the Shopify webhook attribution via
	 * VerificationEvent.discountCode.
	 *
	 * @param string $code Canonical lowercase coupon code.
	 * @return array|null {platform, protocol}
	 */
	public static function find_verification_by_code( $code ) {
		global $wpdb;
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT platform, protocol FROM ' . self::verification_table() .
				' WHERE discount_code = %s ORDER BY id DESC LIMIT 1',
				$code
			),
			ARRAY_A
		);
		return $row ? $row : null;
	}

	/**
	 * @param mixed $value Column value.
	 * @param int   $len   Column capacity.
	 */
	private static function truncate( $value, $len ) {
		$s = (string) $value;
		return strlen( $s ) > $len ? substr( $s, 0, $len ) : $s;
	}
}
