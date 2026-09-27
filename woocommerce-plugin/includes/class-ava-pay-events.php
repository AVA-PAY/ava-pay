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

	/** Daily WP-Cron event that drops old page-visit rows. */
	const PURGE_HOOK = 'ava_pay_purge_page_visits';

	/** Page-visit rows are kept this long (filter: ava_pay_page_visit_retention_days). */
	const DEFAULT_RETENTION_DAYS = 90;

	/** Rows per DELETE, and the most batches one run takes. */
	const PURGE_BATCH       = 5000;
	const PURGE_MAX_BATCHES = 20;

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

		// outcome: 'verified' | 'failed' | 'unverifiable' | 'policy_blocked' | 'error'
		//   failed         the agent presented credentials that did not verify
		//   unverifiable   the verifier could not complete its checks (a trust
		//                  root could not be consulted), so nothing was proved either
		//                  way. Fails closed like 'failed', but must never be
		//                  counted or shown as a rejection.
		//   policy_blocked verified, but merchant settings rejected it
		//   error          the AVA Pay API was unreachable (failed closed)
		// reason: typed VerificationFailureReason, policy reason, or ava_* client error.
		// source: 'verify_endpoint' (the REST verify endpoint, and every row
		//   written before 0.4.0, which the DEFAULT fills in when dbDelta adds
		//   the column) | 'page_view' (a signed front-end page visit, observed
		//   only; see AVA_Pay_Page_Visit).
		// path: page_view rows only. The request path with its query string
		//   removed; never the query, the IP, the user agent or header values.
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
				source VARCHAR(20) NULL DEFAULT 'verify_endpoint',
				path VARCHAR(255) NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY discount_code (discount_code),
				KEY source_created (source, created_at)
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

		self::schedule_purge();

		// Autoloaded on purpose: plugins_loaded reads it on EVERY request to
		// decide whether dbDelta needs a re-run; non-autoloaded it would cost
		// an extra uncached SELECT per page load for a tiny string.
		update_option( 'ava_pay_db_version', AVA_PAY_WC_VERSION, true );
	}

	/**
	 * Record one verification event: one row per verify-agent request, and
	 * one per signed page visit that was checked (source page_view).
	 *
	 * @param array $event outcome (required), platform, protocol, reason,
	 *                     identity_only, discount_pct, discount_code, source
	 *                     (defaults to 'verify_endpoint'), path.
	 */
	public static function record_verification( array $event ) {
		global $wpdb;
		$row = array(
			'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			'protocol'      => isset( $event['protocol'] ) ? $event['protocol'] : null,
			'platform'      => isset( $event['platform'] ) ? self::truncate( $event['platform'], 191 ) : null,
			'outcome'       => $event['outcome'],
			'reason'        => isset( $event['reason'] ) ? self::truncate( $event['reason'], 64 ) : null,
			'identity_only' => ! empty( $event['identity_only'] ) ? 1 : 0,
			'discount_pct'  => isset( $event['discount_pct'] ) ? (int) $event['discount_pct'] : null,
			'discount_code' => isset( $event['discount_code'] ) ? self::truncate( $event['discount_code'], 64 ) : null,
			'source'        => isset( $event['source'] ) ? self::truncate( $event['source'], 20 ) : 'verify_endpoint',
			'path'          => isset( $event['path'] ) ? self::truncate( $event['path'], 255 ) : null,
		);

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery -- insert into this plugin's own event table; no core API exists for custom tables.
		if ( false === $wpdb->insert( self::verification_table(), $row ) && self::repair_tables() ) {
			$wpdb->insert( self::verification_table(), $row );
		}
		// phpcs:enable
	}

	/**
	 * Re-run the installer once per request after a failed insert.
	 *
	 * The version gate in the main plugin file only re-runs dbDelta when
	 * AVA_PAY_WC_VERSION changes, so a site whose event tables went missing
	 * while `ava_pay_db_version` still matched (a database restored without
	 * custom tables, a staging clone, a migration plugin that copied only
	 * core tables) would drop every event for the rest of the release and say
	 * nothing: verification still succeeds and coupons are still minted, so
	 * the merchant sees a working store and an empty traffic table.
	 *
	 * Checking the tables exist on every request would cost a query per page
	 * load for a condition that is almost never true, so the check hangs off
	 * the failure instead. Once per request, because a row rejected for any
	 * other reason (a value too long for its column) must not retry forever.
	 *
	 * @return bool True if the installer ran and the caller should retry.
	 */
	private static function repair_tables() {
		static $attempted = false;
		if ( $attempted || ! defined( 'ABSPATH' ) ) {
			return false;
		}
		$attempted = true;
		self::install();
		return true;
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- dedup read on this plugin's own event table; must see the live row, so no cache.
		$existing = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT id FROM %i WHERE kind = %s AND source_id = %s',
				self::commerce_table(),
				$event['kind'],
				$event['source_id']
			)
		);
		if ( null !== $existing ) {
			return false;
		}

		$row = array(
			'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			'kind'          => $event['kind'],
			'source_id'     => self::truncate( $event['source_id'], 191 ),
			'order_name'    => isset( $event['order_name'] ) ? self::truncate( $event['order_name'], 64 ) : null,
			'total_minor'   => isset( $event['total_minor'] ) ? (int) $event['total_minor'] : null,
			'currency'      => isset( $event['currency'] ) ? self::truncate( $event['currency'], 8 ) : null,
			'discount_code' => isset( $event['discount_code'] ) ? self::truncate( $event['discount_code'], 64 ) : null,
			'platform'      => isset( $event['platform'] ) ? self::truncate( $event['platform'], 191 ) : null,
			'protocol'      => isset( $event['protocol'] ) ? $event['protocol'] : null,
		);

		// The unique key still guards the SELECT→INSERT race; suppress the
		// duplicate-key error rather than surfacing it to the checkout flow.
		$suppress = $wpdb->suppress_errors();
		$inserted = $wpdb->insert( self::commerce_table(), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- insert into this plugin's own event table.
		// A missing table looks the same as a duplicate key from here, so the
		// retry is worth one attempt; a real duplicate simply fails again and
		// still reads as already-recorded. See repair_tables().
		if ( false === $inserted && self::repair_tables() ) {
			$inserted = $wpdb->insert( self::commerce_table(), $row ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- insert into this plugin's own event table.
		}
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- attribution read on this plugin's own event table, once per order.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT platform, protocol FROM %i WHERE discount_code = %s ORDER BY id DESC LIMIT 1',
				self::verification_table(),
				$code
			),
			ARRAY_A
		);
		return $row ? $row : null;
	}

	/**
	 * Schedule the daily purge if it is not scheduled. install() calls this,
	 * so activation and every version upgrade schedule it; admin_init calls
	 * it too, so a cron array that lost the event is repaired the next time
	 * the merchant opens the admin.
	 */
	public static function schedule_purge() {
		if ( ! wp_next_scheduled( self::PURGE_HOOK ) ) {
			wp_schedule_event( time() + 3600, 'daily', self::PURGE_HOOK );
		}
	}

	/** Deactivation and uninstall. */
	public static function unschedule_purge() {
		wp_clear_scheduled_hook( self::PURGE_HOOK );
	}

	/**
	 * Delete page-visit rows older than the retention period. Only
	 * source = 'page_view': verify-endpoint rows feed order attribution and
	 * are not this path's to expire. Batched so a large backlog cannot hold
	 * one long lock on the table.
	 *
	 * @return int Rows deleted.
	 */
	public static function purge_page_visits() {
		global $wpdb;
		$days   = max( 1, (int) apply_filters( 'ava_pay_page_visit_retention_days', self::DEFAULT_RETENTION_DAYS ) );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * 86400 );

		$deleted = 0;
		for ( $i = 0; $i < self::PURGE_MAX_BATCHES; $i++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- retention delete on this plugin's own event table.
			$n = (int) $wpdb->query(
				$wpdb->prepare(
					'DELETE FROM %i WHERE source = %s AND created_at < %s LIMIT %d',
					self::verification_table(),
					AVA_Pay_Page_Visit::SOURCE,
					$cutoff,
					self::PURGE_BATCH
				)
			);
			$deleted += max( 0, $n );
			if ( $n < self::PURGE_BATCH ) {
				break;
			}
		}
		return $deleted;
	}

	/**
	 * Page-visit rows since $since_gmt, counted by platform and outcome.
	 *
	 * @param string $since_gmt 'Y-m-d H:i:s', UTC.
	 * @return array<int,array{platform:string|null,outcome:string,n:string}>
	 */
	public static function page_visit_counts( $since_gmt ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- admin report over this plugin's own event table; must be current.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT platform, outcome, COUNT(*) AS n FROM %i WHERE source = %s AND created_at >= %s GROUP BY platform, outcome',
				self::verification_table(),
				AVA_Pay_Page_Visit::SOURCE,
				$since_gmt
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * The most recent page-visit rows, newest first.
	 *
	 * @param int $limit Row cap.
	 * @return array<int,array{created_at:string,platform:string|null,protocol:string|null,outcome:string,reason:string|null,path:string|null}>
	 */
	public static function recent_page_visits( $limit ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- admin report over this plugin's own event table; must be current.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				'SELECT created_at, platform, protocol, outcome, reason, path FROM %i WHERE source = %s ORDER BY id DESC LIMIT %d',
				self::verification_table(),
				AVA_Pay_Page_Visit::SOURCE,
				(int) $limit
			),
			ARRAY_A
		);
		return is_array( $rows ) ? $rows : array();
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
