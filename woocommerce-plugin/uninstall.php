<?php
/**
 * Uninstall cleanup: drop the event tables and remove options. Runs only on
 * deletion (not deactivation), per WordPress.org guidelines.
 *
 * Coupons the plugin minted are deliberately NOT removed. They are ordinary
 * store records, and completed orders reference them by code; deleting them
 * would rewrite the merchant's order history to tidy up our own install.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- schema teardown.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ava_pay_verification_events" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ava_pay_commerce_events" );

// Rate-limit buckets: one transient pair per client IP seen in the last
// window. They expire on their own, but WordPress only collects expired
// transients lazily, so on a site without a working cron they would sit in
// wp_options indefinitely after the plugin is gone. delete_transient() cannot
// help here: the keys are md5 hashes of client IPs we no longer know.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_ava\\_pay\\_rl\\_%'
		OR option_name LIKE '\\_transient\\_timeout\\_ava\\_pay\\_rl\\_%'"
);
// Page-visit budget counters, the daily "not checked" tallies and the
// per-agent backoff marks, for the same reason: the per-agent keys are md5
// hashes of agent labels.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_ava\\_pay\\_vb\\_%'
		OR option_name LIKE '\\_transient\\_timeout\\_ava\\_pay\\_vb\\_%'
		OR option_name LIKE '\\_transient\\_ava\\_pay\\_vskip\\_%'
		OR option_name LIKE '\\_transient\\_timeout\\_ava\\_pay\\_vskip\\_%'
		OR option_name LIKE '\\_transient\\_ava\\_pay\\_vneg\\_%'
		OR option_name LIKE '\\_transient\\_timeout\\_ava\\_pay\\_vneg\\_%'"
);
// phpcs:enable

wp_clear_scheduled_hook( 'ava_pay_purge_page_visits' );

delete_option( 'ava_pay_page_visit_lock' );
delete_option( 'ava_pay_settings' );
delete_option( 'ava_pay_db_version' );
