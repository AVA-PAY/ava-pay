<?php
/**
 * Uninstall cleanup: drop the event tables and remove options. Runs only on
 * deletion (not deactivation), per WordPress.org guidelines.
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
// phpcs:enable

delete_option( 'ava_pay_settings' );
delete_option( 'ava_pay_db_version' );
