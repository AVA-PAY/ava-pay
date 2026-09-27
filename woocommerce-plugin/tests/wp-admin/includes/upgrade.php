<?php
/**
 * Stand-in for wp-admin/includes/upgrade.php, which AVA_Pay_Events::install()
 * requires from ABSPATH (the tests directory in this suite). dbDelta records
 * the SQL it was given so SchemaTest can read the table definitions.
 *
 * @package AVA_Pay
 */

function dbDelta( $sql ) { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.FunctionNameInvalid -- WordPress's own name.
	$GLOBALS['ava_test_dbdelta'][] = $sql;
	return array();
}
