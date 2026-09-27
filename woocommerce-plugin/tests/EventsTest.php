<?php
/**
 * The verification table across the 0.4.0 schema change, and the rows the
 * two paths write. Loads the real AVA_Pay_Events with WordPress stand-ins
 * (tests/wp-stubs.php): dbDelta records the SQL, $wpdb records inserts.
 *
 * The live upgrade proof (0.3.0 table with rows, then 0.4.0's dbDelta
 * against MySQL) is in the PR body; this pins the definition that proof
 * depends on, so a later edit cannot quietly change an existing column.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/wp-stubs.php';
require_once __DIR__ . '/../includes/class-ava-pay-events.php';

final class EventsTest extends TestCase {

	/**
	 * The 0.3.0 verification-table columns, verbatim from the 0.3.0 release
	 * (fa33c1c). dbDelta leaves a column alone when its definition is
	 * unchanged, so each must survive byte for byte and in this order.
	 */
	const COLUMNS_0_3_0 = array(
		'id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,',
		'created_at DATETIME NOT NULL,',
		'protocol VARCHAR(32) NULL,',
		'platform VARCHAR(191) NULL,',
		'outcome VARCHAR(20) NOT NULL,',
		'reason VARCHAR(64) NULL,',
		'identity_only TINYINT(1) NOT NULL DEFAULT 0,',
		'discount_pct SMALLINT NULL,',
		'discount_code VARCHAR(64) NULL,',
	);

	/** @var Ava_Test_Wpdb */
	private $wpdb;

	protected function setUp(): void {
		$this->wpdb                  = new Ava_Test_Wpdb();
		$GLOBALS['wpdb']             = $this->wpdb;
		$GLOBALS['ava_test_dbdelta'] = array();
	}

	private function verification_sql(): string {
		AVA_Pay_Events::install();
		foreach ( $GLOBALS['ava_test_dbdelta'] as $sql ) {
			if ( false !== strpos( $sql, 'CREATE TABLE wp_ava_pay_verification_events' ) ) {
				return $sql;
			}
		}
		$this->fail( 'no verification table definition' );
	}

	/** @return string[] Trimmed definition lines between the parentheses. */
	private function definition_lines(): array {
		$sql   = $this->verification_sql();
		$body  = substr( $sql, strpos( $sql, '(' ) + 1, strrpos( $sql, ')' ) - strpos( $sql, '(' ) - 1 );
		$lines = array_values( array_filter( array_map( 'trim', explode( "\n", $body ) ) ) );
		return $lines;
	}

	public function test_existing_columns_are_unchanged_and_new_ones_are_appended_nullable(): void {
		$lines = $this->definition_lines();
		$this->assertSame( self::COLUMNS_0_3_0, array_slice( $lines, 0, count( self::COLUMNS_0_3_0 ) ) );
		$this->assertSame(
			array(
				"source VARCHAR(20) NULL DEFAULT 'verify_endpoint',",
				'path VARCHAR(255) NULL,',
			),
			array_slice( $lines, count( self::COLUMNS_0_3_0 ), 2 )
		);
	}

	public function test_existing_keys_are_kept_and_one_is_added(): void {
		$lines = $this->definition_lines();
		$keys  = array_slice( $lines, count( self::COLUMNS_0_3_0 ) + 2 );
		$this->assertSame(
			array(
				'PRIMARY KEY  (id),',
				'KEY created_at (created_at),',
				'KEY discount_code (discount_code),',
				'KEY source_created (source, created_at)',
			),
			$keys
		);
	}

	public function test_no_column_can_hold_an_ip_user_agent_or_header(): void {
		$names = array_map(
			static function ( $line ) {
				return strtok( $line, ' ' );
			},
			$this->definition_lines()
		);
		foreach ( array( 'ip', 'remote_addr', 'user_agent', 'headers', 'query', 'url' ) as $forbidden ) {
			$this->assertNotContains( $forbidden, $names );
		}
	}

	public function test_install_records_the_new_db_version(): void {
		$GLOBALS['ava_test_options']['ava_pay_db_version'] = '0.3.0';
		AVA_Pay_Events::install();
		$this->assertSame( '0.4.0', get_option( 'ava_pay_db_version' ) );
	}

	public function test_the_verify_endpoint_row_is_marked_verify_endpoint(): void {
		AVA_Pay_Events::record_verification(
			array(
				'outcome'  => 'verified',
				'platform' => 'https://chatgpt.com',
			)
		);
		AVA_Pay_Events::record_verification(
			array(
				'outcome' => 'failed',
				'source'  => 'verify_endpoint',
			)
		);
		$this->assertSame( 'verify_endpoint', $this->wpdb->inserts[0][1]['source'], 'the default' );
		$this->assertNull( $this->wpdb->inserts[0][1]['path'] );
		$this->assertSame( 'verify_endpoint', $this->wpdb->inserts[1][1]['source'] );
	}

	public function test_a_page_visit_row_carries_source_and_path_and_nothing_else_new(): void {
		$event = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted'  => true,
					'protocol' => 'web-bot-auth',
					'agent'    => array( 'id' => 'https://chatgpt.com' ),
				),
			),
			array( 'signature-agent' => '"https://chatgpt.com"', 'signature-input' => 'sig1=("@authority")', 'signature' => 'sig1=:AA==:' ),
			AVA_Pay_Page_Visit::request_path( '/product/widget?email=a%40b.example' )
		);
		AVA_Pay_Events::record_verification( $event );

		list( $table, $row ) = $this->wpdb->inserts[0];
		$this->assertSame( 'wp_ava_pay_verification_events', $table );
		$this->assertSame( 'page_view', $row['source'] );
		$this->assertSame( '/product/widget', $row['path'] );
		$this->assertSame( 'verified', $row['outcome'] );
		$this->assertSame( 1, $row['identity_only'] );
		$this->assertNull( $row['discount_pct'] );
		$this->assertNull( $row['discount_code'] );
		$this->assertSame(
			array( 'created_at', 'protocol', 'platform', 'outcome', 'reason', 'identity_only', 'discount_pct', 'discount_code', 'source', 'path' ),
			array_keys( $row )
		);
	}
}
