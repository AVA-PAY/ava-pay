<?php
/**
 * The Agent visits count tables.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class VisitReportTest extends TestCase {

	public function test_rows_and_skips_merge_by_platform_busiest_first(): void {
		$summary = AVA_Pay_Visit_Report::summarize(
			array(
				array( 'platform' => 'https://chatgpt.com', 'outcome' => 'verified', 'n' => '12' ),
				array( 'platform' => 'https://chatgpt.com', 'outcome' => 'failed', 'n' => '1' ),
				array( 'platform' => null, 'outcome' => 'error', 'n' => '2' ),
				array( 'platform' => 'tap_agent', 'outcome' => 'unverifiable', 'n' => '3' ),
			),
			array(
				'https://chatgpt.com' => 4,
				''                    => 1,
			)
		);

		$this->assertSame(
			array(
				array(
					'platform' => 'https://chatgpt.com',
					'counts'   => array( 'verified' => 12, 'failed' => 1, 'unverifiable' => 0, 'error' => 0, 'not_checked' => 4 ),
					'total'    => 17,
				),
				array(
					'platform' => '',
					'counts'   => array( 'verified' => 0, 'failed' => 0, 'unverifiable' => 0, 'error' => 2, 'not_checked' => 1 ),
					'total'    => 3,
				),
				array(
					'platform' => 'tap_agent',
					'counts'   => array( 'verified' => 0, 'failed' => 0, 'unverifiable' => 3, 'error' => 0, 'not_checked' => 0 ),
					'total'    => 3,
				),
			),
			$summary
		);
	}

	public function test_outcomes_this_table_does_not_show_are_ignored(): void {
		$summary = AVA_Pay_Visit_Report::summarize(
			array(
				array( 'platform' => 'a', 'outcome' => 'policy_blocked', 'n' => '5' ),
				array( 'platform' => 'a', 'outcome' => 'not_checked', 'n' => '5' ),
				array( 'platform' => 'a', 'outcome' => 'verified', 'n' => '0' ),
			),
			array( 'b' => 0 )
		);
		$this->assertSame( array(), $summary );
	}

	public function test_numeric_looking_labels_stay_strings(): void {
		$summary = AVA_Pay_Visit_Report::summarize( array( array( 'platform' => '123', 'outcome' => 'failed', 'n' => 1 ) ), array() );
		$this->assertSame( '123', $summary[0]['platform'] );
	}
}
