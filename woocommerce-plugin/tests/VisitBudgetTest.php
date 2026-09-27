<?php
/**
 * The page-visit verification budget (storage and clock injected).
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class VisitBudgetTest extends TestCase {

	/** @var array<string,mixed> */
	private $store = array();

	/** @var int */
	private $writes = 0;

	/** @var int 2026-09-27 12:00:10 UTC, ten seconds into a minute. */
	private $now = 1790510410;

	private function budget( array $limits = array() ): AVA_Pay_Visit_Budget {
		return new AVA_Pay_Visit_Budget(
			function ( $key ) {
				return array_key_exists( $key, $this->store ) ? $this->store[ $key ] : false;
			},
			function ( $key, $value, $ttl ) {
				$this->store[ $key ] = $value;
				++$this->writes;
			},
			function () {
				return $this->now;
			},
			$limits
		);
	}

	public function test_defaults_are_the_documented_numbers(): void {
		$this->assertSame(
			array(
				'agent_per_minute' => 30,
				'agent_per_day'    => 2000,
				'site_per_minute'  => 120,
				'site_per_day'     => 10000,
			),
			AVA_Pay_Visit_Budget::DEFAULT_LIMITS
		);
	}

	public function test_thirty_a_minute_per_agent_by_default(): void {
		$budget = $this->budget();
		for ( $i = 0; $i < 30; $i++ ) {
			$this->assertTrue( $budget->admit( 'https://chatgpt.com' ), "visit {$i}" );
		}
		$this->assertFalse( $budget->admit( 'https://chatgpt.com' ), 'the 31st in the same minute' );
		$this->assertTrue( $budget->admit( 'https://other-agent.example' ), 'another agent has its own budget' );

		$this->now += 60;
		$this->assertTrue( $budget->admit( 'https://chatgpt.com' ), 'the next minute starts fresh' );
	}

	public function test_minute_windows_are_fixed_not_sliding(): void {
		$budget = $this->budget( array( 'agent_per_minute' => 1 ) );
		$this->assertTrue( $budget->admit( 'a' ) );
		$this->assertFalse( $budget->admit( 'a' ) );
		$this->now += 50; // 12:01:00, a new minute although only 50 s passed.
		$this->assertTrue( $budget->admit( 'a' ) );
	}

	public function test_two_thousand_a_day_per_agent_by_default(): void {
		$budget = $this->budget( array( 'agent_per_minute' => 100000, 'site_per_minute' => 100000 ) );
		for ( $i = 0; $i < 2000; $i++ ) {
			$budget->admit( 'https://chatgpt.com' );
		}
		$this->assertFalse( $budget->admit( 'https://chatgpt.com' ), 'the 2,001st of the UTC day' );
		$this->now += 11 * 3600 + 60; // 23:01 the same UTC day.
		$this->assertFalse( $budget->admit( 'https://chatgpt.com' ) );
		$this->now += 3600; // 00:01 the next UTC day.
		$this->assertTrue( $budget->admit( 'https://chatgpt.com' ) );
	}

	public function test_the_site_cap_bounds_a_flood_that_rotates_agent_labels(): void {
		$budget = $this->budget();
		$admitted = 0;
		for ( $i = 0; $i < 500; $i++ ) {
			if ( $budget->admit( "https://fake-{$i}.example" ) ) {
				++$admitted;
			}
		}
		$this->assertSame( 120, $admitted );
		$per_agent_keys = array_filter(
			array_keys( $this->store ),
			static function ( $k ) {
				return 0 === strpos( $k, 'ava_pay_vb_' ) && 0 !== strpos( $k, 'ava_pay_vb_site_' );
			}
		);
		$this->assertCount( 240, $per_agent_keys, 'past the site cap no per-agent counters are created' );
	}

	public function test_over_budget_counts_nothing(): void {
		$budget = $this->budget( array( 'agent_per_minute' => 1 ) );
		$budget->admit( 'a' );
		$before = $this->store;
		$writes = $this->writes;
		$this->assertFalse( $budget->admit( 'a' ) );
		$this->assertSame( $before, $this->store );
		$this->assertSame( $writes, $this->writes );
	}

	public function test_a_zero_limit_admits_nothing(): void {
		$this->assertFalse( $this->budget( array( 'site_per_day' => 0 ) )->admit( 'a' ) );
		$this->assertFalse( $this->budget( array( 'agent_per_minute' => -5 ) )->admit( 'a' ), 'negative floors at zero' );
		$this->assertTrue( $this->budget( array( 'agent_per_minute' => 'lots' ) )->admit( 'a' ), 'a non-number keeps the default' );
	}

	public function test_skips_are_tallied_by_day_and_label(): void {
		$budget = $this->budget();
		$budget->count_skip( 'https://chatgpt.com' );
		$budget->count_skip( 'https://chatgpt.com' );
		$budget->count_skip( null );
		$this->now -= 86400 * 3;
		$budget->count_skip( 'https://chatgpt.com' );
		$this->now -= 86400 * 10; // 13 days before "today".
		$budget->count_skip( 'https://chatgpt.com' );
		$this->now += 86400 * 13;

		$this->assertSame( array( 'https://chatgpt.com' => 3, '' => 1 ), $budget->skips( 7 ) );
		$this->assertSame( array( 'https://chatgpt.com' => 4, '' => 1 ), $budget->skips( 30 ) );
		$this->assertSame( array( 'https://chatgpt.com' => 2, '' => 1 ), $budget->skips( 1 ) );
	}

	public function test_skip_labels_are_capped_per_day(): void {
		$budget = $this->budget();
		for ( $i = 0; $i < 40; $i++ ) {
			$budget->count_skip( "https://fake-{$i}.example" );
		}
		$budget->count_skip( 'https://fake-0.example' );
		$tally = $budget->skips( 1 );
		$this->assertCount( AVA_Pay_Visit_Budget::SKIP_LABELS_MAX + 1, $tally );
		$this->assertSame( 2, $tally['https://fake-0.example'], 'a label already kept keeps counting' );
		$this->assertSame( 40 - AVA_Pay_Visit_Budget::SKIP_LABELS_MAX, $tally[ AVA_Pay_Visit_Budget::OTHER_LABEL ] );
		$this->assertSame( 41, array_sum( $tally ) );
	}

	public function test_window_start_is_utc_midnight_days_minus_one_ago(): void {
		$budget = $this->budget();
		$this->assertSame( '2026-09-27 00:00:00', gmdate( 'Y-m-d H:i:s', $budget->window_start( 1 ) ) );
		$this->assertSame( '2026-09-21 00:00:00', gmdate( 'Y-m-d H:i:s', $budget->window_start( 7 ) ) );
		$this->assertSame( '2026-08-29 00:00:00', gmdate( 'Y-m-d H:i:s', $budget->window_start( 30 ) ) );
	}
}
