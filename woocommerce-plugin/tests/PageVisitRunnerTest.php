<?php
/**
 * The page-visit run order: backoff, lock, budget, one call, one row. The
 * headline case drives two visits against each other: the second arrives
 * while the first is inside its API call, and only one API call is made.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class PageVisitRunnerTest extends TestCase {

	/** @var array<string,mixed> Transient stand-in shared by every budget. */
	private $transients = array();

	/** @var string|null The shared lock row. */
	private $lock_row = null;

	/** @var int */
	private $now = 1790510410;

	/** @var int */
	private $api_calls = 0;

	/** @var array[] */
	private $rows = array();

	/** @var int */
	private $tokens = 0;

	private function budget( array $limits = array() ): AVA_Pay_Visit_Budget {
		return new AVA_Pay_Visit_Budget(
			function ( $key ) {
				return array_key_exists( $key, $this->transients ) ? $this->transients[ $key ] : false;
			},
			function ( $key, $value, $ttl ) {
				$this->transients[ $key ] = $value;
			},
			function () {
				return $this->now;
			},
			$limits
		);
	}

	/** A fresh lock handle per request, all on the same row, as in production. */
	private function lock(): AVA_Pay_Visit_Lock {
		return new AVA_Pay_Visit_Lock(
			array(
				'add'       => function ( $v ) {
					if ( null !== $this->lock_row ) {
						return false;
					}
					$this->lock_row = $v;
					return true;
				},
				'get'       => function () {
					return $this->lock_row;
				},
				'swap'      => function ( $old, $new ) {
					if ( $this->lock_row !== $old ) {
						return false;
					}
					$this->lock_row = $new;
					return true;
				},
				'delete_if' => function ( $v ) {
					if ( $this->lock_row === $v ) {
						$this->lock_row = null;
					}
				},
			),
			function () {
				return $this->now;
			},
			5,
			'req' . ( ++$this->tokens )
		);
	}

	private function visit( string $agent = 'https://agent.example' ): array {
		return array(
			'incoming' => array(
				'method'  => 'GET',
				'url'     => 'https://shop.example/p',
				'headers' => array(
					'host'            => 'shop.example',
					'signature'       => 'sig1=:AA==:',
					'signature-input' => 'sig1=("@authority");keyid="k";tag="web-bot-auth"',
					'signature-agent' => '"' . $agent . '"',
				),
			),
			'path'     => '/p',
		);
	}

	/** An API that answers $result, optionally running $during mid-call. */
	private function api( array $result, ?callable $during = null ): callable {
		return function () use ( $result, $during ) {
			++$this->api_calls;
			if ( null !== $during ) {
				$during();
			}
			return $result;
		};
	}

	private function record(): callable {
		return function ( $row ) {
			$this->rows[] = $row;
		};
	}

	private function run_visit( array $visit, callable $api, ?AVA_Pay_Visit_Budget $budget = null ): string {
		return AVA_Pay_Page_Visit_Runner::run( $visit, $budget ?? $this->budget(), $this->lock(), $api, $this->record() );
	}

	private const VERIFIED = array(
		'ok'     => true,
		'result' => array( 'trusted' => true ),
	);

	public function test_two_overlapping_visits_make_one_api_call(): void {
		$second = null;
		$first  = $this->run_visit(
			$this->visit( 'https://slow-directory.example' ),
			$this->api(
				array(
					'ok'    => false,
					'error' => 'timeout',
				),
				function () use ( &$second ) {
					// A second signed visit (another agent, so no backoff applies)
					// reaches shutdown while the first is still waiting on the API.
					$second = $this->run_visit( $this->visit( 'https://another.example' ), $this->api( self::VERIFIED ) );
				}
			)
		);

		$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $first );
		$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BUSY, $second );
		$this->assertSame( 1, $this->api_calls, 'one API call for two overlapping visits' );
		$this->assertCount( 1, $this->rows );
		$this->assertSame( 'error', $this->rows[0]['outcome'] );
		$this->assertSame( array( 'https://another.example' => 1 ), $this->budget()->skips( 1 ) );
		$this->assertSame( 1, $this->budget()->skip_reasons( 1 )['busy'] );
		$this->assertNull( $this->lock_row, 'released after the first call ended' );

		$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit( 'https://another.example' ), $this->api( self::VERIFIED ) ) );
		$this->assertSame( 2, $this->api_calls, 'the next visit after it runs normally' );
	}

	public function test_a_busy_visit_consumes_no_budget(): void {
		$budget = $this->budget( array( 'site_per_minute' => 1 ) );
		$this->lock()->acquire(); // Held by a request in flight.
		$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BUSY, $this->run_visit( $this->visit(), $this->api( self::VERIFIED ), $budget ) );
		$this->lock_row = null;
		$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit(), $this->api( self::VERIFIED ), $budget ) );
	}

	public function test_over_budget_releases_the_lock_and_calls_nothing(): void {
		$budget = $this->budget( array( 'agent_per_minute' => 0 ) );
		$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BUDGET, $this->run_visit( $this->visit(), $this->api( self::VERIFIED ), $budget ) );
		$this->assertSame( 0, $this->api_calls );
		$this->assertNull( $this->lock_row );
		$this->assertSame( 1, $budget->skip_reasons( 1 )['budget'] );
	}

	public function test_the_lock_is_released_when_the_call_throws(): void {
		try {
			$this->run_visit(
				$this->visit(),
				function () {
					throw new RuntimeException( 'transport exploded' );
				}
			);
			$this->fail( 'expected the throw to reach the caller' );
		} catch ( RuntimeException $e ) {
			$this->assertSame( 'transport exploded', $e->getMessage() );
		}
		$this->assertNull( $this->lock_row );
	}

	public function test_error_and_unverifiable_back_the_label_off_for_ten_minutes(): void {
		$unverifiable = array(
			'ok'     => true,
			'result' => array(
				'trusted'    => false,
				'reason'     => 'key_directory_unavailable',
				'conclusive' => false,
			),
		);
		foreach ( array( 'error' => array( 'ok' => false, 'error' => 'timeout' ), 'unverifiable' => $unverifiable ) as $case => $answer ) {
			$agent = "https://{$case}.example";
			$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit( $agent ), $this->api( $answer ) ) );
			$calls = $this->api_calls;

			$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BACKOFF, $this->run_visit( $this->visit( $agent ), $this->api( self::VERIFIED ) ), $case );
			$this->assertSame( $calls, $this->api_calls, "{$case}: no call while backing off" );
			$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit( 'https://healthy.example' ), $this->api( self::VERIFIED ) ), 'other labels are unaffected' );

			$this->now += 599;
			$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BACKOFF, $this->run_visit( $this->visit( $agent ), $this->api( self::VERIFIED ) ) );
			$this->now += 1;
			$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit( $agent ), $this->api( self::VERIFIED ) ), "{$case}: checked again after 600 s" );
		}
		$this->assertSame( 4, $this->budget()->skip_reasons( 1 )['backoff'] );
	}

	public function test_verified_and_failed_do_not_back_off(): void {
		$failed = array(
			'ok'     => true,
			'result' => array(
				'trusted'    => false,
				'reason'     => 'invalid_signature',
				'conclusive' => true,
			),
		);
		foreach ( array( self::VERIFIED, $failed ) as $answer ) {
			$this->run_visit( $this->visit(), $this->api( $answer ) );
			$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, $this->run_visit( $this->visit(), $this->api( $answer ) ) );
		}
		$this->assertSame( 4, $this->api_calls );
	}

	public function test_backoff_is_checked_before_the_lock(): void {
		$this->run_visit( $this->visit(), $this->api( array( 'ok' => false, 'error' => 'network' ) ) );
		$this->lock()->acquire();
		$this->assertSame( AVA_Pay_Page_Visit_Runner::SKIPPED_BACKOFF, $this->run_visit( $this->visit(), $this->api( self::VERIFIED ) ) );
	}

	public function test_a_zero_backoff_disables_it(): void {
		$budget = $this->budget();
		AVA_Pay_Page_Visit_Runner::run( $this->visit(), $budget, $this->lock(), $this->api( array( 'ok' => false, 'error' => 'timeout' ) ), $this->record(), 0 );
		$this->assertSame( AVA_Pay_Page_Visit_Runner::RECORDED, AVA_Pay_Page_Visit_Runner::run( $this->visit(), $budget, $this->lock(), $this->api( self::VERIFIED ), $this->record(), 0 ) );
	}
}
