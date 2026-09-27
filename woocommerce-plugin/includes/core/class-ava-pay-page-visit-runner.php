<?php
/**
 * One captured page visit, from "should we check it" to the recorded row.
 * The order is the point, so it lives here, pure, where a test can drive two
 * visits against each other:
 *
 *   1. backoff: a label whose last check ended error or unverifiable is
 *      skipped for a while (read-only, before anything is taken);
 *   2. lock: at most one verification in flight per site; a visit that finds
 *      it held is skipped as busy and consumes no budget;
 *   3. budget: per-agent and per-site windows, counted only by the lock
 *      holder;
 *   4. one /verify call, one row, and a backoff when the check could not
 *      complete;
 *   5. the lock is released however the call ended.
 *
 * Every skip is a "not checked" tally, never a row.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Page_Visit_Runner {

	/** run() results. */
	const RECORDED        = 'recorded';
	const SKIPPED_BACKOFF = 'skipped_backoff';
	const SKIPPED_BUSY    = 'skipped_busy';
	const SKIPPED_BUDGET  = 'skipped_budget';

	/**
	 * @param array                $pending         {incoming: IncomingRequest, path: string}.
	 * @param AVA_Pay_Visit_Budget $budget          Budget, tallies and backoff.
	 * @param AVA_Pay_Visit_Lock   $lock            This request's lock handle.
	 * @param callable             $verify          fn(array $incoming): array API client result.
	 * @param callable             $record          fn(array $row): void.
	 * @param int                  $backoff_seconds See AVA_Pay_Visit_Budget::DEFAULT_BACKOFF_SECONDS.
	 * @return string One of the result constants.
	 */
	public static function run( array $pending, AVA_Pay_Visit_Budget $budget, AVA_Pay_Visit_Lock $lock, callable $verify, callable $record, $backoff_seconds = AVA_Pay_Visit_Budget::DEFAULT_BACKOFF_SECONDS ) {
		$headers = $pending['incoming']['headers'];
		$bucket  = AVA_Pay_Page_Visit::budget_bucket( $headers );
		$label   = AVA_Pay_Page_Visit::agent_label( $headers );

		if ( $budget->in_backoff( $bucket ) ) {
			$budget->count_skip( $label, AVA_Pay_Visit_Budget::SKIP_BACKOFF );
			return self::SKIPPED_BACKOFF;
		}
		if ( ! $lock->acquire() ) {
			$budget->count_skip( $label, AVA_Pay_Visit_Budget::SKIP_BUSY );
			return self::SKIPPED_BUSY;
		}

		try {
			if ( ! $budget->admit( $bucket ) ) {
				$budget->count_skip( $label, AVA_Pay_Visit_Budget::SKIP_BUDGET );
				return self::SKIPPED_BUDGET;
			}
			$row = AVA_Pay_Page_Visit::event( call_user_func( $verify, $pending['incoming'] ), $headers, $pending['path'] );
			call_user_func( $record, $row );
			if ( 'error' === $row['outcome'] || 'unverifiable' === $row['outcome'] ) {
				$budget->start_backoff( $bucket, $backoff_seconds );
			}
			return self::RECORDED;
		} finally {
			$lock->release();
		}
	}
}
