<?php
/**
 * The "Agent visits" count tables, from raw rows: page-visit rows grouped by
 * platform and outcome (AVA_Pay_Events::page_visit_counts()) plus the
 * budget's "not checked" tallies (AVA_Pay_Visit_Budget::skips()). Pure, so
 * the admin view only has to escape and print.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Visit_Report {

	/** Table columns, in display order. not_checked comes from the budget. */
	const COLUMNS = array( 'verified', 'failed', 'unverifiable', 'error', 'not_checked' );

	/**
	 * @param array $count_rows Rows {platform: string|null, outcome: string, n: int|string}.
	 * @param array $skips      label => count; '' is the request that named no agent.
	 * @return array<int,array{platform:string,counts:array<string,int>,total:int}>
	 *         One entry per platform ('' = unknown), busiest first, then by
	 *         platform so equal totals list in a stable order.
	 */
	public static function summarize( array $count_rows, array $skips ) {
		$by_platform = array();
		$add         = static function ( $platform, $column, $n ) use ( &$by_platform ) {
			if ( $n <= 0 ) {
				return;
			}
			if ( ! isset( $by_platform[ $platform ] ) ) {
				$by_platform[ $platform ] = array_fill_keys( self::COLUMNS, 0 );
			}
			$by_platform[ $platform ][ $column ] += $n;
		};

		foreach ( $count_rows as $row ) {
			$outcome = isset( $row['outcome'] ) ? (string) $row['outcome'] : '';
			// not_checked is never a row, and page-visit rows carry no other
			// outcome; anything else is not this table's to show.
			if ( 'not_checked' === $outcome || ! in_array( $outcome, self::COLUMNS, true ) ) {
				continue;
			}
			$platform = isset( $row['platform'] ) ? (string) $row['platform'] : '';
			$add( $platform, $outcome, isset( $row['n'] ) ? (int) $row['n'] : 0 );
		}
		foreach ( $skips as $label => $n ) {
			$add( (string) $label, 'not_checked', (int) $n );
		}

		$out = array();
		foreach ( $by_platform as $platform => $counts ) {
			$out[] = array(
				'platform' => (string) $platform,
				'counts'   => $counts,
				'total'    => array_sum( $counts ),
			);
		}
		usort(
			$out,
			static function ( $a, $b ) {
				if ( $a['total'] !== $b['total'] ) {
					return $b['total'] - $a['total'];
				}
				return strcmp( $a['platform'], $b['platform'] );
			}
		);
		return $out;
	}
}
