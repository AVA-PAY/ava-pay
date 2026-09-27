<?php
/**
 * How many signed page visits get verified: a budget that protects the
 * merchant's site and the AVA Pay API from a flood of signed requests.
 *
 * Two layers, each with a per-minute and a per-day window:
 *
 *   - per agent (the Signature-Agent origin, else the keyid), 30 a minute and
 *     2,000 a day by default, so one busy or misbehaving agent cannot use up
 *     the site's share;
 *   - per site, 20 a minute and 2,000 a day by default. The agent label is
 *     read from headers nobody has verified yet, so a flood that rotates it
 *     would get a fresh per-agent budget on every request. The site layer is
 *     what still bounds that flood, and it is checked first, so a rotating
 *     flood past the site cap creates no per-agent counters either.
 *
 * Windows are fixed and named by their index (minute number, UTC date), so a
 * counter never carries over into the next window whatever its TTL does.
 *
 * Over budget, the visit is not verified and not recorded as a row; instead
 * a per-day "not checked" tally is kept by agent label and reason (capped,
 * see SKIP_LABELS_MAX) so the merchant can see that visits were skipped. The
 * same tally takes the two other reasons a visit goes unchecked: another
 * verification was in flight (SKIP_BUSY, see AVA_Pay_Visit_Lock), or the
 * label is backing off after its last check could not complete (SKIP_BACKOFF,
 * see in_backoff()).
 *
 * Storage and clock are injected (transients and time() in production,
 * arrays in tests). Like the verify endpoint's limiter, counts are
 * read-then-write and not atomic: two simultaneous requests can both pass on
 * the last slot. That is an overshoot of a request or two, not a bypass.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Visit_Budget {

	/** Defaults; each is behind its own filter in the WordPress layer. */
	const DEFAULT_LIMITS = array(
		'agent_per_minute' => 30,
		'agent_per_day'    => 2000,
		'site_per_minute'  => 20,
		'site_per_day'     => 2000,
	);

	/** Why a visit was not checked, as tallied by count_skip(). */
	const SKIP_BUDGET  = 'budget';
	const SKIP_BUSY    = 'busy';
	const SKIP_BACKOFF = 'backoff';
	const SKIP_REASONS = array( self::SKIP_BUDGET, self::SKIP_BUSY, self::SKIP_BACKOFF );

	/**
	 * How long a label is skipped after a check ended in error or
	 * unverifiable (filter: ava_pay_page_visit_backoff_seconds). A label
	 * rotation defeats it; it exists so one dead or slow directory is not
	 * asked again on every visit, not as a bound on hostile traffic, which
	 * is the lock's job.
	 */
	const DEFAULT_BACKOFF_SECONDS = 600;

	/**
	 * Distinct agent labels kept per day in the "not checked" tally. The
	 * labels are unverified, so without a cap a label-rotating flood would
	 * grow the stored map without bound. Past the cap, skips are counted
	 * under OTHER_LABEL.
	 */
	const SKIP_LABELS_MAX = 25;

	const OTHER_LABEL = '(other)';

	/** How long a day's tally is kept: the admin view reads back 30 days. */
	const SKIP_TTL_SECONDS = 32 * 86400;

	/** @var callable(string): mixed */
	private $get;

	/** @var callable(string, mixed, int): void */
	private $set;

	/** @var callable(): int */
	private $now;

	/** @var array<string,int> */
	private $limits;

	/**
	 * @param callable $get    fn(string $key): mixed, false when absent.
	 * @param callable $set    fn(string $key, mixed $value, int $ttl): void.
	 * @param callable $now    fn(): int, Unix seconds.
	 * @param array    $limits Overrides for DEFAULT_LIMITS (each floored at 0).
	 */
	public function __construct( callable $get, callable $set, callable $now, array $limits = array() ) {
		$this->get    = $get;
		$this->set    = $set;
		$this->now    = $now;
		$this->limits = array();
		foreach ( self::DEFAULT_LIMITS as $name => $default ) {
			$this->limits[ $name ] = isset( $limits[ $name ] ) && is_numeric( $limits[ $name ] )
				? max( 0, (int) $limits[ $name ] )
				: $default;
		}
	}

	/**
	 * Count one verification for $bucket if every window has room, and say
	 * whether it may go ahead. Nothing is counted when any window is full.
	 *
	 * @param string $bucket Agent label (see AVA_Pay_Page_Visit::budget_bucket()).
	 * @return bool
	 */
	public function admit( $bucket ) {
		$now    = (int) call_user_func( $this->now );
		$minute = (string) intdiv( $now, 60 );
		$day    = gmdate( 'Ymd', $now );
		$agent  = md5( (string) $bucket );

		// Site windows first: see the class docblock.
		$windows = array(
			array( 'ava_pay_vb_site_m' . $minute, $this->limits['site_per_minute'], 120 ),
			array( 'ava_pay_vb_site_d' . $day, $this->limits['site_per_day'], 2 * 86400 ),
			array( 'ava_pay_vb_' . $agent . '_m' . $minute, $this->limits['agent_per_minute'], 120 ),
			array( 'ava_pay_vb_' . $agent . '_d' . $day, $this->limits['agent_per_day'], 2 * 86400 ),
		);

		$counts = array();
		foreach ( $windows as $i => $window ) {
			$current      = call_user_func( $this->get, $window[0] );
			$counts[ $i ] = false === $current ? 0 : (int) $current;
			if ( $counts[ $i ] >= $window[1] ) {
				return false;
			}
		}
		foreach ( $windows as $i => $window ) {
			call_user_func( $this->set, $window[0], $counts[ $i ] + 1, $window[2] );
		}
		return true;
	}

	/**
	 * Add one to today's "not checked" tally for $label and $reason.
	 *
	 * @param string|null $label  Agent label, null when the request named none.
	 * @param string      $reason One of SKIP_REASONS (anything else counts as budget).
	 */
	public function count_skip( $label, $reason = self::SKIP_BUDGET ) {
		$now    = (int) call_user_func( $this->now );
		$key    = self::skip_key( gmdate( 'Ymd', $now ) );
		$reason = in_array( $reason, self::SKIP_REASONS, true ) ? $reason : self::SKIP_BUDGET;
		$tally  = call_user_func( $this->get, $key );
		if ( ! is_array( $tally ) ) {
			$tally = array();
		}
		$label = ( null === $label || '' === (string) $label ) ? '' : (string) $label;
		if ( ! isset( $tally[ $label ] ) && count( $tally ) >= self::SKIP_LABELS_MAX ) {
			$label = self::OTHER_LABEL;
		}
		if ( ! isset( $tally[ $label ] ) || ! is_array( $tally[ $label ] ) ) {
			$tally[ $label ] = array();
		}
		$tally[ $label ][ $reason ] = ( isset( $tally[ $label ][ $reason ] ) ? (int) $tally[ $label ][ $reason ] : 0 ) + 1;
		call_user_func( $this->set, $key, $tally, self::SKIP_TTL_SECONDS );
	}

	/**
	 * "Not checked" tallies summed over the last $days UTC days, today
	 * included, by label (all reasons together). The empty-string label is
	 * the request that named no agent.
	 *
	 * @param int $days Number of days.
	 * @return array<string,int>
	 */
	public function skips( $days ) {
		$out = array();
		foreach ( $this->skip_cells( $days ) as $cell ) {
			list( $label, , $count ) = $cell;
			$out[ $label ]           = ( isset( $out[ $label ] ) ? $out[ $label ] : 0 ) + $count;
		}
		return $out;
	}

	/**
	 * The same tallies by reason, for the line under the counts table.
	 *
	 * @param int $days Number of days.
	 * @return array<string,int> Every SKIP_REASONS key, zero when none.
	 */
	public function skip_reasons( $days ) {
		$out = array_fill_keys( self::SKIP_REASONS, 0 );
		foreach ( $this->skip_cells( $days ) as $cell ) {
			$out[ $cell[1] ] += $cell[2];
		}
		return $out;
	}

	/**
	 * Is $bucket backing off after a check that could not complete?
	 *
	 * @param string $bucket Agent bucket.
	 * @return bool
	 */
	public function in_backoff( $bucket ) {
		$until = call_user_func( $this->get, self::backoff_key( $bucket ) );
		return false !== $until && (int) $until > (int) call_user_func( $this->now );
	}

	/**
	 * Skip $bucket for $seconds from now.
	 *
	 * @param string $bucket  Agent bucket.
	 * @param int    $seconds Backoff length; 0 or less does nothing.
	 */
	public function start_backoff( $bucket, $seconds = self::DEFAULT_BACKOFF_SECONDS ) {
		$seconds = (int) $seconds;
		if ( $seconds <= 0 ) {
			return;
		}
		$until = (int) call_user_func( $this->now ) + $seconds;
		call_user_func( $this->set, self::backoff_key( $bucket ), $until, $seconds );
	}

	/**
	 * Every stored tally cell in the window, as [label, reason, count]. A
	 * day stored by 0.4.0 before skip reasons existed (label => int) reads
	 * as budget, the only reason there was.
	 *
	 * @param int $days Number of days.
	 * @return array<int,array{0:string,1:string,2:int}>
	 */
	private function skip_cells( $days ) {
		$now   = (int) call_user_func( $this->now );
		$cells = array();
		for ( $i = 0; $i < (int) $days; $i++ ) {
			$tally = call_user_func( $this->get, self::skip_key( gmdate( 'Ymd', $now - $i * 86400 ) ) );
			if ( ! is_array( $tally ) ) {
				continue;
			}
			foreach ( $tally as $label => $by_reason ) {
				if ( ! is_array( $by_reason ) ) {
					$by_reason = array( self::SKIP_BUDGET => (int) $by_reason );
				}
				foreach ( $by_reason as $reason => $count ) {
					if ( in_array( $reason, self::SKIP_REASONS, true ) ) {
						$cells[] = array( (string) $label, $reason, (int) $count );
					}
				}
			}
		}
		return $cells;
	}

	/**
	 * Start of the window skips($days) covers, for queries that must line up
	 * with it: midnight UTC, $days - 1 days ago.
	 *
	 * @param int $days Number of days.
	 * @return int Unix seconds.
	 */
	public function window_start( $days ) {
		$now = (int) call_user_func( $this->now );
		return ( intdiv( $now, 86400 ) - ( (int) $days - 1 ) ) * 86400;
	}

	/**
	 * @param string $ymd UTC date, Ymd.
	 * @return string
	 */
	private static function skip_key( $ymd ) {
		return 'ava_pay_vskip_' . $ymd;
	}

	/**
	 * @param string $bucket Agent bucket.
	 * @return string
	 */
	private static function backoff_key( $bucket ) {
		return 'ava_pay_vneg_' . md5( (string) $bucket );
	}
}
