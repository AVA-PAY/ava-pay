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
 *   - per site, 120 a minute and 10,000 a day by default. The agent label is
 *     read from headers nobody has verified yet, so a flood that rotates it
 *     would get a fresh per-agent budget on every request. The site layer is
 *     what still bounds that flood, and it is checked first, so a rotating
 *     flood past the site cap creates no per-agent counters either.
 *
 * Windows are fixed and named by their index (minute number, UTC date), so a
 * counter never carries over into the next window whatever its TTL does.
 *
 * Over budget, the visit is not verified and not recorded as a row; instead
 * a per-day "not checked" tally is kept by agent label (capped, see
 * SKIP_LABELS_MAX) so the merchant can see that visits were skipped.
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
		'site_per_minute'  => 120,
		'site_per_day'     => 10000,
	);

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
	 * Add one to today's "not checked (budget)" tally for $label.
	 *
	 * @param string|null $label Agent label, null when the request named none.
	 */
	public function count_skip( $label ) {
		$now   = (int) call_user_func( $this->now );
		$key   = self::skip_key( gmdate( 'Ymd', $now ) );
		$tally = call_user_func( $this->get, $key );
		if ( ! is_array( $tally ) ) {
			$tally = array();
		}
		$label = ( null === $label || '' === (string) $label ) ? '' : (string) $label;
		if ( ! isset( $tally[ $label ] ) && count( $tally ) >= self::SKIP_LABELS_MAX ) {
			$label = self::OTHER_LABEL;
		}
		$tally[ $label ] = ( isset( $tally[ $label ] ) ? (int) $tally[ $label ] : 0 ) + 1;
		call_user_func( $this->set, $key, $tally, self::SKIP_TTL_SECONDS );
	}

	/**
	 * "Not checked" tallies summed over the last $days UTC days, today
	 * included. The empty-string label is the request that named no agent.
	 *
	 * @param int $days Number of days.
	 * @return array<string,int>
	 */
	public function skips( $days ) {
		$now = (int) call_user_func( $this->now );
		$out = array();
		for ( $i = 0; $i < (int) $days; $i++ ) {
			$tally = call_user_func( $this->get, self::skip_key( gmdate( 'Ymd', $now - $i * 86400 ) ) );
			if ( ! is_array( $tally ) ) {
				continue;
			}
			foreach ( $tally as $label => $count ) {
				$label         = (string) $label;
				$out[ $label ] = ( isset( $out[ $label ] ) ? $out[ $label ] : 0 ) + (int) $count;
			}
		}
		return $out;
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
}
