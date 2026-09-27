<?php
/**
 * At most one page-visit verification in flight per site.
 *
 * Why: anyone can send made-up Signature headers with a Signature-Agent that
 * points at a slow server, and each such request holds a PHP worker for the
 * whole API timeout after the response is sent. The budget limits how many
 * start per minute; this lock limits how many run at once, to one, so hostile
 * traffic can hold at most one worker, for at most one timeout, at a time.
 * Real signed-agent volume is tiny, so one at a time costs real visits
 * nothing measurable; a visit that finds the lock held is counted as "not
 * checked (busy)".
 *
 * The lock is one row, value "<expiry>:<token>". It must be atomic without a
 * persistent object cache (transients are read-then-write on a plain
 * install), so the storage the WordPress layer injects is SQL on the options
 * table, whose option_name is a unique key:
 *
 *   add($value)          INSERT IGNORE; true only for the one caller whose
 *                        row went in;
 *   get()                the current value, or null;
 *   swap($old, $new)     UPDATE ... WHERE option_value = $old; true only for
 *                        the one caller that replaced exactly $old, which is
 *                        how an expired lock (a worker that died holding it)
 *                        is taken over without two callers both winning;
 *   delete_if($value)    DELETE ... WHERE option_value = $value, so a holder
 *                        whose lock expired and was taken over cannot release
 *                        the new holder's lock.
 *
 * Pure (no WordPress): storage, clock and token are injected.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Visit_Lock {

	/** Option row that holds the lock. */
	const OPTION_NAME = 'ava_pay_page_visit_lock';

	/** @var array{add:callable,get:callable,swap:callable,delete_if:callable} */
	private $store;

	/** @var callable(): int */
	private $now;

	/** @var int */
	private $ttl;

	/** @var string */
	private $token;

	/** @var string|null The value this instance wrote, while it holds the lock. */
	private $held = null;

	/**
	 * @param array    $store {add, get, swap, delete_if} callables, see the class docblock.
	 * @param callable $now   fn(): int, Unix seconds.
	 * @param int      $ttl   Seconds the lock lives if never released. Just
	 *                        above the API timeout.
	 * @param string   $token Unique per request.
	 */
	public function __construct( array $store, callable $now, $ttl, $token ) {
		$this->store = $store;
		$this->now   = $now;
		$this->ttl   = max( 1, (int) $ttl );
		$this->token = (string) $token;
	}

	/**
	 * Take the lock if nobody holds a live one.
	 *
	 * @return bool
	 */
	public function acquire() {
		if ( null !== $this->held ) {
			return true;
		}
		$now   = (int) call_user_func( $this->now );
		$value = ( $now + $this->ttl ) . ':' . $this->token;

		if ( call_user_func( $this->store['add'], $value ) ) {
			$this->held = $value;
			return true;
		}
		$current = call_user_func( $this->store['get'] );
		if ( null === $current || false === $current ) {
			// Released between our insert and our read: one more try.
			if ( call_user_func( $this->store['add'], $value ) ) {
				$this->held = $value;
				return true;
			}
			return false;
		}
		if ( self::expiry( (string) $current ) > $now ) {
			return false;
		}
		if ( call_user_func( $this->store['swap'], (string) $current, $value ) ) {
			$this->held = $value;
			return true;
		}
		return false;
	}

	/** Release the lock if this instance holds it. Safe to call twice. */
	public function release() {
		if ( null === $this->held ) {
			return;
		}
		call_user_func( $this->store['delete_if'], $this->held );
		$this->held = null;
	}

	/** @return bool */
	public function is_held() {
		return null !== $this->held;
	}

	/**
	 * Expiry from a stored value. A value that does not parse reads as
	 * expired, so a corrupt row can be taken over instead of blocking every
	 * verification forever.
	 *
	 * @param string $value Stored value.
	 * @return int
	 */
	private static function expiry( $value ) {
		$colon = strpos( $value, ':' );
		$head  = false === $colon ? $value : substr( $value, 0, $colon );
		return ctype_digit( $head ) ? (int) $head : 0;
	}
}
