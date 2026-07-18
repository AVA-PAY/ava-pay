<?php
/**
 * Fixed-window rate limiter for the public verify endpoint. Storage is
 * injected (WordPress transients in production, an array in tests) so the
 * counting logic stays pure.
 *
 * This is a plugin-side flood guard in front of the hosted API's own global
 * rate limit — it must only ever be MORE restrictive than the API, never a
 * substitute for it.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Rate_Limiter {

	/** @var callable(string): (int|false) */
	private $get;

	/** @var callable(string, int, int): void */
	private $set;

	/** @var int */
	private $limit;

	/** @var int */
	private $window_seconds;

	/**
	 * @param callable $get            fn(string $key): int|false — current count.
	 * @param callable $set            fn(string $key, int $count, int $ttl): void.
	 * @param int      $limit          Max requests per window.
	 * @param int      $window_seconds Window length.
	 */
	public function __construct( callable $get, callable $set, $limit = 60, $window_seconds = 60 ) {
		$this->get            = $get;
		$this->set            = $set;
		$this->limit          = max( 1, (int) $limit );
		$this->window_seconds = max( 1, (int) $window_seconds );
	}

	/**
	 * Count a hit for $bucket (e.g. a hashed client IP) and report whether it
	 * is still within the limit. Fixed window: the first hit sets the TTL;
	 * counts reset when the storage entry expires.
	 *
	 * @param string $bucket Rate-limit bucket key.
	 * @return bool True = allowed, false = over the limit.
	 */
	public function allow( $bucket ) {
		$key     = 'ava_pay_rl_' . md5( (string) $bucket );
		$current = call_user_func( $this->get, $key );
		$count   = ( false === $current ) ? 0 : (int) $current;
		if ( $count >= $this->limit ) {
			return false;
		}
		call_user_func( $this->set, $key, $count + 1, $this->window_seconds );
		return true;
	}
}
