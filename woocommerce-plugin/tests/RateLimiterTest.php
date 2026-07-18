<?php
/**
 * Rate limiter counting logic (storage injected, transients in production).
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class RateLimiterTest extends TestCase {

	/** @var array<string,int> */
	private $store = array();

	/** @var array<string,int> */
	private $ttls = array();

	private function limiter( int $limit, int $window = 60 ): AVA_Pay_Rate_Limiter {
		return new AVA_Pay_Rate_Limiter(
			function ( $key ) {
				return array_key_exists( $key, $this->store ) ? $this->store[ $key ] : false;
			},
			function ( $key, $count, $ttl ) {
				$this->store[ $key ] = $count;
				$this->ttls[ $key ]  = $ttl;
			},
			$limit,
			$window
		);
	}

	public function test_allows_up_to_limit_then_blocks(): void {
		$limiter = $this->limiter( 3 );
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
		$this->assertFalse( $limiter->allow( '1.2.3.4' ) );
		$this->assertFalse( $limiter->allow( '1.2.3.4' ), 'stays blocked within the window' );
	}

	public function test_buckets_are_independent(): void {
		$limiter = $this->limiter( 1 );
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
		$this->assertFalse( $limiter->allow( '1.2.3.4' ) );
		$this->assertTrue( $limiter->allow( '5.6.7.8' ), 'another client is unaffected' );
	}

	public function test_window_reset_allows_again(): void {
		$limiter = $this->limiter( 1, 60 );
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
		$this->assertFalse( $limiter->allow( '1.2.3.4' ) );
		$this->assertSame( array( 60 ), array_values( $this->ttls ), 'window length handed to storage as TTL' );

		// Simulate transient expiry.
		$this->store = array();
		$this->assertTrue( $limiter->allow( '1.2.3.4' ) );
	}
}
