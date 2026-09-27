<?php
/**
 * The one-at-a-time page-visit lock, over an in-memory store with the same
 * atomic semantics as the SQL the WordPress layer injects (INSERT IGNORE,
 * UPDATE ... WHERE value = old, DELETE ... WHERE value = mine). The live
 * MySQL run is in the PR body.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class VisitLockTest extends TestCase {

	/** @var string|null The one lock row. */
	public $row = null;

	/** @var int */
	public $now = 1790510410;

	/** @var callable|null Runs between add() failing and get(), to stage races. */
	public $between = null;

	public function store(): array {
		return array(
			'add'       => function ( $value ) {
				if ( null !== $this->row ) {
					return false;
				}
				$this->row = $value;
				return true;
			},
			'get'       => function () {
				if ( null !== $this->between ) {
					$between       = $this->between;
					$this->between = null;
					$between();
				}
				return $this->row;
			},
			'swap'      => function ( $old, $new ) {
				if ( $this->row !== $old ) {
					return false;
				}
				$this->row = $new;
				return true;
			},
			'delete_if' => function ( $value ) {
				if ( $this->row === $value ) {
					$this->row = null;
				}
			},
		);
	}

	public function lock( string $token, int $ttl = 5 ): AVA_Pay_Visit_Lock {
		return new AVA_Pay_Visit_Lock(
			$this->store(),
			function () {
				return $this->now;
			},
			$ttl,
			$token
		);
	}

	public function test_only_one_holder_at_a_time(): void {
		$a = $this->lock( 'a' );
		$b = $this->lock( 'b' );
		$this->assertTrue( $a->acquire() );
		$this->assertFalse( $b->acquire() );
		$this->assertSame( ( $this->now + 5 ) . ':a', $this->row );
		$a->release();
		$this->assertNull( $this->row );
		$this->assertTrue( $b->acquire() );
	}

	public function test_an_expired_lock_is_taken_over_once(): void {
		$dead = $this->lock( 'dead' );
		$dead->acquire(); // Its worker dies without releasing.
		$this->now += 4;
		$this->assertFalse( $this->lock( 'early' )->acquire(), 'still live a second before its expiry' );
		$this->now += 1; // Exactly at expiry: the TTL has run out.
		$b = $this->lock( 'b' );
		$c = $this->lock( 'c' );
		$this->assertTrue( $b->acquire() );
		$this->assertFalse( $c->acquire(), 'the takeover is itself exclusive' );
	}

	public function test_a_stale_holder_cannot_release_the_new_holders_lock(): void {
		$slow = $this->lock( 'slow' );
		$slow->acquire();
		$this->now += 10;
		$new = $this->lock( 'new' );
		$this->assertTrue( $new->acquire() );
		$slow->release();
		$this->assertSame( ( $this->now + 5 ) . ':new', $this->row );
		$this->assertFalse( $this->lock( 'third' )->acquire() );
	}

	public function test_a_takeover_that_loses_the_race_does_not_hold(): void {
		$this->lock( 'dead' )->acquire();
		$this->now += 10;
		$loser = $this->lock( 'loser' );
		// Another request swaps the expired row between our read and our swap.
		$this->between = function () {
			$this->row = ( $this->now + 5 ) . ':winner';
		};
		$this->assertFalse( $loser->acquire() );
		$this->assertFalse( $loser->is_held() );
		$loser->release();
		$this->assertSame( ( $this->now + 5 ) . ':winner', $this->row, 'the loser releases nothing' );
	}

	public function test_released_between_insert_and_read_retries_once(): void {
		$this->lock( 'a' )->acquire();
		$b             = $this->lock( 'b' );
		$this->between = function () {
			$this->row = null;
		};
		$this->assertTrue( $b->acquire() );
		$this->assertSame( ( $this->now + 5 ) . ':b', $this->row );
	}

	public function test_a_corrupt_row_reads_as_expired(): void {
		$this->row = 'garbage';
		$this->assertTrue( $this->lock( 'a' )->acquire() );
	}

	public function test_release_is_idempotent_and_acquire_is_reentrant(): void {
		$a = $this->lock( 'a' );
		$this->assertTrue( $a->acquire() );
		$this->assertTrue( $a->acquire() );
		$a->release();
		$a->release();
		$this->assertNull( $this->row );
	}
}
