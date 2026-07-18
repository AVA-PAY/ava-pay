<?php
/**
 * Commerce attribution helpers (port of commerce.ts, Woo-normalized codes).
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class CommerceTest extends TestCase {

	public function test_find_ava_discount_code(): void {
		$this->assertSame( 'ava-x7k2m4p9', AVA_Pay_Commerce::find_ava_discount_code( array( 'summer10', 'ava-x7k2m4p9' ) ) );
		$this->assertSame(
			'ava-x7k2m4p9',
			AVA_Pay_Commerce::find_ava_discount_code( array( 'AVA-X7K2M4P9' ) ),
			'match is case-insensitive and result canonical lowercase (Woo normalizes codes)'
		);
		$this->assertNull( AVA_Pay_Commerce::find_ava_discount_code( array( 'summer10', 'avalanche' ) ) );
		$this->assertNull( AVA_Pay_Commerce::find_ava_discount_code( array() ) );
		$this->assertNull( AVA_Pay_Commerce::find_ava_discount_code( null ) );
		$this->assertNull( AVA_Pay_Commerce::find_ava_discount_code( array( 42, null ) ) );
	}

	public function test_to_minor_units(): void {
		$this->assertSame( 12345, AVA_Pay_Commerce::to_minor_units( '123.45' ) );
		$this->assertSame( 4999, AVA_Pay_Commerce::to_minor_units( 49.99 ) );
		$this->assertSame( 0, AVA_Pay_Commerce::to_minor_units( 0 ) );
		$this->assertSame( 10, AVA_Pay_Commerce::to_minor_units( '0.1' ) );
		$this->assertNull( AVA_Pay_Commerce::to_minor_units( null ) );
		$this->assertNull( AVA_Pay_Commerce::to_minor_units( '' ) );
		$this->assertNull( AVA_Pay_Commerce::to_minor_units( 'abc' ) );
	}
}
