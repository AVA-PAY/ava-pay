<?php
/**
 * AVA_Pay_Accept_Signature: the -01 Section 5.3 signature request.
 *
 * Byte-level parity with the Shopify twin's canonical TypeScript definition
 * is enforced from the API suite (tests/accept-signature.test.ts reads this
 * file's VALUE); these tests cover the gate and the value's load-bearing
 * parts so a local edit cannot quietly invert either.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class AcceptSignatureTest extends TestCase {

	public function test_sent_to_unverified_callers() {
		$this->assertSame(
			AVA_Pay_Accept_Signature::VALUE,
			AVA_Pay_Accept_Signature::for_outcome( false )
		);
	}

	public function test_withheld_from_trusted_callers() {
		$this->assertNull( AVA_Pay_Accept_Signature::for_outcome( true ) );
	}

	public function test_value_asks_for_what_the_verifier_requires() {
		$value = AVA_Pay_Accept_Signature::VALUE;
		$this->assertSame( 'Accept-Signature', AVA_Pay_Accept_Signature::HEADER );
		$this->assertStringContainsString( 'tag="web-bot-auth"', $value );
		$this->assertStringContainsString( '"@authority"', $value );
		$this->assertStringContainsString( '"content-digest"', $value );
		$this->assertStringContainsString( '"signature-agent";key="sig1"', $value );
		$this->assertStringContainsString( ';created;expires', $value );
		// No requested key, algorithm or nonce: any directory key, either
		// accepted algorithm, no chosen nonce value.
		$this->assertStringNotContainsString( 'keyid', $value );
		$this->assertStringNotContainsString( 'alg=', $value );
		$this->assertStringNotContainsString( 'nonce', $value );
	}
}
