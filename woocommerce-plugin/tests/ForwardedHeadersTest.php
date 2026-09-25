<?php
/**
 * What leaves the site. Two halves:
 *
 *   - parity: every case in tests/fixtures/forwarding-golden.json, generated
 *     by running the REAL Shopify-app minimizer and the SDK's own
 *     Signature-Input parser (scripts/generate-forwarding-golden.ts), replayed
 *     through AVA_Pay_Forwarded_Headers with identical output required;
 *   - behavior: the plugin's own request shapes, including every fixture in
 *     verify-fixtures.json (real SDK signatures), which must keep every
 *     header their signature covers.
 *
 * If parity fails after a legitimate TS change, regenerate the golden file
 * and port the change; never adjust the PHP side alone.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class ForwardedHeadersTest extends TestCase {

	/** @var array */
	private static $golden;

	const HOST = 'demo-store.example';

	/** What a same-origin storefront call to the REST endpoint carries besides the agent's headers. */
	const BROWSER_HEADERS = array(
		'x-forwarded-for' => '203.0.113.7, 10.0.0.1',
		'user-agent'      => 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36',
		'cookie'          => 'wordpress_logged_in_x=abc',
		'accept'          => 'application/json',
		'accept-language' => 'en-US,en;q=0.9',
		'x-wp-nonce'      => 'abc123',
		'x-request-id'    => 'req-1',
	);

	public static function setUpBeforeClass(): void {
		self::$golden = ava_pay_load_fixture( 'forwarding-golden.json' );
	}

	public function test_covered_field_parity(): void {
		$cases = self::$golden['coveredCases'];
		$this->assertGreaterThan( 30, count( $cases ), 'golden file looks truncated' );
		foreach ( $cases as $case ) {
			$this->assertSame(
				$case['members'],
				AVA_Pay_Forwarded_Headers::split_dictionary_members( $case['signatureInput'] ),
				"split mismatch: {$case['name']}"
			);
			$this->assertSame(
				$case['expected'],
				AVA_Pay_Forwarded_Headers::covered_header_fields( $case['signatureInput'] ),
				"covered-field mismatch: {$case['name']}"
			);
		}
	}

	public function test_minimize_parity(): void {
		foreach ( self::$golden['minimizeCases'] as $case ) {
			$this->assertSame(
				$case['expected'],
				AVA_Pay_Forwarded_Headers::minimize( $case['headers'], $case['hasBody'] ),
				"minimize mismatch: {$case['name']}"
			);
		}
	}

	private function wba( array $extra = array(), $components = '"@authority" "signature-agent";key="sig1"' ): array {
		return array_merge(
			self::BROWSER_HEADERS,
			array(
				'host'            => self::HOST,
				'signature'       => 'sig1=:AAAA:',
				'signature-input' => 'sig1=(' . $components . ');created=1790345533;keyid="k1";alg="ed25519";nonce="n1";tag="web-bot-auth"',
				'signature-agent' => 'sig1="https://agent.example"',
			),
			$extra
		);
	}

	private static function names( array $headers ): array {
		$names = array_keys( $headers );
		sort( $names );
		return $names;
	}

	public function test_wba_request_forwards_signature_and_host_only(): void {
		$this->assertSame(
			array( 'host', 'signature', 'signature-agent', 'signature-input' ),
			self::names( AVA_Pay_Forwarded_Headers::minimize( $this->wba(), false ) )
		);
	}

	public function test_covered_content_digest_and_content_type_are_forwarded(): void {
		$headers = $this->wba(
			array(
				'content-digest' => 'sha-256=:abc=:',
				'content-type'   => 'application/json',
			),
			'"@authority" "signature-agent";key="sig1" "content-digest" "content-type"'
		);
		$this->assertSame(
			array( 'content-digest', 'content-type', 'host', 'signature', 'signature-agent', 'signature-input' ),
			self::names( AVA_Pay_Forwarded_Headers::minimize( $headers, true ) )
		);
	}

	public function test_covered_custom_header_is_forwarded(): void {
		$headers = $this->wba( array( 'x-example' => 'kept' ), '"@authority" "signature-agent";key="sig1" "x-example"' );
		$out     = AVA_Pay_Forwarded_Headers::minimize( $headers, false );
		$this->assertSame( 'kept', $out['x-example'] );
	}

	public function test_uncovered_user_agent_is_dropped(): void {
		$this->assertArrayNotHasKey( 'user-agent', AVA_Pay_Forwarded_Headers::minimize( $this->wba(), false ) );
	}

	public function test_unreadable_signature_input_forwards_the_fixed_set_only(): void {
		$headers = array_merge(
			self::BROWSER_HEADERS,
			array(
				'host'            => self::HOST,
				'signature'       => 'sig1=:AAAA:',
				'signature-input' => 'sig1=("user-agent" "accept-language"',
				'x-ava-mandate'   => 'e30=',
			)
		);
		$this->assertSame(
			array( 'host', 'signature', 'signature-input', 'x-ava-mandate' ),
			self::names( AVA_Pay_Forwarded_Headers::minimize( $headers, false ) )
		);
	}

	public function test_outbound_request_keeps_method_url_and_body(): void {
		$incoming = array(
			'method'  => 'POST',
			'url'     => 'https://' . self::HOST . '/wp-json/ava-pay/v1/verify-agent',
			'headers' => $this->wba( array( 'content-type' => 'application/json' ) ),
			'body'    => '{"cart":[]}',
		);
		$out      = AVA_Pay_Forwarded_Headers::outbound_request( $incoming );

		$this->assertSame( 'POST', $out['method'] );
		$this->assertSame( $incoming['url'], $out['url'] );
		$this->assertSame( '{"cart":[]}', $out['body'] );
		$this->assertSame(
			array( 'content-type', 'host', 'signature', 'signature-agent', 'signature-input' ),
			self::names( $out['headers'] ),
			'content-type rides along with a body'
		);
	}

	/**
	 * Real SDK-signed requests: minimizing must never drop a header their
	 * signature covers, or the verifier could not rebuild the base.
	 */
	public function test_real_signed_fixtures_keep_every_covered_header(): void {
		$data = ava_pay_load_fixture( 'verify-fixtures.json' );
		foreach ( $data['fixtures'] as $fixture ) {
			$headers = array_merge( self::BROWSER_HEADERS, $fixture['request']['headers'] );
			$out     = AVA_Pay_Forwarded_Headers::outbound_request( array_merge( $fixture['request'], array( 'headers' => $headers ) ) );

			$fixture_headers = $fixture['request']['headers'];
			$covered         = AVA_Pay_Forwarded_Headers::covered_header_fields( $fixture_headers['signature-input'] ?? null );
			$must_travel     = array_merge(
				array( 'host' ),
				AVA_Pay_Forwarded_Headers::SIGNATURE_HEADERS,
				AVA_Pay_Forwarded_Headers::PROTOCOL_HEADERS,
				null === $covered ? array() : $covered
			);
			foreach ( $must_travel as $name ) {
				if ( isset( $fixture_headers[ $name ] ) ) {
					$this->assertSame( $fixture_headers[ $name ], $out['headers'][ $name ] ?? null, "{$fixture['name']}: {$name} must travel" );
				}
			}
			foreach ( array_keys( $headers ) as $name ) {
				if ( ! in_array( $name, $must_travel, true ) && 'content-type' !== $name ) {
					$this->assertArrayNotHasKey( $name, $out['headers'], "{$fixture['name']}: {$name} must not travel" );
				}
			}
		}
	}
}
