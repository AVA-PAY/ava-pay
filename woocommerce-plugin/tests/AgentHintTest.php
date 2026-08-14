<?php
/**
 * Request-hint parity with shopify-app/app/lib/request-hints.ts (agent id and
 * protocol sniffing), including against the real signed fixture headers.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class AgentHintTest extends TestCase {

	public function test_real_wba_headers_yield_operator_origin(): void {
		$data = ava_pay_load_fixture( 'verify-fixtures.json' );
		foreach ( $data['fixtures'] as $f ) {
			if ( 'web_bot_auth_identity_only' === $f['name'] ) {
				$this->assertSame( 'https://agent-demo.ava.example', AVA_Pay_Agent_Hint::extract( $f['request']['headers'] ) );
			}
			if ( 'ava_tap_mandate_backed' === $f['name'] ) {
				$this->assertSame( 'agent_woo_fixture', AVA_Pay_Agent_Hint::extract( $f['request']['headers'] ), 'TAP falls back to keyid' );
			}
			if ( 'no_credentials' === $f['name'] ) {
				$this->assertNull( AVA_Pay_Agent_Hint::extract( $f['request']['headers'] ) );
			}
		}
	}

	public function test_signature_agent_wire_forms(): void {
		$this->assertSame(
			'https://chatgpt.com',
			AVA_Pay_Agent_Hint::extract( array( 'signature-agent' => '"https://ChatGPT.com"' ) ),
			'bare quoted form, lowercased'
		);
		$this->assertSame(
			'https://chatgpt.com',
			AVA_Pay_Agent_Hint::extract( array( 'signature-agent' => 'sig1="https://chatgpt.com"' ) ),
			'dictionary form'
		);
		$this->assertSame(
			'https://agent.example:8443',
			AVA_Pay_Agent_Hint::extract( array( 'signature-agent' => '"https://agent.example:8443/path"' ) ),
			'non-default port kept, path dropped (origin semantics)'
		);
		$this->assertSame(
			'https://agent.example',
			AVA_Pay_Agent_Hint::extract( array( 'signature-agent' => '"https://agent.example:443"' ) ),
			'default https port elided like the JS URL.origin'
		);
	}

	public function test_unusable_signature_agent_falls_back_to_keyid(): void {
		$headers = array(
			'signature-agent' => 'https://unquoted.example',
			'signature-input' => 'sig1=("@authority");keyid="agent_123";alg="ed25519"',
		);
		$this->assertSame( 'agent_123', AVA_Pay_Agent_Hint::extract( $headers ), 'unquoted form does not match, keyid wins' );

		$this->assertSame(
			'agent_123',
			AVA_Pay_Agent_Hint::extract(
				array(
					'signature-agent' => '"http://insecure.example"',
					'signature-input' => 'sig1=();keyid="agent_123"',
				)
			),
			'non-https origin rejected, keyid fallback'
		);
	}

	public function test_no_usable_headers_is_null(): void {
		$this->assertNull( AVA_Pay_Agent_Hint::extract( array() ) );
		$this->assertNull( AVA_Pay_Agent_Hint::extract( array( 'signature-input' => 'sig1=();alg="ed25519"' ) ) );
	}

	public function test_protocol_sniff_over_real_signed_fixture_headers(): void {
		$expected = array(
			'ava_tap_mandate_backed'          => 'ava-tap',
			'web_bot_auth_identity_only'      => 'web-bot-auth',
			'web_bot_auth_tampered_signature' => 'web-bot-auth',
			'no_credentials'                  => null,
			'ava_tap_directory_unavailable'   => 'ava-tap',
		);
		$data     = ava_pay_load_fixture( 'verify-fixtures.json' );
		$seen     = 0;
		foreach ( $data['fixtures'] as $f ) {
			if ( ! array_key_exists( $f['name'], $expected ) ) {
				continue;
			}
			++$seen;
			$this->assertSame(
				$expected[ $f['name'] ],
				AVA_Pay_Agent_Hint::sniff_protocol( $f['request']['headers'] ),
				$f['name']
			);
		}
		$this->assertSame( count( $expected ), $seen, 'every fixture was checked' );
	}

	public function test_protocol_sniff_rules(): void {
		$sig = array(
			'signature'       => ':abc:',
			'signature-input' => 'sig1=("@authority");keyid="k";alg="ed25519"',
		);

		$this->assertSame(
			'web-bot-auth',
			AVA_Pay_Agent_Hint::sniff_protocol(
				array_merge( $sig, array( 'signature-input' => 'sig1=("@authority");keyid="k";tag="web-bot-auth"' ) )
			),
			'tag wins'
		);
		$this->assertSame(
			'web-bot-auth',
			AVA_Pay_Agent_Hint::sniff_protocol( array_merge( $sig, array( 'signature-agent' => '"https://chatgpt.com"' ) ) ),
			'Signature-Agent present is enough'
		);
		$this->assertSame(
			'visa-tap',
			AVA_Pay_Agent_Hint::sniff_protocol(
				array_merge( $sig, array( 'signature-input' => 'sig1=("@authority");tag="agent-browser-auth"' ) )
			)
		);
		$this->assertSame(
			'visa-tap',
			AVA_Pay_Agent_Hint::sniff_protocol(
				array_merge( $sig, array( 'signature-input' => 'sig1=("@authority");tag="agent-payer-auth"' ) )
			)
		);
		$this->assertSame( 'ava-tap', AVA_Pay_Agent_Hint::sniff_protocol( $sig ), 'no tag, no Signature-Agent' );
		$this->assertSame(
			'ap2',
			AVA_Pay_Agent_Hint::sniff_protocol( array( 'ap2-checkout-mandate' => 'jws' ) )
		);
		$this->assertSame(
			'ap2',
			AVA_Pay_Agent_Hint::sniff_protocol( array( 'ap2-attestation' => 'jws' ) )
		);
	}

	public function test_protocol_sniff_is_null_when_it_cannot_say(): void {
		$this->assertNull( AVA_Pay_Agent_Hint::sniff_protocol( array() ) );
		$this->assertNull(
			AVA_Pay_Agent_Hint::sniff_protocol( array( 'signature-input' => 'sig1=("@authority")' ) ),
			'Signature-Input without Signature is not a signed request'
		);
		$this->assertNull(
			AVA_Pay_Agent_Hint::sniff_protocol( array( 'signature' => ':abc:' ) ),
			'Signature without Signature-Input is not a signed request'
		);
		$this->assertNull(
			AVA_Pay_Agent_Hint::sniff_protocol(
				array(
					'signature'            => ':abc:',
					'signature-input'      => 'sig1=("@authority");tag="web-bot-auth"',
					'ap2-checkout-mandate' => 'jws',
				)
			),
			'two protocols at once is ambiguous, and the verifier rejects it rather than picking one'
		);
	}

	public function test_tag_match_requires_a_parameter_boundary(): void {
		// Guards the [;\s] prefix in the port: a keyid that merely contains the
		// tag text must not be read as a tag.
		$this->assertSame(
			'ava-tap',
			AVA_Pay_Agent_Hint::sniff_protocol(
				array(
					'signature'       => ':abc:',
					'signature-input' => 'sig1=("@authority");keyid="not-a-tag="web-bot-auth""',
				)
			)
		);
	}
}
