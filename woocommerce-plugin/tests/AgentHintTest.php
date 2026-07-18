<?php
/**
 * Agent-hint extraction parity with proxy.verify.tsx, including against the
 * real signed fixture headers.
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
}
