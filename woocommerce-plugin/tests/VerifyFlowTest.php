<?php
/**
 * Round-trip tests over REAL cryptographic material: the fixtures in
 * verify-fixtures.json are requests signed with the SDK's actual signers
 * and verdicts emitted by the actual multi-protocol verifier
 * (scripts/generate-verify-fixtures.ts). Here they flow through the
 * plugin's full decision path — interpret_api_response → decide — exactly
 * as a live request would, asserting the event rows, storefront responses,
 * and coupon minting the REST controller will act on.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class VerifyFlowTest extends TestCase {

	/** @var array<string,array> */
	private static $fixtures;

	public static function setUpBeforeClass(): void {
		$data = ava_pay_load_fixture( 'verify-fixtures.json' );
		foreach ( $data['fixtures'] as $f ) {
			self::$fixtures[ $f['name'] ] = $f;
		}
	}

	private function settings( array $overrides = array() ): array {
		return array_merge(
			array(
				'acceptVerifiedAgents'    => true,
				'defaultDiscountPct'      => 10,
				'maxDiscountPct'          => 20,
				'identityOnlyDiscountPct' => 0,
				'policy'                  => null,
			),
			$overrides
		);
	}

	/** interpret + decide, the way AVA_Pay_Rest::handle_verify composes them. */
	private function run_fixture( string $name, array $settings ): array {
		$fixture = self::$fixtures[ $name ];
		$call    = AVA_Pay_Verify_Flow::interpret_api_response(
			$fixture['response']['status'],
			json_encode( $fixture['response']['body'] )
		);
		return AVA_Pay_Verify_Flow::decide( $settings, $call, $fixture['request']['headers'] );
	}

	public function test_mandate_backed_tap_request_is_admitted_with_default_discount(): void {
		$out = $this->run_fixture( 'ava_tap_mandate_backed', $this->settings() );

		$this->assertTrue( $out['response']['allow'] );
		$this->assertSame( 'verified', $out['response']['reason'] );
		$this->assertSame( 10, $out['mint_discount_pct'] );

		$this->assertSame( 'verified', $out['event']['outcome'] );
		$this->assertSame( 'ava-tap', $out['event']['protocol'] );
		$this->assertSame( 'agent_woo_fixture', $out['event']['platform'], 'TAP platform comes from the signed keyid' );
		$this->assertFalse( $out['event']['identity_only'] );
		$this->assertSame( 10, $out['event']['discount_pct'] );
	}

	public function test_identity_only_wba_request_is_admitted_with_zero_discount(): void {
		$out = $this->run_fixture( 'web_bot_auth_identity_only', $this->settings() );

		$this->assertTrue( $out['response']['allow'] );
		$this->assertSame( 0, $out['mint_discount_pct'], 'no coupon minted for identity-only traffic by default' );

		$this->assertSame( 'verified', $out['event']['outcome'] );
		$this->assertSame( 'web-bot-auth', $out['event']['protocol'] );
		$this->assertSame( 'https://agent-demo.ava.example', $out['event']['platform'], 'WBA platform is the verified agent identity' );
		$this->assertTrue( $out['event']['identity_only'] );
		$this->assertSame( 0, $out['event']['discount_pct'] );
	}

	public function test_identity_only_tier_opt_in_applies_to_real_wba_traffic(): void {
		$out = $this->run_fixture(
			'web_bot_auth_identity_only',
			$this->settings( array( 'identityOnlyDiscountPct' => 5 ) )
		);
		$this->assertTrue( $out['response']['allow'] );
		$this->assertSame( 5, $out['mint_discount_pct'] );
	}

	public function test_platform_offer_does_not_leak_onto_real_identity_only_traffic(): void {
		$parsed = AVA_Pay_Agent_Policy::parse(
			'{"version":1,"rules":[{"platform":"https://agent-demo.ava.example","action":"allow","offerDiscountPct":15}]}'
		);
		$this->assertTrue( $parsed['ok'] );
		$out = $this->run_fixture(
			'web_bot_auth_identity_only',
			$this->settings( array( 'policy' => $parsed['policy'] ) )
		);
		$this->assertTrue( $out['response']['allow'] );
		$this->assertSame( 0, $out['mint_discount_pct'], 'identity-only invariant holds against a real signed request' );
	}

	public function test_challenge_policy_rejects_real_identity_only_traffic(): void {
		$parsed = AVA_Pay_Agent_Policy::parse(
			'{"version":1,"rules":[{"platform":"https://agent-demo.ava.example","action":"challenge"}]}'
		);
		$this->assertTrue( $parsed['ok'] );
		$out = $this->run_fixture(
			'web_bot_auth_identity_only',
			$this->settings( array( 'policy' => $parsed['policy'] ) )
		);
		$this->assertFalse( $out['response']['allow'] );
		$this->assertSame( 'challenge_required', $out['response']['reason'] );
		$this->assertSame( 'policy_blocked', $out['event']['outcome'] );
		$this->assertTrue( $out['event']['identity_only'] );
	}

	public function test_tampered_signature_is_rejected_and_recorded_as_failed(): void {
		$out = $this->run_fixture( 'web_bot_auth_tampered_signature', $this->settings() );

		$this->assertFalse( $out['response']['allow'] );
		$this->assertSame( 'agent_blocked', $out['response']['reason'], 'external response carries no failure detail' );
		$this->assertSame( 0, $out['mint_discount_pct'] );

		$this->assertSame( 'failed', $out['event']['outcome'] );
		$this->assertSame( 'invalid_signature', $out['event']['reason'], 'typed reason recorded for the dashboard' );
		$this->assertSame( 'https://agent-demo.ava.example', $out['event']['platform'], 'failure attributed via Signature-Agent hint' );
	}

	public function test_credential_less_request_is_rejected(): void {
		$out = $this->run_fixture( 'no_credentials', $this->settings() );

		$this->assertFalse( $out['response']['allow'] );
		$this->assertSame( 'failed', $out['event']['outcome'] );
		$this->assertSame( 'missing_agent_credentials', $out['event']['reason'] );
		$this->assertNull( $out['event']['platform'] );
	}

	public function test_merchant_disabled_blocks_even_verified_traffic(): void {
		$out = $this->run_fixture(
			'ava_tap_mandate_backed',
			$this->settings( array( 'acceptVerifiedAgents' => false ) )
		);
		$this->assertFalse( $out['response']['allow'] );
		$this->assertSame( 'merchant_disabled', $out['response']['reason'] );
		$this->assertSame( 'policy_blocked', $out['event']['outcome'] );
	}

	public function test_api_unreachable_fails_closed_with_error_outcome(): void {
		$headers = self::$fixtures['web_bot_auth_identity_only']['request']['headers'];
		foreach ( array( 'timeout', 'network', 'bad_response' ) as $error ) {
			$out = AVA_Pay_Verify_Flow::decide(
				$this->settings(),
				array(
					'ok'    => false,
					'error' => $error,
				),
				$headers
			);
			$this->assertFalse( $out['response']['allow'] );
			$this->assertSame( "ava_{$error}", $out['response']['reason'] );
			$this->assertSame( 'error', $out['event']['outcome'] );
			$this->assertSame( "ava_{$error}", $out['event']['reason'] );
			$this->assertSame( 0, $out['mint_discount_pct'] );
			$this->assertSame(
				'https://agent-demo.ava.example',
				$out['event']['platform'],
				'error rows still get the best-effort platform hint'
			);
		}
	}

	public function test_interpret_api_response_maps_statuses_like_the_ts_client(): void {
		$ok = AVA_Pay_Verify_Flow::interpret_api_response( 200, '{"trusted":true,"ttlSeconds":60}' );
		$this->assertTrue( $ok['ok'] );

		$blocked = AVA_Pay_Verify_Flow::interpret_api_response( 403, '{"trusted":false,"reason":"unknown_agent","message":"m"}' );
		$this->assertTrue( $blocked['ok'], '403 carries a valid verification body' );

		$bad = AVA_Pay_Verify_Flow::interpret_api_response( 500, 'oops' );
		$this->assertFalse( $bad['ok'] );
		$this->assertSame( 'bad_response', $bad['error'] );
		$this->assertSame( 500, $bad['status'] );

		$garbled = AVA_Pay_Verify_Flow::interpret_api_response( 200, 'not-json' );
		$this->assertFalse( $garbled['ok'] );
		$this->assertSame( 'network', $garbled['error'], 'unparseable body maps like the TS res.json() throw' );
	}
}
