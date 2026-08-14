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

	/**
	 * decide() over a hand-built verdict body, carrying real signed headers so
	 * platform and protocol hints behave as they would live. Used for verdict
	 * shapes the generator cannot mint on demand: reasons from other protocols'
	 * could-not-check paths, and older API builds that predate `conclusive`.
	 */
	private function decide_body( array $body, ?array $settings = null ): array {
		return AVA_Pay_Verify_Flow::decide(
			null === $settings ? $this->settings() : $settings,
			array(
				'ok'     => true,
				'result' => $body,
			),
			self::$fixtures['web_bot_auth_tampered_signature']['request']['headers']
		);
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

		$this->assertSame( 'failed', $out['event']['outcome'], 'a conclusive rejection is a real block, not an unverifiable' );
		$this->assertSame( 'invalid_signature', $out['event']['reason'], 'typed reason recorded for the dashboard' );
		$this->assertSame( 'https://agent-demo.ava.example', $out['event']['platform'], 'failure attributed via Signature-Agent hint' );
		$this->assertSame( 'web-bot-auth', $out['event']['protocol'], 'rejected rows record the protocol the request attempted' );
	}

	/**
	 * The one that matters. A verdict the verifier could not complete must fail
	 * closed AND must not be reported as a blocked agent: we did not block this
	 * agent, we never managed to check it. Anchored to a real verdict the
	 * production verifier emitted for a cryptographically valid request against
	 * a directory backend that throws.
	 */
	public function test_could_not_check_fails_closed_and_is_not_reported_as_blocked(): void {
		$out = $this->run_fixture( 'ava_tap_directory_unavailable', $this->settings() );

		$this->assertFalse( $out['response']['allow'], 'fail-closed behaviour is unchanged' );
		$this->assertSame( 0, $out['mint_discount_pct'] );

		$this->assertNotSame(
			'agent_blocked',
			$out['response']['reason'],
			'the plugin must not claim it blocked an agent it never checked'
		);
		$this->assertSame( 'verification_unavailable', $out['response']['reason'] );

		$this->assertSame( 'unverifiable', $out['event']['outcome'] );
		$this->assertNotSame( 'failed', $out['event']['outcome'], 'could-not-check must not be counted as a rejection' );
		$this->assertSame( 'directory_unavailable', $out['event']['reason'], 'typed API reason kept for diagnosis' );
		$this->assertSame( 'ava-tap', $out['event']['protocol'], 'unverifiable rows still say what was attempted' );
		$this->assertSame( 'agent_woo_fixture', $out['event']['platform'] );
	}

	/**
	 * The fixture above covers directory_unavailable. Web Bot Auth and the Visa
	 * JWKS path report the same could-not-check condition under the older name
	 * key_directory_unavailable, so the split must key on `conclusive`, never on
	 * a list of reason strings.
	 */
	public function test_conclusive_flag_not_the_reason_string_drives_the_split(): void {
		$cases = array(
			// [reason, conclusive, expected outcome, expected storefront reason]
			array( 'key_directory_unavailable', false, 'unverifiable', 'verification_unavailable' ),
			array( 'directory_unavailable', false, 'unverifiable', 'verification_unavailable' ),
			array( 'unknown_agent', true, 'failed', 'agent_blocked' ),
			array( 'unsigned_key', true, 'failed', 'agent_blocked' ),
			array( 'key_proof_invalid', true, 'failed', 'agent_blocked' ),
		);

		foreach ( $cases as list( $reason, $conclusive, $outcome, $response_reason ) ) {
			$out = $this->decide_body(
				array(
					'trusted'    => false,
					'reason'     => $reason,
					'message'    => 'm',
					'conclusive' => $conclusive,
				)
			);
			$this->assertFalse( $out['response']['allow'], "{$reason} still fails closed" );
			$this->assertSame( $outcome, $out['event']['outcome'], "outcome for {$reason}" );
			$this->assertSame( $response_reason, $out['response']['reason'], "storefront reason for {$reason}" );
			$this->assertSame( $reason, $out['event']['reason'] );
		}
	}

	/**
	 * Forward compatibility, matching the API's own rule: `conclusive` is an
	 * additive field, so a verdict without it (an older API build, or a cached
	 * response minted before the field existed) means "we checked", not "we
	 * could not check". Getting this backwards would relabel every ordinary
	 * rejection as unverifiable.
	 */
	public function test_absent_or_malformed_conclusive_reads_as_conclusive(): void {
		$bodies = array(
			'absent'      => array(
				'trusted' => false,
				'reason'  => 'unknown_agent',
				'message' => 'm',
			),
			'null'        => array(
				'trusted'    => false,
				'reason'     => 'unknown_agent',
				'message'    => 'm',
				'conclusive' => null,
			),
			'string false' => array(
				'trusted'    => false,
				'reason'     => 'unknown_agent',
				'message'    => 'm',
				'conclusive' => 'false',
			),
		);

		foreach ( $bodies as $label => $body ) {
			$this->assertTrue( AVA_Pay_Verify_Flow::is_conclusive( $body ), "is_conclusive({$label})" );
			$out = $this->decide_body( $body );
			$this->assertSame( 'failed', $out['event']['outcome'], "outcome with conclusive {$label}" );
			$this->assertSame( 'agent_blocked', $out['response']['reason'], "storefront reason with conclusive {$label}" );
			$this->assertFalse( $out['response']['allow'] );
		}
	}

	/**
	 * A coupon that cannot be minted must not demote a verified agent to a
	 * failure. Mirrors the compose block in AVA_Pay_Rest::verify(), where
	 * AVA_Pay_Coupons::mint() returns null (WooCommerce unavailable, a
	 * conflicting plugin's filter throwing, save() returning 0) rather than
	 * throwing: the verdict stands, the response simply carries no discount.
	 */
	public function test_perk_failure_does_not_turn_a_verified_agent_into_a_failed_one(): void {
		$out      = $this->run_fixture( 'ava_tap_mandate_backed', $this->settings() );
		$event    = $out['event'];
		$response = $out['response'];

		$this->assertTrue( $response['allow'] );
		$this->assertSame( 10, $out['mint_discount_pct'] );

		// The controller's minting block, with mint() returning null.
		$coupon = null;
		if ( $response['allow'] && $out['mint_discount_pct'] > 0 && null !== $coupon ) {
			$event['discount_code'] = $coupon['code'];
			$response['discount']   = $coupon;
		}

		$this->assertTrue( $response['allow'], 'a missing coupon does not withdraw the verification' );
		$this->assertSame( 'verified', $response['reason'] );
		$this->assertArrayNotHasKey( 'discount', $response, 'no coupon means no discount in the response' );
		$this->assertSame( 'verified', $event['outcome'] );
		$this->assertArrayNotHasKey( 'discount_code', $event );
		$this->assertSame( 10, $event['discount_pct'], 'the granted percentage is still what policy decided' );
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
			$this->assertSame(
				'web-bot-auth',
				$out['event']['protocol'],
				'error rows record the protocol the request attempted'
			);
		}
	}

	public function test_sensitive_headers_are_stripped_before_forwarding(): void {
		// Regression (ultrareview PR #9): WP REST hands the plugin cookies and
		// authorization along with the agent's signed headers; they must never
		// reach the external API.
		$headers = array(
			'signature'       => 'sig',
			'signature-input' => 'sig1=…',
			'cookie'          => 'wordpress_logged_in_abc=admin%7C…; wp_woocommerce_session_x=y',
			'authorization'   => 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==',
			'x-wp-nonce'      => 'deadbeef',
			'x-ava-mandate'   => 'kept',
		);
		$stripped = AVA_Pay_Verify_Flow::strip_sensitive_headers( $headers );
		$this->assertArrayNotHasKey( 'cookie', $stripped );
		$this->assertArrayNotHasKey( 'authorization', $stripped );
		$this->assertArrayNotHasKey( 'x-wp-nonce', $stripped );
		$this->assertSame( 'sig', $stripped['signature'] );
		$this->assertSame( 'kept', $stripped['x-ava-mandate'], 'agent material passes through untouched' );
	}

	public function test_signed_url_problems_flags_unusable_site_configs(): void {
		$this->assertSame(
			array(),
			AVA_Pay_Verify_Flow::signed_url_problems( 'https://demo-store.example/wp-json/ava-pay/v1/verify-agent' )
		);
		$this->assertSame(
			array( 'plain_permalinks' ),
			AVA_Pay_Verify_Flow::signed_url_problems( 'https://demo-store.example/index.php?rest_route=/ava-pay/v1/verify-agent' )
		);
		$this->assertSame(
			array( 'not_https' ),
			AVA_Pay_Verify_Flow::signed_url_problems( 'http://demo-store.example/wp-json/ava-pay/v1/verify-agent' )
		);
		$this->assertSame(
			array( 'plain_permalinks', 'not_https' ),
			AVA_Pay_Verify_Flow::signed_url_problems( 'http://demo-store.example/?rest_route=/ava-pay/v1/verify-agent' )
		);
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
