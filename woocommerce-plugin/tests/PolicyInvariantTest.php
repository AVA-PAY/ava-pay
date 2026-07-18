<?php
/**
 * Hand-written regression tests for the invariants the golden file could in
 * principle drift away from if the matrix were ever regenerated carelessly.
 * The identity-only invariant is non-negotiable (Nick, 2026-07-12): verified
 * traffic without a buyer mandate is admitted but receives NO discount
 * unless the merchant explicitly raised the identity-only tier — and
 * platform offers / verifier hints never leak onto it.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class PolicyInvariantTest extends TestCase {

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

	private function policy( string $json ): array {
		$parsed = AVA_Pay_Agent_Policy::parse( $json );
		$this->assertTrue( $parsed['ok'], isset( $parsed['error'] ) ? $parsed['error'] : '' );
		return $parsed['policy'];
	}

	private const IDENTITY_ONLY = array(
		'trusted'    => true,
		'ttlSeconds' => 300,
	);

	private const MANDATE_BACKED = array(
		'trusted'    => true,
		'mandate'    => array(
			'id'             => 'm1',
			'iat'            => 1,
			'exp'            => 2,
			'maxAmountMinor' => 50000,
			'currency'       => 'USD',
			'allowedMerchants' => array( 'demo-store.example' ),
		),
		'ttlSeconds' => 300,
	);

	public function test_identity_only_admitted_with_zero_discount_by_default(): void {
		$d = AVA_Pay_Policy::apply_merchant_policy( $this->settings(), self::IDENTITY_ONLY );
		$this->assertTrue( $d['allow'] );
		$this->assertSame( 0, $d['discountPct'] );
	}

	public function test_identity_only_ignores_verifier_discount_hint(): void {
		$result = self::IDENTITY_ONLY + array( 'discount' => 0.15 );
		$d      = AVA_Pay_Policy::apply_merchant_policy( $this->settings(), $result );
		$this->assertTrue( $d['allow'] );
		$this->assertSame( 0, $d['discountPct'], 'verifier hint must never apply without a mandate' );
	}

	public function test_platform_offer_never_leaks_onto_identity_only_traffic(): void {
		$settings = $this->settings(
			array(
				'policy' => $this->policy(
					'{"version":1,"rules":[{"platform":"https://chatgpt.com","action":"allow","offerDiscountPct":15}]}'
				),
			)
		);
		$d = AVA_Pay_Policy::apply_merchant_policy( $settings, self::IDENTITY_ONLY, 'https://chatgpt.com' );
		$this->assertTrue( $d['allow'] );
		$this->assertSame( 0, $d['discountPct'], 'offerDiscountPct is a mandate-backed grant only' );

		$mandated = AVA_Pay_Policy::apply_merchant_policy( $settings, self::MANDATE_BACKED, 'https://chatgpt.com' );
		$this->assertSame( 15, $mandated['discountPct'], 'same offer DOES apply once a mandate is present' );
	}

	public function test_identity_tier_is_explicit_opt_in_and_capped(): void {
		$d = AVA_Pay_Policy::apply_merchant_policy(
			$this->settings( array( 'identityOnlyDiscountPct' => 5 ) ),
			self::IDENTITY_ONLY
		);
		$this->assertSame( 5, $d['discountPct'] );

		$capped = AVA_Pay_Policy::apply_merchant_policy(
			$this->settings(
				array(
					'identityOnlyDiscountPct' => 30,
					'maxDiscountPct'          => 20,
				)
			),
			self::IDENTITY_ONLY
		);
		$this->assertSame( 20, $capped['discountPct'], 'identity tier is still bounded by the global cap' );
	}

	public function test_challenge_rejects_identity_only_and_admits_mandate_backed(): void {
		$settings = $this->settings(
			array( 'policy' => $this->policy( '{"version":1,"rules":[{"platform":"https://chatgpt.com","action":"challenge"}]}' ) )
		);
		$rejected = AVA_Pay_Policy::apply_merchant_policy( $settings, self::IDENTITY_ONLY, 'https://chatgpt.com' );
		$this->assertFalse( $rejected['allow'] );
		$this->assertSame( 'challenge_required', $rejected['reason'] );

		$admitted = AVA_Pay_Policy::apply_merchant_policy( $settings, self::MANDATE_BACKED, 'https://chatgpt.com' );
		$this->assertTrue( $admitted['allow'] );
	}

	public function test_unknown_platform_gets_most_restrictive_synthesis(): void {
		$settings = $this->settings(
			array(
				'policy' => $this->policy(
					'{"version":1,"rules":['
					. '{"platform":"https://chatgpt.com","action":"allow","maxDiscountPct":5},'
					. '{"platform":"https://agents.visa.com","action":"block"}]}'
				),
			)
		);
		$d = AVA_Pay_Policy::apply_merchant_policy( $settings, self::MANDATE_BACKED, 'https://unknown.example' );
		$this->assertFalse( $d['allow'] );
		$this->assertSame( 'blocked_by_policy', $d['reason'], 'unknown platforms inherit the harshest action' );
	}

	public function test_spend_rule_rejects_oversized_mandates(): void {
		$settings = $this->settings(
			array( 'policy' => $this->policy( '{"version":1,"rules":[{"platform":"https://chatgpt.com","action":"allow","maxSpendMinor":40000}]}' ) )
		);
		$d = AVA_Pay_Policy::apply_merchant_policy( $settings, self::MANDATE_BACKED, 'https://chatgpt.com' );
		$this->assertFalse( $d['allow'] );
		$this->assertSame( 'spend_limit_exceeded', $d['reason'] );
	}

	public function test_merchant_disabled_rejects_everything(): void {
		$d = AVA_Pay_Policy::apply_merchant_policy(
			$this->settings( array( 'acceptVerifiedAgents' => false ) ),
			self::MANDATE_BACKED
		);
		$this->assertFalse( $d['allow'] );
		$this->assertSame( 'merchant_disabled', $d['reason'] );
	}

	public function test_clamp_pct(): void {
		$this->assertSame( 0, AVA_Pay_Policy::clamp_pct( 'abc' ) );
		$this->assertSame( 0, AVA_Pay_Policy::clamp_pct( -5 ) );
		$this->assertSame( 100, AVA_Pay_Policy::clamp_pct( 150 ) );
		$this->assertSame( 13, AVA_Pay_Policy::clamp_pct( '12.6' ) );
		$this->assertSame( 0, AVA_Pay_Policy::clamp_pct( NAN ) );
		$this->assertSame( 0, AVA_Pay_Policy::clamp_pct( INF ) );
		$this->assertSame( 12, AVA_Pay_Policy::clamp_pct( 12 ) );
	}
}
