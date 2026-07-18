<?php
/**
 * Agent platform policy — the merchant's rules layer.
 *
 * Faithful PHP port of shopify-app/app/lib/agent-policy.ts. The decision
 * semantics of the two implementations MUST stay identical; the golden-file
 * test (tests/PolicyGoldenTest.php) replays cases generated from the
 * TypeScript implementation to enforce this mechanically. If you change
 * behavior here, change the TS first and regenerate the golden file.
 *
 * A policy is a versioned, JSON-portable document: per-platform
 * allow/challenge/block, discount caps, spend rules, and agent-only offers.
 * Everything here is pure (no WordPress, no I/O) so enforcement is
 * unit-testable.
 *
 * Fail-closed contract:
 *   - No policy configured (null)  → legacy behavior, unchanged.
 *   - Platform with no matching rule → the explicit defaultRule if present,
 *     otherwise the MOST RESTRICTIVE synthesis of the listed rules
 *     (harshest action, lowest caps). Unknown platforms never get a better
 *     deal than any known one.
 *   - A policy with no rules and no defaultRule is rejected at parse time.
 *
 * Identity-only invariant (non-negotiable, decided by Nick 2026-07-12):
 *   traffic verified without a buyer mandate is admitted but receives NO
 *   discount unless the merchant raised the identity-only tier. Platform
 *   offers (offerDiscountPct) apply to mandate-backed traffic only and can
 *   never leak onto identity-only requests.
 *
 * Validation operates on the raw json_decode() graph (stdClass objects, not
 * assoc arrays) so that "must be an object, not an array" checks mirror the
 * TypeScript Array.isArray() distinctions exactly. Validated policies are
 * returned as plain associative arrays.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) && ! defined( 'AVA_PAY_TESTS' ) ) {
	exit;
}

class AVA_Pay_Agent_Policy {

	const ACTIONS = array( 'allow', 'challenge', 'block' );

	/** Restrictiveness order for the unknown-platform synthesis. */
	const ACTION_RANK = array(
		'allow'     => 0,
		'challenge' => 1,
		'block'     => 2,
	);

	/**
	 * JSON numbers arrive as int or float; JavaScript's Number.isInteger()
	 * accepts both 5 and 5.0. Match that (and reject bool/string/NaN/Inf).
	 *
	 * @param mixed $v Candidate value.
	 */
	private static function is_integer_number( $v ) {
		if ( is_int( $v ) ) {
			return true;
		}
		return is_float( $v ) && is_finite( $v ) && floor( $v ) === $v;
	}

	/**
	 * Port of validateRuleBody(). Returns the normalized rule body (assoc
	 * array) or an error string.
	 *
	 * @param mixed  $rule  Raw decoded rule.
	 * @param string $label Error label ("rules[0]", "defaultRule").
	 * @return array|string
	 */
	private static function validate_rule_body( $rule, $label ) {
		if ( ! $rule instanceof stdClass ) {
			return "{$label} must be an object";
		}
		$action = isset( $rule->action ) ? $rule->action : null;
		if ( ! in_array( $action, self::ACTIONS, true ) ) {
			return "{$label}: action must be one of " . implode( ', ', self::ACTIONS );
		}
		foreach ( array( 'maxDiscountPct', 'offerDiscountPct' ) as $key ) {
			if ( ! property_exists( $rule, $key ) ) {
				continue;
			}
			$v = $rule->{$key};
			if ( ! self::is_integer_number( $v ) || $v < 0 || $v > 100 ) {
				return "{$label}: {$key} must be an integer 0–100";
			}
		}
		if ( property_exists( $rule, 'maxSpendMinor' ) ) {
			$v = $rule->maxSpendMinor;
			if ( ! self::is_integer_number( $v ) || $v < 0 ) {
				return "{$label}: maxSpendMinor must be a non-negative integer (minor units)";
			}
		}

		$body = array( 'action' => $action );
		if ( property_exists( $rule, 'maxDiscountPct' ) ) {
			$body['maxDiscountPct'] = (int) $rule->maxDiscountPct;
		}
		if ( property_exists( $rule, 'maxSpendMinor' ) ) {
			$body['maxSpendMinor'] = (int) $rule->maxSpendMinor;
		}
		if ( property_exists( $rule, 'offerDiscountPct' ) ) {
			$body['offerDiscountPct'] = (int) $rule->offerDiscountPct;
		}
		return $body;
	}

	/**
	 * Strict validation — imports reject rather than silently repair.
	 * Port of parseAgentPolicy().
	 *
	 * @param string $json Raw JSON text.
	 * @return array {ok: true, policy: array} | {ok: false, error: string}
	 */
	public static function parse( $json ) {
		$raw = json_decode( $json );
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			return array(
				'ok'    => false,
				'error' => 'Not valid JSON.',
			);
		}
		return self::validate( $raw );
	}

	/**
	 * Port of validateAgentPolicy(). $raw is the json_decode() (non-assoc)
	 * graph.
	 *
	 * @param mixed $raw Decoded JSON value.
	 * @return array {ok: true, policy: array} | {ok: false, error: string}
	 */
	public static function validate( $raw ) {
		if ( ! $raw instanceof stdClass ) {
			return array(
				'ok'    => false,
				'error' => 'Policy must be a JSON object.',
			);
		}
		$version = isset( $raw->version ) ? $raw->version : null;
		if ( ! self::is_integer_number( $version ) || (int) $version !== 1 ) {
			return array(
				'ok'    => false,
				'error' => 'Unsupported policy version (expected version: 1).',
			);
		}
		if ( ! isset( $raw->rules ) || ! is_array( $raw->rules ) ) {
			return array(
				'ok'    => false,
				'error' => 'rules must be an array.',
			);
		}

		$rules = array();
		$seen  = array();
		foreach ( array_values( $raw->rules ) as $i => $entry ) {
			$label = "rules[{$i}]";
			if ( ! $entry instanceof stdClass ) {
				return array(
					'ok'    => false,
					'error' => "{$label} must be an object",
				);
			}
			$platform_raw = isset( $entry->platform ) ? $entry->platform : null;
			if ( ! is_string( $platform_raw ) || trim( $platform_raw ) === '' ) {
				return array(
					'ok'    => false,
					'error' => "{$label}: platform must be a non-empty string",
				);
			}
			$platform = trim( $platform_raw );
			$key      = strtolower( $platform );
			if ( isset( $seen[ $key ] ) ) {
				return array(
					'ok'    => false,
					'error' => "{$label}: duplicate platform \"{$platform}\"",
				);
			}
			$seen[ $key ] = true;
			$body         = self::validate_rule_body( $entry, $label );
			if ( is_string( $body ) ) {
				return array(
					'ok'    => false,
					'error' => $body,
				);
			}
			$rules[] = array_merge( array( 'platform' => $platform ), $body );
		}

		$default_rule = null;
		if ( property_exists( $raw, 'defaultRule' ) ) {
			$body = self::validate_rule_body( $raw->defaultRule, 'defaultRule' );
			if ( is_string( $body ) ) {
				return array(
					'ok'    => false,
					'error' => $body,
				);
			}
			$default_rule = $body;
		}

		if ( count( $rules ) === 0 && null === $default_rule ) {
			return array(
				'ok'    => false,
				'error' => 'Policy must contain at least one rule or a defaultRule (an empty policy has no defined behavior).',
			);
		}

		$policy = array(
			'version' => 1,
			'rules'   => $rules,
		);
		if ( null !== $default_rule ) {
			$policy['defaultRule'] = $default_rule;
		}
		return array(
			'ok'     => true,
			'policy' => $policy,
		);
	}

	/**
	 * Most-restrictive synthesis for platforms no rule names: harshest action
	 * of any listed rule, lowest defined caps. Offers are per-platform grants
	 * and are never inherited. Port of mostRestrictiveRule().
	 *
	 * @param array $policy Validated policy.
	 * @return array Rule body.
	 */
	public static function most_restrictive_rule( array $policy ) {
		$sources = count( $policy['rules'] ) > 0 ? $policy['rules'] : array( $policy['defaultRule'] );
		$out     = array( 'action' => 'allow' );
		foreach ( $sources as $r ) {
			if ( self::ACTION_RANK[ $r['action'] ] > self::ACTION_RANK[ $out['action'] ] ) {
				$out['action'] = $r['action'];
			}
			if ( isset( $r['maxDiscountPct'] ) ) {
				$out['maxDiscountPct'] = isset( $out['maxDiscountPct'] )
					? min( $out['maxDiscountPct'], $r['maxDiscountPct'] )
					: $r['maxDiscountPct'];
			}
			if ( isset( $r['maxSpendMinor'] ) ) {
				$out['maxSpendMinor'] = isset( $out['maxSpendMinor'] )
					? min( $out['maxSpendMinor'], $r['maxSpendMinor'] )
					: $r['maxSpendMinor'];
			}
		}
		return $out;
	}

	/**
	 * Rule for a given platform: exact match → explicit default →
	 * most-restrictive synthesis. Port of resolveRule().
	 *
	 * @param array       $policy   Validated policy.
	 * @param string|null $platform Platform identity.
	 * @return array Rule body (platform rules include their 'platform' key).
	 */
	public static function resolve_rule( array $policy, $platform ) {
		if ( null !== $platform && '' !== $platform ) {
			$key = strtolower( $platform );
			foreach ( $policy['rules'] as $rule ) {
				if ( strtolower( $rule['platform'] ) === $key ) {
					return $rule;
				}
			}
		}
		if ( isset( $policy['defaultRule'] ) ) {
			return $policy['defaultRule'];
		}
		return self::most_restrictive_rule( $policy );
	}

	/**
	 * Port of serializeAgentPolicy() — pretty JSON for export.
	 *
	 * @param array $policy Validated policy.
	 */
	public static function serialize( array $policy ) {
		return json_encode( $policy, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	}
}
