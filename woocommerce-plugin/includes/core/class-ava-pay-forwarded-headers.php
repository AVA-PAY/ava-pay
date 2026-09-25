<?php
/**
 * What leaves the site: the header set forwarded to AVA Pay /verify.
 *
 * PHP twin of shopify-app/app/lib/forwarded-headers.ts, held to it by the
 * golden cases in tests/fixtures/forwarding-golden.json (generated from the
 * TypeScript by scripts/generate-forwarding-golden.ts). The REST endpoint
 * sees every header the storefront request carried: the visitor's IP, user
 * agent, language, cookies. The verifier needs almost none of it, so
 * AVA_Pay_Api_Client::verify() sends only:
 *
 *   (a) signature, signature-input, signature-agent;
 *   (b) every HTTP field the incoming Signature-Input names as a covered
 *       component, in any member (lower-cased, component parameters such as
 *       ;key= or ;req dropped, derived @components skipped since they are not
 *       headers);
 *   (c) the protocol headers the verifier reads by name without their being
 *       components: PROTOCOL_HEADERS always, BODY_HEADERS when a body travels;
 *   (d) host, which the REST layer has already rebuilt from rest_url().
 *
 * NEVER_FORWARD is applied last and wins over all of the above, coverage
 * included: credentials never leave the site.
 *
 * If Signature-Input is absent or unreadable, (b) is empty and the verifier
 * still gets (a), (c) and (d), enough to return its honest reason.
 *
 * Minimizing is a statement about what we send, not what we read: the REST
 * layer keeps the full map for its own use (the request hints).
 *
 * The Signature-Input reader below is a port of the SDK's
 * parseSignatureInput (packages/agent-sdk/src/protocol/visa/http-signatures.ts),
 * which the TypeScript twin calls directly: "readable" has to mean what it
 * means to the verifier, so this follows that parser rule for rule rather
 * than being a stricter or looser Structured Fields reader of its own.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Forwarded_Headers {

	/** (a) The signature itself. */
	const SIGNATURE_HEADERS = array( 'signature', 'signature-input', 'signature-agent' );

	/**
	 * (c) Headers the API reads by name whether or not the signature covers
	 * them: the AVA TAP profile's mandate and discount hint, the AP2 v0.2
	 * mandate chains, AP2 v0.1's attestation (read only to answer
	 * unsupported_protocol_version), and content-digest, which the verifier
	 * checks against the body and against the empty body when none arrives.
	 */
	const PROTOCOL_HEADERS = array(
		'x-ava-mandate',
		'x-ava-discount-hint',
		'ap2-checkout-mandate',
		'ap2-payment-mandate',
		'ap2-attestation',
		'content-digest',
	);

	/** (c) Forwarded only alongside a body. */
	const BODY_HEADERS = array( 'content-type' );

	/**
	 * Credentials, never forwarded, even when a Signature-Input names them as
	 * covered. An agent that covers the shopper's cookies is misconfigured or
	 * hostile; its request fails at the API with the covered component
	 * missing, which is the intended outcome. The REST handler's
	 * strip_sensitive_headers() also drops these, but this client-side choke
	 * point does not rely on its caller for that.
	 */
	const NEVER_FORWARD = array( 'cookie', 'authorization', 'proxy-authorization', 'x-wp-nonce' );

	/** What JavaScript's String.prototype.trim removes, in the ASCII range. */
	const JS_WHITESPACE = " \t\n\r\x0B\x0C";

	/**
	 * The IncomingRequest as it should leave the site: same method, url and
	 * body, minimized headers.
	 *
	 * @param array $incoming IncomingRequest {method, url, headers, body?}.
	 * @return array
	 */
	public static function outbound_request( array $incoming ) {
		$headers  = isset( $incoming['headers'] ) && is_array( $incoming['headers'] ) ? $incoming['headers'] : array();
		$has_body = isset( $incoming['body'] ) && is_string( $incoming['body'] ) && '' !== $incoming['body'];

		$incoming['headers'] = self::minimize( $headers, $has_body );
		return $incoming;
	}

	/**
	 * The headers to forward. Names come out lower-cased, which is how the
	 * API indexes them. `host` must already be the rebuilt value.
	 *
	 * @param array $headers  Header map.
	 * @param bool  $has_body Whether a non-empty body travels with them.
	 * @return array<string,string>
	 */
	public static function minimize( array $headers, $has_body ) {
		$lower = array();
		foreach ( $headers as $name => $value ) {
			$lower[ strtolower( (string) $name ) ] = $value;
		}

		$keep = array_merge( self::SIGNATURE_HEADERS, self::PROTOCOL_HEADERS, array( 'host' ) );
		if ( $has_body ) {
			$keep = array_merge( $keep, self::BODY_HEADERS );
		}
		$covered = self::covered_header_fields(
			isset( $lower['signature-input'] ) && is_string( $lower['signature-input'] ) ? $lower['signature-input'] : null
		);
		if ( null !== $covered ) {
			$keep = array_merge( $keep, $covered );
		}
		$keep = array_diff( $keep, self::NEVER_FORWARD );
		$keep = array_flip( $keep );

		$out = array();
		foreach ( $lower as $name => $value ) {
			if ( isset( $keep[ $name ] ) ) {
				$out[ $name ] = $value;
			}
		}
		return $out;
	}

	/**
	 * The HTTP field names Signature-Input covers across all its members, in
	 * first-appearance order, or null when the field is unreadable.
	 *
	 * @param string|null $signature_input Raw Signature-Input value.
	 * @return string[]|null
	 */
	public static function covered_header_fields( $signature_input ) {
		if ( null === $signature_input ) {
			return null;
		}
		$members = self::split_dictionary_members( $signature_input );
		if ( null === $members ) {
			return null;
		}

		$fields = array();
		foreach ( $members as $member ) {
			if ( '' === $member ) {
				return null;
			}
			$names = self::parse_member_components( $member );
			if ( null === $names ) {
				return null;
			}
			foreach ( $names as $name ) {
				if ( '@' === substr( $name, 0, 1 ) ) {
					continue;
				}
				$field = strtolower( $name );
				if ( ! in_array( $field, $fields, true ) ) {
					$fields[] = $field;
				}
			}
		}
		return $fields;
	}

	/**
	 * Split a Structured Fields Dictionary into its member texts at top-level
	 * commas. Commas inside a String (with its backslash escapes) or an Inner
	 * List do not split. Null for unbalanced parentheses or an unterminated
	 * string.
	 *
	 * @param string $value Field value.
	 * @return string[]|null
	 */
	public static function split_dictionary_members( $value ) {
		$members   = array();
		$depth     = 0;
		$in_string = false;
		$start     = 0;
		$len       = strlen( $value );
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $value[ $i ];
			if ( $in_string ) {
				if ( '\\' === $c ) {
					++$i;
				} elseif ( '"' === $c ) {
					$in_string = false;
				}
				continue;
			}
			if ( '"' === $c ) {
				$in_string = true;
			} elseif ( '(' === $c ) {
				++$depth;
			} elseif ( ')' === $c ) {
				--$depth;
				if ( $depth < 0 ) {
					return null;
				}
			} elseif ( ',' === $c && 0 === $depth ) {
				$members[] = substr( $value, $start, $i - $start );
				$start     = $i + 1;
			}
		}
		if ( $in_string || 0 !== $depth ) {
			return null;
		}
		$members[] = substr( $value, $start );
		return array_map(
			static function ( $m ) {
				return trim( $m, self::JS_WHITESPACE );
			},
			$members
		);
	}

	/**
	 * Covered component names of ONE Signature-Input member, or null where
	 * the SDK's parseSignatureInput would throw.
	 *
	 * @param string $header_value One dictionary member.
	 * @return string[]|null
	 */
	private static function parse_member_components( $header_value ) {
		$value = trim( $header_value, self::JS_WHITESPACE );
		if ( self::has_top_level_comma( $value ) ) {
			return null;
		}

		$eq = strpos( $value, '=' );
		if ( false === $eq ) {
			return null;
		}
		$rest = trim( substr( $value, $eq + 1 ), self::JS_WHITESPACE );
		if ( '(' !== substr( $rest, 0, 1 ) ) {
			return null;
		}
		$close = strpos( $rest, ')' );
		if ( false === $close ) {
			return null;
		}
		$components_raw = trim( substr( $rest, 1, $close - 1 ), self::JS_WHITESPACE );
		$params_raw     = substr( $rest, $close + 1 );

		// Same expression as the SDK: a quoted name plus its parameters, so a
		// key="sig1" parameter is never read as a component of its own.
		$re = '/"([^"]*)"((?:;[A-Za-z0-9_-]+(?:=(?:"[^"]*"|[^;"\s)]*))?)*)/';
		preg_match_all( $re, $components_raw, $matches, PREG_SET_ORDER );

		$names    = array();
		$seen     = array();
		$consumed = 0;
		foreach ( $matches as $m ) {
			$name = $m[1];
			if ( '' === $name ) {
				return null;
			}
			$params     = isset( $m[2] ) ? $m[2] : '';
			$identifier = '"' . $name . '"' . $params;
			if ( isset( $seen[ $identifier ] ) ) {
				return null;
			}
			$seen[ $identifier ] = true;
			$names[]             = $name;
			$consumed           += strlen( $m[0] );
		}
		if ( array() === $names ) {
			return null;
		}
		if ( strlen( (string) preg_replace( '/\s+/', '', $components_raw ) ) !== $consumed ) {
			return null;
		}

		$params_trimmed = trim( $params_raw, self::JS_WHITESPACE );
		if ( ';' === substr( $params_trimmed, 0, 1 ) ) {
			foreach ( explode( ';', substr( $params_trimmed, 1 ) ) as $seg ) {
				$idx = strpos( $seg, '=' );
				if ( false === $idx ) {
					continue;
				}
				$param = trim( substr( $seg, 0, $idx ), self::JS_WHITESPACE );
				$raw   = trim( substr( $seg, $idx + 1 ), self::JS_WHITESPACE );
				if ( strlen( $raw ) >= 1 && '"' === $raw[0] && '"' === substr( $raw, -1 ) ) {
					$raw = (string) substr( $raw, 1, -1 );
				}
				if ( ( 'created' === $param || 'expires' === $param ) && ! self::js_number_is_finite( $raw ) ) {
					return null;
				}
			}
		}

		return $names;
	}

	/**
	 * The SDK's rejectIfMultiDictionary: a comma outside parentheses and
	 * quotes. Its quote tracking ignores backslash escapes, and so does this.
	 *
	 * @param string $value Member text.
	 * @return bool
	 */
	private static function has_top_level_comma( $value ) {
		$depth     = 0;
		$in_string = false;
		$len       = strlen( $value );
		for ( $i = 0; $i < $len; $i++ ) {
			$c = $value[ $i ];
			if ( '"' === $c ) {
				$in_string = ! $in_string;
			} elseif ( ! $in_string && '(' === $c ) {
				++$depth;
			} elseif ( ! $in_string && ')' === $c ) {
				--$depth;
			} elseif ( ! $in_string && 0 === $depth && ',' === $c ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Number.isFinite(Number(raw)), for the created/expires check the SDK
	 * parser makes.
	 *
	 * @param string $raw Parameter text.
	 * @return bool
	 */
	private static function js_number_is_finite( $raw ) {
		$s = trim( $raw, self::JS_WHITESPACE );
		if ( '' === $s ) {
			return true;
		}
		if ( preg_match( '/^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/', $s ) ) {
			return is_finite( (float) $s );
		}
		if ( preg_match( '/^0[xX]([0-9a-fA-F]+)$/', $s, $m ) ) {
			return is_finite( (float) hexdec( $m[1] ) );
		}
		if ( preg_match( '/^0[oO]([0-7]+)$/', $s, $m ) ) {
			return is_finite( (float) octdec( $m[1] ) );
		}
		if ( preg_match( '/^0[bB]([01]+)$/', $s, $m ) ) {
			return is_finite( (float) bindec( $m[1] ) );
		}
		return false;
	}
}
