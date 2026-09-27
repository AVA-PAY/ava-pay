<?php
/**
 * Signed agent page visits: observe, never act.
 *
 * When a front-end page request carries HTTP Message Signature headers, the
 * WordPress layer (AVA_Pay_Page_Visits) hands this class the request as PHP
 * saw it and, after the page has been sent, asks AVA Pay /verify what the
 * signature proves. The verdict is recorded and shown to the merchant. It is
 * never used to block, delay, redirect or discount the page view: a visit is
 * observed, the verify endpoint is still the only path that acts.
 *
 * Everything here is pure (no WordPress), so the gate, the request
 * reconstruction and the event row are unit-tested directly.
 *
 * Reconstruction trust model. The agent signed the URL it requested, so the
 * signed @authority is the Host header it sent. That is why the URL is built
 * from HTTP_HOST as received, not from home_url(): a site whose home URL
 * differs from the host the agent used (www vs apex, a staging domain) would
 * otherwise fail every verification. Taking the Host as received is safe
 * here in a way it is not on the verify endpoint, because nothing is granted
 * on this path: a spoofed Host can only make an agent's own signature fail
 * to verify, and the row records that. X-Forwarded-* is never read, for
 * anything: those headers are client-controlled unless a proxy the site
 * trusts rewrites them, and nothing here can know which.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Page_Visit {

	/** Value of the verification table's `source` column for this path. */
	const SOURCE = 'page_view';

	/** Page loads only; anything with a body is not a page view. */
	const METHODS = array( 'GET', 'HEAD' );

	/** Capacity of the verification table's `path` column. */
	const PATH_MAX = 255;

	/**
	 * Budget bucket for a request that names no agent at all (no
	 * Signature-Agent, no keyid): every such request shares one bucket.
	 */
	const ANONYMOUS_BUCKET = 'anonymous';

	/**
	 * The only check a human visitor pays for. Both headers, because a
	 * Signature without its Signature-Input (or the reverse) cannot verify.
	 *
	 * @param array $server $_SERVER.
	 * @return bool
	 */
	public static function has_signature_headers( array $server ) {
		return isset( $server['HTTP_SIGNATURE'], $server['HTTP_SIGNATURE_INPUT'] );
	}

	/**
	 * Whether this request is a signed front-end page view we should verify.
	 *
	 * @param array $server  $_SERVER.
	 * @param array $context Booleans from the WordPress layer: enabled (the
	 *                       setting), is_admin, is_rest, is_ajax, is_cron,
	 *                       is_cli, is_feed, is_xmlrpc, is_robots, is_favicon,
	 *                       is_trackback. A missing key reads as the unsafe
	 *                       answer (disabled, or a non-page context), so an
	 *                       incomplete context never turns verification on.
	 * @return bool
	 */
	public static function should_verify( array $server, array $context ) {
		if ( ! self::has_signature_headers( $server ) ) {
			return false;
		}
		$method = isset( $server['REQUEST_METHOD'] ) ? strtoupper( (string) $server['REQUEST_METHOD'] ) : '';
		if ( ! in_array( $method, self::METHODS, true ) ) {
			return false;
		}
		if ( empty( $context['enabled'] ) ) {
			return false;
		}
		$not_a_page = array( 'is_admin', 'is_rest', 'is_ajax', 'is_cron', 'is_cli', 'is_feed', 'is_xmlrpc', 'is_robots', 'is_favicon', 'is_trackback' );
		foreach ( $not_a_page as $flag ) {
			if ( ! array_key_exists( $flag, $context ) || false !== $context[ $flag ] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Request headers from $_SERVER, as a lower-cased hyphenated map: every
	 * HTTP_* key, plus CONTENT_TYPE and CONTENT_LENGTH, which PHP files
	 * without the prefix. Values must already be unslashed (WordPress adds
	 * slashes to $_SERVER) and are otherwise untouched: a signature covers
	 * the bytes the agent sent.
	 *
	 * @param array $server $_SERVER, unslashed.
	 * @return array<string,string>
	 */
	public static function headers_from_server( array $server ) {
		$headers = array();
		foreach ( $server as $key => $value ) {
			if ( ! is_string( $key ) || ! is_scalar( $value ) ) {
				continue;
			}
			if ( 0 === strpos( $key, 'HTTP_' ) ) {
				$name = substr( $key, 5 );
			} elseif ( 'CONTENT_TYPE' === $key || 'CONTENT_LENGTH' === $key ) {
				$name = $key;
			} else {
				continue;
			}
			if ( '' === $name ) {
				continue;
			}
			$headers[ str_replace( '_', '-', strtolower( $name ) ) ] = (string) $value;
		}
		return $headers;
	}

	/**
	 * The request the agent signed, as it should leave the site: method, URL
	 * rebuilt from the Host as received plus the raw request URI, no body,
	 * and the headers minimized by the same rules as the verify endpoint
	 * (credentials never forwarded). Null when the pieces a URL needs are
	 * missing.
	 *
	 * @param array $server $_SERVER, unslashed.
	 * @param bool  $is_ssl is_ssl(), the only scheme signal trusted.
	 * @return array|null IncomingRequest {method, url, headers}.
	 */
	public static function reconstruct( array $server, $is_ssl ) {
		$host = isset( $server['HTTP_HOST'] ) ? (string) $server['HTTP_HOST'] : '';
		$uri  = isset( $server['REQUEST_URI'] ) ? (string) $server['REQUEST_URI'] : '';
		if ( '' === $host || '' === $uri || '/' !== $uri[0] ) {
			return null;
		}
		$headers = AVA_Pay_Verify_Flow::strip_sensitive_headers( self::headers_from_server( $server ) );

		return array(
			'method'  => strtoupper( (string) $server['REQUEST_METHOD'] ),
			'url'     => ( $is_ssl ? 'https' : 'http' ) . '://' . $host . $uri,
			'headers' => AVA_Pay_Forwarded_Headers::minimize( $headers, false ),
		);
	}

	/**
	 * The path to record: the request URI without its query string (which
	 * can carry search terms, tokens or email addresses) or fragment, cut to
	 * the column width. Bytes outside printable ASCII are percent-encoded,
	 * the form a browser would have sent, so the stored value is always
	 * ASCII: a byte cut can then never leave invalid UTF-8 that the database
	 * would reject along with the whole row.
	 *
	 * @param string $request_uri Raw REQUEST_URI.
	 * @return string
	 */
	public static function request_path( $request_uri ) {
		$path = (string) $request_uri;
		$cut  = strcspn( $path, '?#' );
		$path = (string) preg_replace_callback(
			'/[^\x21-\x7E]/',
			static function ( $m ) {
				return '%' . strtoupper( bin2hex( $m[0] ) );
			},
			substr( $path, 0, $cut )
		);
		if ( '' === $path ) {
			$path = '/';
		}
		return strlen( $path ) > self::PATH_MAX ? substr( $path, 0, self::PATH_MAX ) : $path;
	}

	/**
	 * Who the request says it is, before verification: the Signature-Agent
	 * origin, else the keyid. Labels the row and names the budget bucket.
	 *
	 * Starts from the verify endpoint's label (AVA_Pay_Agent_Hint), then
	 * reads the keyid case-insensitively, because Visa TAP spells the
	 * parameter keyId and that label, a port of the Shopify twin's, only
	 * matches keyid. This path has no twin, so it can read both; without it
	 * every TAP agent would share one budget and show as unknown.
	 *
	 * @param array $headers Lower-cased header map.
	 * @return string|null
	 */
	public static function agent_label( array $headers ) {
		$hint = AVA_Pay_Agent_Hint::extract( $headers );
		if ( null !== $hint ) {
			return $hint;
		}
		$input = isset( $headers['signature-input'] ) ? (string) $headers['signature-input'] : '';
		if ( preg_match( '/[;\s]keyid="([^"]+)"/i', $input, $m ) ) {
			return $m[1];
		}
		return null;
	}

	/**
	 * Budget bucket for a request: agent_label(), or one shared bucket for
	 * requests that name no agent.
	 *
	 * @param array $headers Lower-cased header map.
	 * @return string
	 */
	public static function budget_bucket( array $headers ) {
		$label = self::agent_label( $headers );
		return null === $label ? self::ANONYMOUS_BUCKET : $label;
	}

	/**
	 * The verification row for one page visit. Identity only: no merchant
	 * policy runs (a page view is never admitted or refused), so the outcome
	 * is what the verifier concluded, and there is never a discount.
	 *
	 *   verified      the signature verified
	 *   failed        it was checked and rejected
	 *   unverifiable  the verifier could not complete its checks
	 *   error         the API call itself failed (timeout, network, bad
	 *                 response); reason is the client's ava_* reason, never
	 *                 a verdict we did not get
	 *
	 * @param array  $call    API client result.
	 * @param array  $headers Lower-cased request headers (for the labels).
	 * @param string $path    Recorded path (see request_path()).
	 * @return array Event row for AVA_Pay_Events::record_verification().
	 */
	public static function event( array $call, array $headers, $path ) {
		$platform_hint = self::agent_label( $headers );
		$protocol_hint = AVA_Pay_Agent_Hint::sniff_protocol( $headers );
		$row           = array(
			'source'   => self::SOURCE,
			'path'     => (string) $path,
			'platform' => $platform_hint,
			'protocol' => $protocol_hint,
		);

		if ( empty( $call['ok'] ) ) {
			$row['outcome'] = 'error';
			$row['reason']  = 'ava_' . ( isset( $call['error'] ) ? $call['error'] : 'network' );
			return $row;
		}

		$result = is_array( $call['result'] ) ? $call['result'] : array();
		if ( empty( $result['trusted'] ) ) {
			$row['outcome'] = AVA_Pay_Verify_Flow::is_conclusive( $result ) ? 'failed' : 'unverifiable';
			$row['reason']  = ( isset( $result['reason'] ) && is_string( $result['reason'] ) ) ? $result['reason'] : null;
			return $row;
		}

		$labels               = AVA_Pay_Verify_Flow::trusted_labels( $result, $platform_hint, $protocol_hint );
		$row['platform']      = $labels['platform'];
		$row['protocol']      = $labels['protocol'];
		$row['outcome']       = 'verified';
		$row['reason']        = null;
		$row['identity_only'] = ! ( isset( $result['mandate'] ) && is_array( $result['mandate'] ) );
		return $row;
	}
}
