<?php
/**
 * Public verify endpoint:  POST /wp-json/ava-pay/v1/verify-agent
 *
 * The WooCommerce twin of the Shopify App Proxy route
 * (shopify-app/app/routes/proxy.verify.tsx). The agent (or the storefront
 * embed JS on the agent's behalf) sends a request whose actual HTTP headers
 * carry the signed payload — Signature, Signature-Input, Content-Digest,
 * x-ava-mandate, and anything else the agent attaches.
 *
 * We pass that request through to AVA Pay /verify EXACTLY as we received it:
 * no header allowlist, no JSON wrapper. The only construction we do is
 * reconstructing the canonical URL + Host the agent signed against from the
 * site's own configuration (rest_url), never from the spoofable incoming
 * Host header — the same trust move the Shopify app makes by rebuilding the
 * host from the Shopify-validated session.shop.
 *
 * Failure mode: if AVA Pay is unreachable or the agent fails verification,
 * we fail closed (allow: false) and record the outcome. Storefront JS treats
 * that as "no discount, proceed normally" — never blocks the customer.
 *
 * All decision logic lives in AVA_Pay_Verify_Flow (pure, unit-tested); this
 * class is I/O only.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Rest {

	const NAMESPACE_V1 = 'ava-pay/v1';
	const ROUTE        = '/verify-agent';

	public static function register_routes() {
		register_rest_route(
			self::NAMESPACE_V1,
			self::ROUTE,
			array(
				array(
					'methods'             => 'GET',
					'callback'            => array( __CLASS__, 'handle_ping' ),
					'permission_callback' => '__return_true',
				),
				array(
					'methods'             => 'POST',
					'callback'            => array( __CLASS__, 'handle_verify' ),
					'permission_callback' => '__return_true',
				),
			)
		);
	}

	public static function handle_ping() {
		return new WP_REST_Response(
			array(
				'ok'      => true,
				'service' => 'ava-pay-woocommerce',
			),
			200
		);
	}

	/**
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public static function handle_verify( $request ) {
		if ( ! self::rate_limiter()->allow( self::client_bucket() ) ) {
			// Pre-verification flood guard: no event row (a flood would fill
			// the table before the API's own rate limit ever engages).
			return self::json(
				array(
					'allow'  => false,
					'reason' => 'rate_limited',
				),
				429
			);
		}

		$headers = self::collect_headers( $request );

		// Canonical signed URL from site config (see file docblock).
		$signed_url = rest_url( self::NAMESPACE_V1 . self::ROUTE );
		$host       = wp_parse_url( $signed_url, PHP_URL_HOST );
		$port       = wp_parse_url( $signed_url, PHP_URL_PORT );
		if ( is_string( $host ) && '' !== $host ) {
			$headers['host'] = $host . ( $port ? ':' . $port : '' );
		}

		$body     = $request->get_body();
		$incoming = array(
			'method'  => $request->get_method(),
			'url'     => $signed_url,
			'headers' => $headers,
		);
		if ( is_string( $body ) && '' !== $body ) {
			$incoming['body'] = $body;
		}

		$settings = AVA_Pay_Settings::get();

		$client = new AVA_Pay_Api_Client(
			apply_filters( 'ava_pay_api_url', $settings['apiUrl'] )
		);
		$call   = $client->verify( $incoming );

		$decision = AVA_Pay_Verify_Flow::decide( $settings, $call, $headers );

		$event    = $decision['event'];
		$response = $decision['response'];

		if ( $response['allow'] && $decision['mint_discount_pct'] > 0 ) {
			$coupon = AVA_Pay_Coupons::mint( $decision['mint_discount_pct'] );
			if ( null !== $coupon ) {
				$event['discount_code'] = $coupon['code'];
				$response['discount']   = array(
					'code'       => $coupon['code'],
					'percentage' => $coupon['percentage'],
				);
			}
		}

		AVA_Pay_Events::record_verification( $event );

		return self::json( $response, 200 );
	}

	/**
	 * Incoming headers as a lower-cased hyphenated map, matching what the
	 * verifier indexes. WP_REST_Request normalizes header keys to
	 * underscores; HTTP header names with literal underscores are
	 * vanishingly rare (and commonly stripped by proxies), so the reverse
	 * mapping is safe in practice.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return array<string,string>
	 */
	private static function collect_headers( $request ) {
		$headers = array();
		foreach ( $request->get_headers() as $key => $values ) {
			$name             = str_replace( '_', '-', strtolower( $key ) );
			$headers[ $name ] = implode( ', ', (array) $values );
		}
		return $headers;
	}

	private static function rate_limiter() {
		$limit  = (int) apply_filters( 'ava_pay_rate_limit', 60 );
		$window = (int) apply_filters( 'ava_pay_rate_limit_window', 60 );
		return new AVA_Pay_Rate_Limiter(
			static function ( $key ) {
				return get_transient( $key );
			},
			static function ( $key, $count, $ttl ) {
				set_transient( $key, $count, $ttl );
			},
			$limit,
			$window
		);
	}

	/**
	 * Rate-limit bucket: REMOTE_ADDR only. X-Forwarded-For is
	 * client-controlled and would let an attacker rotate buckets at will.
	 */
	private static function client_bucket() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : 'unknown';
	}

	private static function json( array $body, $status ) {
		$response = new WP_REST_Response( $body, $status );
		$response->header( 'Cache-Control', 'no-store' );
		return $response;
	}
}
