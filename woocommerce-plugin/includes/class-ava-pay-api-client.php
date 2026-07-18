<?php
/**
 * Thin client around the AVA Pay /verify endpoint — the WordPress-transport
 * twin of AvaPayClient (shopify-app lib/ava.server.ts). Network/timeout
 * failures return a typed result instead of throwing, so the REST route
 * never crashes the storefront when AVA is briefly down; the response
 * interpretation itself is pure and lives in
 * AVA_Pay_Verify_Flow::interpret_api_response().
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Api_Client {

	/**
	 * Hard cap on how long we'll wait for /verify before failing closed.
	 * The Shopify app pins 1.5s to fit the app-proxy budget; here nothing
	 * upstream imposes one, but the storefront is still waiting.
	 */
	const DEFAULT_TIMEOUT_SECONDS = 2;

	/** @var string */
	private $base_url;

	/** @var int */
	private $timeout;

	/**
	 * @param string $base_url AVA Pay API base URL.
	 * @param int    $timeout  Seconds.
	 */
	public function __construct( $base_url, $timeout = self::DEFAULT_TIMEOUT_SECONDS ) {
		$this->base_url = rtrim( $base_url, '/' );
		$this->timeout  = (int) apply_filters( 'ava_pay_verify_timeout', $timeout );
	}

	/**
	 * POST an IncomingRequest ({method, url, headers, body?}) to /verify.
	 *
	 * @param array $incoming IncomingRequest payload.
	 * @return array {ok: true, result: array} | {ok: false, error: 'timeout'|'network'|'bad_response', status?: int}
	 */
	public function verify( array $incoming ) {
		$response = wp_remote_post(
			$this->base_url . '/verify',
			array(
				'timeout' => $this->timeout,
				'headers' => array( 'content-type' => 'application/json' ),
				'body'    => wp_json_encode( $incoming ),
			)
		);

		if ( is_wp_error( $response ) ) {
			return array(
				'ok'    => false,
				'error' => self::classify_wp_error( $response ),
			);
		}

		return AVA_Pay_Verify_Flow::interpret_api_response(
			(int) wp_remote_retrieve_response_code( $response ),
			(string) wp_remote_retrieve_body( $response )
		);
	}

	/**
	 * WP_Error → the TS client's error taxonomy. WordPress doesn't type
	 * timeouts distinctly, so sniff the transport message (cURL error 28 /
	 * "timed out"); everything else is 'network'.
	 *
	 * @param WP_Error $error Transport error.
	 * @return string 'timeout'|'network'
	 */
	public static function classify_wp_error( $error ) {
		$message = strtolower( (string) $error->get_error_message() );
		if ( false !== strpos( $message, 'curl error 28' ) || false !== strpos( $message, 'timed out' ) ) {
			return 'timeout';
		}
		return 'network';
	}
}
