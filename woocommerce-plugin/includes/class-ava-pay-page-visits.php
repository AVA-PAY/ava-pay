<?php
/**
 * Signed agent page visits, the WordPress side. Observe only: this path
 * never blocks, redirects or discounts a page view, and never waits on
 * purpose. See AVA_Pay_Page_Visit for the decisions and the trust model.
 *
 * Flow:
 *
 *   1. template_redirect (front-end page requests only, priority 0 so it runs
 *      before anything that can redirect and exit). A visitor whose request
 *      carries no Signature and Signature-Input headers costs one isset and
 *      nothing else. A signed request is gated (GET/HEAD, setting on, not
 *      admin/REST/AJAX/cron/CLI/feed/XML-RPC/robots/favicon/trackback) and
 *      reconstructed from $_SERVER right there, while it is still the
 *      request as received.
 *   2. shutdown, after WordPress has flushed its output buffers (it does so
 *      at priority 1). The response is finished first where the server
 *      supports it (fastcgi_finish_request, litespeed_finish_request), so
 *      the visitor has the whole page before the API is called. Then the
 *      budget, then one /verify call with a 3 second timeout, then one row.
 *
 * On servers without a finish-request function the call still happens, with
 * the same short timeout: the page bytes have been flushed, but the
 * connection stays open until PHP exits.
 *
 * @package AVA_Pay
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class AVA_Pay_Page_Visits {

	/** /verify timeout for this path, seconds (filter: ava_pay_page_visit_timeout). */
	const TIMEOUT_SECONDS = 3;

	/** After wp_ob_end_flush_all(), which WordPress hooks to shutdown at 1. */
	const SHUTDOWN_PRIORITY = 1000;

	/**
	 * The visit captured at template_redirect, waiting for shutdown.
	 *
	 * @var array|null {incoming: array, path: string}
	 */
	private static $pending = null;

	public static function register() {
		add_action( 'template_redirect', array( __CLASS__, 'maybe_schedule' ), 0 );
	}

	public static function maybe_schedule() {
		// The one check every visitor pays for. Nothing below runs without it.
		if ( ! isset( $_SERVER['HTTP_SIGNATURE'], $_SERVER['HTTP_SIGNATURE_INPUT'] ) ) {
			return;
		}

		// Unslashed but otherwise raw, on purpose: a signature covers the exact
		// bytes the agent sent, and the text sanitizers collapse whitespace and
		// strip %XX octets, which would break every signature over a header or
		// a percent-encoded path. Nothing read here is output or trusted: it
		// is forwarded to the verifier (minimized) and the path is stored
		// through a prepared insert and escaped on display.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$server = wp_unslash( $_SERVER );
		if ( ! AVA_Pay_Page_Visit::should_verify( $server, self::context() ) ) {
			return;
		}
		$incoming = AVA_Pay_Page_Visit::reconstruct( $server, is_ssl() );
		if ( null === $incoming ) {
			return;
		}

		self::$pending = array(
			'incoming' => $incoming,
			'path'     => AVA_Pay_Page_Visit::request_path( isset( $server['REQUEST_URI'] ) ? $server['REQUEST_URI'] : '' ),
		);
		add_action( 'shutdown', array( __CLASS__, 'verify_pending' ), self::SHUTDOWN_PRIORITY );
	}

	/**
	 * Where this request stands, for AVA_Pay_Page_Visit::should_verify().
	 *
	 * @return array<string,bool>
	 */
	private static function context() {
		$settings = AVA_Pay_Settings::get();
		return array(
			'enabled'      => ! empty( $settings['verifyPageVisits'] ),
			'is_admin'     => is_admin(),
			'is_rest'      => wp_is_serving_rest_request() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ),
			'is_ajax'      => wp_doing_ajax(),
			'is_cron'      => wp_doing_cron(),
			'is_cli'       => defined( 'WP_CLI' ) && WP_CLI,
			'is_feed'      => is_feed(),
			'is_xmlrpc'    => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
			'is_robots'    => is_robots(),
			'is_favicon'   => is_favicon(),
			'is_trackback' => is_trackback(),
		);
	}

	/**
	 * Shutdown: finish the response, then check the budget, verify, record.
	 * Nothing here may throw into WordPress's shutdown sequence.
	 */
	public static function verify_pending() {
		$pending       = self::$pending;
		self::$pending = null;
		if ( null === $pending ) {
			return;
		}

		try {
			self::finish_response();

			$headers = $pending['incoming']['headers'];
			$budget  = self::budget();
			if ( ! $budget->admit( AVA_Pay_Page_Visit::budget_bucket( $headers ) ) ) {
				$budget->count_skip( AVA_Pay_Page_Visit::agent_label( $headers ) );
				return;
			}

			$settings = AVA_Pay_Settings::get();
			$client   = new AVA_Pay_Api_Client(
				apply_filters( 'ava_pay_api_url', $settings['apiUrl'] ),
				self::TIMEOUT_SECONDS,
				'page_view'
			);
			$call     = $client->verify( $pending['incoming'] );

			AVA_Pay_Events::record_verification( AVA_Pay_Page_Visit::event( $call, $headers, $pending['path'] ) );
		} catch ( Throwable $e ) {
			self::log_unhandled( $e );
		}
	}

	/**
	 * Hand the visitor the whole response before any network call. Both
	 * functions end PHP's output buffers and close the connection; the
	 * script keeps running. Without either, the bytes are flushed and the
	 * connection stays open until the script ends (see the PR / readme for
	 * the worst case per server type).
	 */
	private static function finish_response() {
		if ( function_exists( 'fastcgi_finish_request' ) ) {
			fastcgi_finish_request();
			return;
		}
		if ( function_exists( 'litespeed_finish_request' ) ) {
			litespeed_finish_request();
			return;
		}
		flush();
	}

	/**
	 * Budget with transient storage and filterable limits.
	 *
	 * @return AVA_Pay_Visit_Budget
	 */
	public static function budget() {
		$defaults = AVA_Pay_Visit_Budget::DEFAULT_LIMITS;
		return new AVA_Pay_Visit_Budget(
			static function ( $key ) {
				return get_transient( $key );
			},
			static function ( $key, $value, $ttl ) {
				set_transient( $key, $value, $ttl );
			},
			static function () {
				return time();
			},
			array(
				'agent_per_minute' => (int) apply_filters( 'ava_pay_page_visit_agent_per_minute', $defaults['agent_per_minute'] ),
				'agent_per_day'    => (int) apply_filters( 'ava_pay_page_visit_agent_per_day', $defaults['agent_per_day'] ),
				'site_per_minute'  => (int) apply_filters( 'ava_pay_page_visit_site_per_minute', $defaults['site_per_minute'] ),
				'site_per_day'     => (int) apply_filters( 'ava_pay_page_visit_site_per_day', $defaults['site_per_day'] ),
			)
		);
	}

	/**
	 * The visitor never sees this path fail; the host's log does.
	 *
	 * @param Throwable $e The thrown error.
	 */
	private static function log_unhandled( $e ) {
		$message = sprintf(
			'Unhandled error verifying a signed page visit: %s in %s:%d',
			$e->getMessage(),
			$e->getFile(),
			$e->getLine()
		);
		if ( function_exists( 'wc_get_logger' ) ) {
			wc_get_logger()->error( $message, array( 'source' => 'ava-pay' ) );
		} elseif ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( $message ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		}
	}
}
