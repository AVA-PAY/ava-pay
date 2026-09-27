<?php
/**
 * Signed page visits (0.4.0): the gate, the reconstruction of the request the
 * agent signed, the recorded path, the budget bucket, and the event row.
 *
 * The reconstruction cases replay tests/fixtures/page-visit-fixtures.json:
 * page requests signed with the SDK, as $_SERVER would carry them, and the
 * request that must leave the site. The API suite
 * (tests/woo-page-visit.test.ts) verifies those same `expected` requests
 * against the real verifiers, so equality here means a live agent's
 * signature verifies.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

final class PageVisitTest extends TestCase {

	/** @var array */
	private static $fixtures;

	public static function setUpBeforeClass(): void {
		self::$fixtures = ava_pay_load_fixture( 'page-visit-fixtures.json' );
	}

	/** A front-end page request: every non-page flag false, setting on. */
	private function page_context( array $overrides = array() ): array {
		return array_merge(
			array(
				'enabled'      => true,
				'is_admin'     => false,
				'is_rest'      => false,
				'is_ajax'      => false,
				'is_cron'      => false,
				'is_cli'       => false,
				'is_feed'      => false,
				'is_xmlrpc'    => false,
				'is_robots'    => false,
				'is_favicon'   => false,
				'is_trackback' => false,
			),
			$overrides
		);
	}

	private function signed_server( array $overrides = array() ): array {
		return array_merge(
			self::$fixtures['cases'][0]['server'],
			$overrides
		);
	}

	private function fixture( string $name ): array {
		foreach ( self::$fixtures['cases'] as $case ) {
			if ( $case['name'] === $name ) {
				return $case;
			}
		}
		$this->fail( "no fixture {$name}" );
	}

	// ---- gate ---------------------------------------------------------------

	public function test_gate_passes_a_signed_get_and_head_page_view(): void {
		$this->assertTrue( AVA_Pay_Page_Visit::should_verify( $this->signed_server(), $this->page_context() ) );
		$this->assertTrue( AVA_Pay_Page_Visit::should_verify( $this->signed_server( array( 'REQUEST_METHOD' => 'HEAD' ) ), $this->page_context() ) );
	}

	public function test_gate_off_without_both_signature_headers(): void {
		$ctx = $this->page_context();
		$this->assertFalse( AVA_Pay_Page_Visit::should_verify( array( 'REQUEST_METHOD' => 'GET' ), $ctx ), 'a human visitor' );

		$only_sig = $this->signed_server();
		unset( $only_sig['HTTP_SIGNATURE_INPUT'] );
		$this->assertFalse( AVA_Pay_Page_Visit::should_verify( $only_sig, $ctx ), 'Signature without Signature-Input' );

		$only_input = $this->signed_server();
		unset( $only_input['HTTP_SIGNATURE'] );
		$this->assertFalse( AVA_Pay_Page_Visit::should_verify( $only_input, $ctx ), 'Signature-Input without Signature' );

		$this->assertFalse( AVA_Pay_Page_Visit::has_signature_headers( array( 'HTTP_SIGNATURE_AGENT' => '"https://chatgpt.com"' ) ) );
	}

	public function test_gate_off_for_methods_other_than_get_and_head(): void {
		foreach ( array( 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', '' ) as $method ) {
			$this->assertFalse(
				AVA_Pay_Page_Visit::should_verify( $this->signed_server( array( 'REQUEST_METHOD' => $method ) ), $this->page_context() ),
				"method {$method}"
			);
		}
		$no_method = $this->signed_server();
		unset( $no_method['REQUEST_METHOD'] );
		$this->assertFalse( AVA_Pay_Page_Visit::should_verify( $no_method, $this->page_context() ) );
	}

	public function test_gate_off_when_the_setting_is_off(): void {
		$this->assertFalse( AVA_Pay_Page_Visit::should_verify( $this->signed_server(), $this->page_context( array( 'enabled' => false ) ) ) );
	}

	public function test_gate_off_in_every_non_page_context(): void {
		foreach ( array( 'is_admin', 'is_rest', 'is_ajax', 'is_cron', 'is_cli', 'is_feed', 'is_xmlrpc', 'is_robots', 'is_favicon', 'is_trackback' ) as $flag ) {
			$this->assertFalse(
				AVA_Pay_Page_Visit::should_verify( $this->signed_server(), $this->page_context( array( $flag => true ) ) ),
				$flag
			);
		}
	}

	public function test_gate_off_when_the_context_is_incomplete(): void {
		foreach ( array_keys( $this->page_context() ) as $flag ) {
			$ctx = $this->page_context();
			unset( $ctx[ $flag ] );
			$this->assertFalse( AVA_Pay_Page_Visit::should_verify( $this->signed_server(), $ctx ), "missing {$flag}" );
		}
		$this->assertFalse(
			AVA_Pay_Page_Visit::should_verify( $this->signed_server(), $this->page_context( array( 'is_admin' => null ) ) ),
			'a non-boolean flag is not "false"'
		);
	}

	// ---- reconstruction -----------------------------------------------------

	public function test_fixtures_cover_a_port_a_query_head_and_both_protocols(): void {
		$names = array_column( self::$fixtures['cases'], 'name' );
		$this->assertSame( array( 'wba_port_and_query', 'wba_bare_string_head', 'wba_covers_user_agent', 'visa_tap_port_and_query' ), $names );
		$this->assertSame( 'shop.example:8443', $this->fixture( 'wba_port_and_query' )['server']['HTTP_HOST'] );
		$this->assertSame( '/product/widget?color=blue&size=m', $this->fixture( 'wba_port_and_query' )['server']['REQUEST_URI'] );
	}

	public function test_reconstruction_matches_the_request_the_agent_signed(): void {
		foreach ( self::$fixtures['cases'] as $case ) {
			$this->assertTrue(
				AVA_Pay_Page_Visit::should_verify( $case['server'], $this->page_context() ),
				"{$case['name']} passes the gate"
			);
			$got      = AVA_Pay_Page_Visit::reconstruct( $case['server'], $case['isSsl'] );
			$expected = $case['expected'];
			$this->assertNotNull( $got, $case['name'] );
			$this->assertSame( $expected['method'], $got['method'], "{$case['name']} method" );
			$this->assertSame( $expected['url'], $got['url'], "{$case['name']} url" );
			ksort( $expected['headers'] );
			ksort( $got['headers'] );
			$this->assertSame( $expected['headers'], $got['headers'], "{$case['name']} headers" );
			$this->assertArrayNotHasKey( 'body', $got, "{$case['name']} carries no body" );
		}
	}

	public function test_reconstruction_never_reads_forwarded_headers_or_forwards_credentials(): void {
		$case = $this->fixture( 'wba_port_and_query' );
		$got  = AVA_Pay_Page_Visit::reconstruct( $case['server'], true );
		$this->assertStringStartsWith( 'https://shop.example:8443/', $got['url'] );
		$this->assertStringNotContainsString( 'attacker.example', json_encode( $got ) );
		foreach ( array( 'cookie', 'authorization', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-for', 'user-agent', 'accept' ) as $name ) {
			$this->assertArrayNotHasKey( $name, $got['headers'], $name );
		}
	}

	public function test_a_covered_header_travels_but_a_covered_cookie_never_does(): void {
		$ua = AVA_Pay_Page_Visit::reconstruct( $this->fixture( 'wba_covers_user_agent' )['server'], true );
		$this->assertArrayHasKey( 'user-agent', $ua['headers'] );

		$server                         = $this->signed_server();
		$server['HTTP_SIGNATURE_INPUT'] = 'sig1=("@authority" "cookie");created=1;keyid="k";tag="web-bot-auth"';
		$got                            = AVA_Pay_Page_Visit::reconstruct( $server, true );
		$this->assertArrayNotHasKey( 'cookie', $got['headers'] );
	}

	public function test_scheme_comes_only_from_is_ssl(): void {
		$server = $this->signed_server( array( 'HTTP_X_FORWARDED_PROTO' => 'https' ) );
		$this->assertStringStartsWith( 'http://shop.example:8443/', AVA_Pay_Page_Visit::reconstruct( $server, false )['url'] );
		$this->assertStringStartsWith( 'https://', AVA_Pay_Page_Visit::reconstruct( $this->signed_server( array( 'HTTP_X_FORWARDED_PROTO' => 'http' ) ), true )['url'] );
	}

	public function test_reconstruction_refuses_without_a_host_or_an_origin_form_uri(): void {
		$no_host = $this->signed_server();
		unset( $no_host['HTTP_HOST'] );
		$this->assertNull( AVA_Pay_Page_Visit::reconstruct( $no_host, true ) );
		$this->assertNull( AVA_Pay_Page_Visit::reconstruct( $this->signed_server( array( 'HTTP_HOST' => '' ) ), true ) );
		$this->assertNull( AVA_Pay_Page_Visit::reconstruct( $this->signed_server( array( 'REQUEST_URI' => '' ) ), true ) );
		$this->assertNull(
			AVA_Pay_Page_Visit::reconstruct( $this->signed_server( array( 'REQUEST_URI' => 'https://shop.example/product' ) ), true ),
			'absolute-form request target'
		);
	}

	public function test_header_map_from_server(): void {
		$headers = AVA_Pay_Page_Visit::headers_from_server(
			array(
				'HTTP_SIGNATURE_INPUT' => 'sig1=("@authority")',
				'HTTP_X_AVA_MANDATE'   => 'e30=',
				'CONTENT_TYPE'         => 'text/plain',
				'CONTENT_LENGTH'       => '0',
				'REMOTE_ADDR'          => '203.0.113.7',
				'SERVER_NAME'          => 'shop.example',
				'HTTP_'                => 'no name',
				'HTTP_X_LIST'          => array( 'not', 'scalar' ),
				7                      => 'numeric key',
			)
		);
		$this->assertSame(
			array(
				'signature-input' => 'sig1=("@authority")',
				'x-ava-mandate'   => 'e30=',
				'content-type'    => 'text/plain',
				'content-length'  => '0',
			),
			$headers
		);
	}

	// ---- recorded path ------------------------------------------------------

	public function test_request_path_never_keeps_the_query(): void {
		foreach ( self::$fixtures['cases'] as $case ) {
			$this->assertSame( $case['expectedPath'], AVA_Pay_Page_Visit::request_path( $case['server']['REQUEST_URI'] ), $case['name'] );
		}
		$this->assertSame( '/checkout/', AVA_Pay_Page_Visit::request_path( '/checkout/?email=a%40b.example&token=secret' ) );
		$this->assertSame( '/p', AVA_Pay_Page_Visit::request_path( '/p#frag?x=1' ) );
		$this->assertSame( '/', AVA_Pay_Page_Visit::request_path( '?s=search+terms' ) );
		$this->assertSame( '/', AVA_Pay_Page_Visit::request_path( '' ) );
	}

	public function test_request_path_is_ascii_and_fits_the_column(): void {
		$this->assertSame( '/caf%C3%A9%20mug', AVA_Pay_Page_Visit::request_path( "/caf\xC3\xA9 mug?x=1" ) );
		$long = AVA_Pay_Page_Visit::request_path( '/' . str_repeat( "\xC3\xA9", 200 ) );
		$this->assertSame( 255, strlen( $long ) );
		$this->assertSame( 1, preg_match( '/^[\x21-\x7E]+$/', $long ) );
	}

	// ---- budget bucket ------------------------------------------------------

	public function test_budget_bucket_is_the_agent_origin_else_the_keyid(): void {
		$wba = AVA_Pay_Page_Visit::reconstruct( $this->fixture( 'wba_port_and_query' )['server'], true );
		$this->assertSame( 'https://agent.example', AVA_Pay_Page_Visit::budget_bucket( $wba['headers'] ) );

		$tap = AVA_Pay_Page_Visit::reconstruct( $this->fixture( 'visa_tap_port_and_query' )['server'], true );
		// TAP spells it keyId, which the log label does not read.
		$this->assertNull( AVA_Pay_Agent_Hint::extract( $tap['headers'] ) );
		$this->assertSame( 'tap_agent_page_visit', AVA_Pay_Page_Visit::budget_bucket( $tap['headers'] ) );

		$keyed = array( 'signature-input' => 'sig1=("@authority");keyid="agent-key-1"' );
		$this->assertSame( 'agent-key-1', AVA_Pay_Page_Visit::budget_bucket( $keyed ) );
		$this->assertSame( AVA_Pay_Page_Visit::ANONYMOUS_BUCKET, AVA_Pay_Page_Visit::budget_bucket( array( 'signature-input' => 'sig1=("@authority")' ) ) );
	}

	// ---- event row ----------------------------------------------------------

	private function wba_headers(): array {
		return AVA_Pay_Page_Visit::reconstruct( $this->fixture( 'wba_port_and_query' )['server'], true )['headers'];
	}

	public function test_a_tap_row_is_labelled_by_its_keyid_even_without_a_verdict(): void {
		$tap = AVA_Pay_Page_Visit::reconstruct( $this->fixture( 'visa_tap_port_and_query' )['server'], true );
		$this->assertSame( 'tap_agent_page_visit', AVA_Pay_Page_Visit::agent_label( $tap['headers'] ) );
		$row = AVA_Pay_Page_Visit::event(
			array(
				'ok'    => false,
				'error' => 'timeout',
			),
			$tap['headers'],
			'/product/widget'
		);
		$this->assertSame( 'tap_agent_page_visit', $row['platform'] );
		$this->assertSame( 'visa-tap', $row['protocol'] );
		$this->assertNull( AVA_Pay_Page_Visit::agent_label( array( 'signature-input' => 'sig1=("@authority")' ) ) );
	}

	public function test_client_failures_are_error_with_the_client_reason_never_failed(): void {
		foreach ( array( 'timeout', 'network', 'bad_response' ) as $error ) {
			$row = AVA_Pay_Page_Visit::event(
				array(
					'ok'    => false,
					'error' => $error,
				),
				$this->wba_headers(),
				'/product/widget'
			);
			$this->assertSame( 'error', $row['outcome'], $error );
			$this->assertSame( 'ava_' . $error, $row['reason'] );
			$this->assertSame( 'https://agent.example', $row['platform'] );
			$this->assertSame( 'web-bot-auth', $row['protocol'] );
		}
	}

	public function test_rejected_and_could_not_check_verdicts(): void {
		$failed = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted'    => false,
					'reason'     => 'invalid_signature',
					'conclusive' => true,
				),
			),
			$this->wba_headers(),
			'/p'
		);
		$this->assertSame( 'failed', $failed['outcome'] );
		$this->assertSame( 'invalid_signature', $failed['reason'] );

		$unverifiable = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted'    => false,
					'reason'     => 'key_directory_unavailable',
					'conclusive' => false,
				),
			),
			$this->wba_headers(),
			'/p'
		);
		$this->assertSame( 'unverifiable', $unverifiable['outcome'] );
		$this->assertSame( 'key_directory_unavailable', $unverifiable['reason'] );
	}

	public function test_verified_row_is_identity_only_with_no_discount_and_no_policy(): void {
		$row = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted'  => true,
					'protocol' => 'web-bot-auth',
					'agent'    => array( 'id' => 'https://chatgpt.com' ),
					// Present on the verdict, and still never acted on here.
					'discount' => 0.5,
				),
			),
			$this->wba_headers(),
			'/product/widget'
		);
		$this->assertSame(
			array(
				'source'        => 'page_view',
				'path'          => '/product/widget',
				'platform'      => 'https://chatgpt.com',
				'protocol'      => 'web-bot-auth',
				'outcome'       => 'verified',
				'reason'        => null,
				'identity_only' => true,
			),
			$row
		);

		$mandated = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted' => true,
					'mandate' => array( 'maxAmountMinor' => 100 ),
				),
			),
			$this->wba_headers(),
			'/p'
		);
		$this->assertFalse( $mandated['identity_only'] );
		$this->assertArrayNotHasKey( 'discount_pct', $mandated );
		$this->assertArrayNotHasKey( 'discount_code', $mandated );
	}

	public function test_demo_verdict_keeps_page_view_source_and_carries_the_flag_in_reason(): void {
		// The demo credential's page views must be tellable apart from real
		// agent traffic, but the source column belongs to this path: the
		// visits screen and the retention purge both select on 'page_view'.
		// So the flag rides in the reason of the verified row.
		$row = AVA_Pay_Page_Visit::event(
			array(
				'ok'     => true,
				'result' => array(
					'trusted'  => true,
					'protocol' => 'ava-tap',
					'agent'    => array(
						'id'       => 'agent_demo_public',
						'protocol' => 'ava-tap',
					),
					'demo'     => true,
				),
			),
			$this->wba_headers(),
			'/product/widget'
		);
		$this->assertSame( 'page_view', $row['source'] );
		$this->assertSame( 'verified', $row['outcome'] );
		$this->assertSame( 'demo_agent', $row['reason'] );
		$this->assertSame( 'agent_demo_public', $row['platform'] );
		$this->assertTrue( $row['identity_only'] );
	}

	public function test_every_row_is_marked_page_view_and_stores_nothing_identifying(): void {
		$row = AVA_Pay_Page_Visit::event(
			array(
				'ok'    => false,
				'error' => 'timeout',
			),
			$this->wba_headers(),
			'/p'
		);
		$this->assertSame( 'page_view', $row['source'] );
		$this->assertSame(
			array( 'source', 'path', 'platform', 'protocol', 'outcome', 'reason' ),
			array_keys( $row )
		);
	}
}
