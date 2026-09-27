<?php
/**
 * The Agent visits markup: every request-derived value is escaped, and the
 * empty state says what it has to.
 *
 * @package AVA_Pay
 */

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/wp-stubs.php';
require_once __DIR__ . '/../includes/class-ava-pay-visits-view.php';

final class VisitsViewTest extends TestCase {

	const HOSTILE_PLATFORM = '<script>alert("platform")</script>';
	const HOSTILE_PATH     = '/"><img src=x onerror=alert(1)>';
	const HOSTILE_REASON   = '</code><b>reason</b>';
	const HOSTILE_PROTOCOL = "web-bot-auth'><svg onload=alert(2)>";

	private function render( array $report ): string {
		ob_start();
		AVA_Pay_Visits_View::render( $report );
		return (string) ob_get_clean();
	}

	private function hostile_report(): array {
		$counts = AVA_Pay_Visit_Report::summarize(
			array(
				array( 'platform' => self::HOSTILE_PLATFORM, 'outcome' => 'failed', 'n' => 3 ),
			),
			array( self::HOSTILE_PLATFORM => 2 )
		);
		return array(
			'enabled'      => true,
			'settings_url' => 'https://shop.example/wp-admin/admin.php?page=ava-pay',
			'periods'      => array(
				7  => $counts,
				30 => $counts,
			),
			'recent'       => array(
				array(
					'time'     => '2026-09-27 12:00',
					'platform' => self::HOSTILE_PLATFORM,
					'protocol' => self::HOSTILE_PROTOCOL,
					'outcome'  => '<i>made-up-outcome</i>',
					'reason'   => self::HOSTILE_REASON,
					'path'     => self::HOSTILE_PATH,
				),
			),
		);
	}

	public function test_hostile_platform_path_reason_and_protocol_are_escaped(): void {
		$html = $this->render( $this->hostile_report() );

		foreach ( array( '<script', '<img', '<svg', '<b>', '<i>' ) as $raw ) {
			$this->assertStringNotContainsString( $raw, $html, "raw {$raw} reached the page" );
		}
		$this->assertStringContainsString( esc_html( self::HOSTILE_PLATFORM ), $html );
		$this->assertStringContainsString( esc_html( self::HOSTILE_PATH ), $html );
		$this->assertStringContainsString( esc_html( self::HOSTILE_REASON ), $html );
		$this->assertStringContainsString( esc_html( self::HOSTILE_PROTOCOL ), $html );
		$this->assertStringContainsString( esc_html( '<i>made-up-outcome</i>' ), $html );
	}

	public function test_counts_tables_show_every_outcome_column(): void {
		$html = $this->render( $this->hostile_report() );
		foreach ( array( 'Verified', 'Failed', 'Unverifiable', 'Error', 'Not checked' ) as $label ) {
			$this->assertStringContainsString( ">{$label}<", $html );
		}
		$this->assertStringContainsString( 'Last 7 days', $html );
		$this->assertStringContainsString( 'Last 30 days', $html );
		$this->assertStringContainsString( 'Recent visits', $html );
		$this->assertStringNotContainsString( 'No signed AI agent has visited your store yet.', $html );
	}

	public function test_not_checked_reasons_are_spelled_out(): void {
		$report            = $this->hostile_report();
		$report['skipped'] = array(
			7  => array( 'budget' => 3, 'busy' => 2, 'backoff' => 1 ),
			30 => array( 'budget' => 30, 'busy' => 20, 'backoff' => 10 ),
		);
		$html = $this->render( $report );
		$this->assertStringContainsString( 'Not checked: 3 over the verification budget', $html );
		$this->assertStringContainsString( '2 while another check was running (one runs at a time), 1 skipped', $html );
		$this->assertStringContainsString( 'Not checked: 30 over', $html );
	}

	public function test_empty_state(): void {
		$html = $this->render(
			array(
				'enabled'      => true,
				'settings_url' => '',
				'periods'      => array(
					7  => array(),
					30 => array(),
				),
				'recent'       => array(),
			)
		);
		$this->assertStringContainsString( 'No signed AI agent has visited your store yet.', $html );
		$this->assertStringContainsString( 'Most AI crawlers do not sign their requests', $html );
		$this->assertStringContainsString( 'ChatGPT' . esc_html( "'" ) . 's agent does sign its requests.', $html );
		$this->assertStringContainsString( 'full-page caching', $html );
		$this->assertStringNotContainsString( 'Last 7 days', $html );
		$this->assertStringNotContainsString( 'is turned off', $html );
	}

	public function test_setting_off_says_so_and_links_to_settings(): void {
		$html = $this->render(
			array(
				'enabled'      => false,
				'settings_url' => 'https://shop.example/wp-admin/admin.php?page=ava-pay&x="y"',
				'periods'      => array(),
				'recent'       => array(),
			)
		);
		$this->assertStringContainsString( 'is turned off', $html );
		$this->assertStringContainsString( 'href="https://shop.example/wp-admin/admin.php?page=ava-pay&amp;x=&quot;y&quot;"', $html );
	}

	public function test_no_em_or_en_dashes_in_the_markup(): void {
		$html = $this->render( $this->hostile_report() ) . $this->render(
			array(
				'enabled' => false,
				'periods' => array(),
				'recent'  => array(),
			)
		);
		$this->assertStringNotContainsString( "\u{2014}", $html );
		$this->assertStringNotContainsString( "\u{2013}", $html );
	}
}
