#!/usr/bin/env bash
# Build the WordPress.org distribution zip.
#
# Assembles dist/ava-pay-for-woocommerce/ from an explicit allowlist of
# runtime files and zips it to dist/ava-pay-for-woocommerce.zip. Anything not
# listed (vendor/, tests/, scripts/, composer files, phpunit config,
# README.md, .wp-env.json, dotfiles) stays out. Keep .distignore in step with
# this list so the WordPress.org tooling agrees.
#
# Usage: woocommerce-plugin/scripts/build-zip.sh (from any directory)

set -euo pipefail

SLUG="ava-pay-for-woocommerce"
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$PLUGIN_DIR/dist"
STAGE="$DIST_DIR/$SLUG"
ZIP="$DIST_DIR/$SLUG.zip"

INCLUDE=(ava-pay-for-woocommerce.php uninstall.php readme.txt includes assets)
if [ -f "$PLUGIN_DIR/LICENSE" ]; then
	INCLUDE+=(LICENSE)
fi

rm -rf "$STAGE" "$ZIP"
mkdir -p "$STAGE"

for entry in "${INCLUDE[@]}"; do
	if [ ! -e "$PLUGIN_DIR/$entry" ]; then
		echo "build-zip: missing $entry" >&2
		exit 1
	fi
	cp -R "$PLUGIN_DIR/$entry" "$STAGE/"
done

# Dotfiles (.DS_Store and friends) never ship, even inside allowed dirs.
find "$STAGE" -name '.*' -exec rm -rf {} +

(cd "$DIST_DIR" && zip -qrX "$SLUG.zip" "$SLUG")

echo "Built $ZIP"
