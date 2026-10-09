#!/usr/bin/env bash
# Renders docs/social-preview.png (1280×640) — the image GitHub shows when the repository link is
# shared (Settings → General → Social preview). Reproducible: preview.html is rendered by headless
# Chromium in the same Playwright image the screenshot and CI scripts use, then shrunk with
# pngquant (GitHub wants it under 1 MB).
#
#   scripts/social-preview/run.sh [out.png]      # default: docs/social-preview.png
#
# Inputs: preview.html (layout), frontend/public/favicon.svg (the logo mark),
# docs/screenshots/02-terminal-dark.png (regenerate those first with scripts/screenshots/run.sh if
# the UI changed), and JetBrains Mono from frontend/node_modules (PW_MODULES to point elsewhere).
#
# GitHub has no API for the social preview: after regenerating, upload the PNG by hand in the
# repository settings.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="${1:-$ROOT/docs/social-preview.png}"
PW_IMAGE="mcr.microsoft.com/playwright:v1.63.0-noble"
PW_MODULES="${PW_MODULES:-$ROOT/frontend/node_modules}"
[ -d "$PW_MODULES/playwright" ] && [ -d "$PW_MODULES/@fontsource/jetbrains-mono" ] || {
  echo "playwright / @fontsource/jetbrains-mono not found in $PW_MODULES — run 'npm ci' in frontend/, or set PW_MODULES" >&2
  exit 1
}
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
chmod 777 "$TMP"

cat > "$TMP/render.mjs" <<'JS'
import { chromium } from 'playwright'
const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 })
page.on('console', (m) => { if (m.type() === 'error') console.log('[console]', m.text()) })
page.on('requestfailed', (r) => console.log('[missing]', r.url()))
await page.goto('file:///repo/scripts/social-preview/preview.html', { waitUntil: 'load' })
await page.evaluate(() => document.fonts.ready)
await page.waitForTimeout(300)
await page.screenshot({ path: '/out/social-preview.png' })
await browser.close()
JS

docker run --rm --network none \
  -v "$ROOT:/repo:ro" -v "$PW_MODULES:/node_modules:ro" -v "$TMP:/out" \
  -w /out "$PW_IMAGE" sh -c '
    set -e
    cp /out/render.mjs /render.mjs && cd / && node /render.mjs
    chmod 666 /out/social-preview.png'

if [ "${OPTIMIZE:-1}" = 1 ]; then
  # lossy palette quantisation, as in scripts/screenshots/run.sh (needs the network for apt)
  docker run --rm -v "$TMP:/out" "$PW_IMAGE" sh -c '
    apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends pngquant >/dev/null
    pngquant --quality=75-95 --speed 1 --strip --skip-if-larger --force --output /out/social-preview.png -- /out/social-preview.png || true
    chmod 666 /out/social-preview.png'
fi

cp "$TMP/social-preview.png" "$OUT"
size=$(stat -c %s "$OUT")
echo "✓ $OUT ($((size / 1024)) KB)"
[ "$size" -lt 1048576 ] || { echo "larger than 1 MB — GitHub refuses it; lower the pngquant quality" >&2; exit 1; }
