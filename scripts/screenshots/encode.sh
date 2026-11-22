#!/bin/sh
# Runs inside the Playwright image (see run.sh): turns the raw Playwright recordings in /out into
# the published media. Raw input, written by shots.mjs:
#   .tour.raw.webm + .tour-cut      {"start":s,"poster":s,"end":s} (seconds into the raw file)
#   .clip-NAME.raw.webm + .clips.json {"clip-NAME":{"start":s,"end":s,"poster":s}, …}
# Output: tour.mp4 + tour-poster.png; clip-NAME.mp4 + clip-NAME.jpg (+ .webm with CLIP_WEBM=1).
set -eu
cd /out
apt-get update -qq >/dev/null
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ffmpeg python3 >/dev/null 2>&1
ff() { ffmpeg -nostdin -loglevel error -y "$@"; }
# value of a key in a small JSON file (python3: no jq in the image)
jget() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); [d:=d[k] for k in sys.argv[2:]]; print(d)' "$@"; }
rc=0

if [ -f .tour.raw.webm ] && [ -f .tour-cut ]; then
  st=$(jget .tour-cut start); en=$(jget .tour-cut end); po=$(jget .tour-cut poster)
  # -ss after -i: frame-exact cut (the chapters are measured from it)
  ff -i .tour.raw.webm -ss "$st" -to "$en" -an -c:v libx264 -preset slow -crf 24 \
    -pix_fmt yuv420p -movflags +faststart tour.mp4 || rc=1
  ff -ss "$po" -i tour.mp4 -frames:v 1 tour-poster.png || rc=1
  echo "tour.mp4: $(du -k tour.mp4 | cut -f1) KB"
fi

if [ -f .clips.json ]; then
  for raw in .clip-*.raw.webm; do
    [ -f "$raw" ] || continue
    name=${raw#.}; name=${name%.raw.webm}
    st=$(jget .clips.json "$name" start) || continue
    en=$(jget .clips.json "$name" end); po=$(jget .clips.json "$name" poster)
    # screen content: few colours, mostly static → high CRF stays sharp; a keyframe every 2 s
    ff -i "$raw" -ss "$st" -to "$en" -an -c:v libx264 -preset slow -crf 28 -g 50 \
      -pix_fmt yuv420p -movflags +faststart "$name.mp4" || { rc=1; continue; }
    pt=$(python3 -c "print(max(0, $po - $st))")
    ff -ss "$pt" -i "$name.mp4" -frames:v 1 -q:v 5 "$name.jpg" || rc=1
    if [ "${CLIP_WEBM:-0}" = 1 ]; then
      ff -i "$name.mp4" -an -c:v libvpx-vp9 -b:v 0 -crf 42 -deadline good -cpu-used 5 -row-mt 1 "$name.webm" || rc=1
    fi
    echo "$name: $(du -k "$name.mp4" | cut -f1) KB"
  done
fi

rm -rf .tour-raw .tour.raw.webm .tour-cut .clip-*-raw .clip-*.raw.webm .clips.json tour.webm
chown "$OWNER" tour.* tour-poster.png tour-chapters.json clip-* 2>/dev/null || true
exit $rc
