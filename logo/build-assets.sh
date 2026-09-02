#!/usr/bin/env bash

set -euo pipefail

logo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_file="${logo_dir}/radiuspilot-approved-source.png"
magick_bin="${MAGICK_BIN:-$(command -v magick)}"
work_dir="$(mktemp -d)"

cleanup() {
  rm -rf -- "${work_dir}"
}
trap cleanup EXIT

if [[ ! -f "${source_file}" ]]; then
  echo "Missing approved source: ${source_file}" >&2
  exit 1
fi

"${magick_bin}" "${source_file}" \
  -alpha set -fuzz 15% -transparent '#F6F6F6' \
  -trim +repage -channel A -morphology Erode Diamond:2 +channel \
  -bordercolor none -border 32 \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-lockup-horizontal.png"

"${magick_bin}" "${source_file}" \
  -crop 620x620+60+120 +repage \
  -alpha set -fuzz 15% -transparent '#F6F6F6' \
  -trim +repage -channel A -morphology Erode Diamond:2 +channel \
  "${work_dir}/mark-trim.png"

"${magick_bin}" "${work_dir}/mark-trim.png" \
  -gravity center -background none -extent 672x672 \
  -filter Lanczos -resize 1024x1024 \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-mark-1024.png"

"${magick_bin}" "${source_file}" \
  -crop 1900x360+680+250 +repage \
  -alpha set -fuzz 15% -transparent '#F6F6F6' \
  -trim +repage -channel A -morphology Erode Diamond:2 +channel \
  -bordercolor none -border 32 \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-wordmark.png"

for size in 512 256 128 64; do
  "${magick_bin}" "${logo_dir}/radiuspilot-mark-1024.png" \
    -filter Lanczos -resize "${size}x${size}" \
    -strip -define png:compression-level=9 \
    "${logo_dir}/radiuspilot-mark-${size}.png"
done

"${magick_bin}" "${logo_dir}/radiuspilot-mark-1024.png" \
  -channel RGB -fill '#061539' -colorize 100 +channel \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-mark-mono-navy.png"
"${magick_bin}" "${logo_dir}/radiuspilot-mark-1024.png" \
  -channel RGB -fill '#FFFFFF' -colorize 100 +channel \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-mark-mono-white.png"
"${magick_bin}" "${logo_dir}/radiuspilot-lockup-horizontal.png" \
  -channel RGB -fill '#061539' -colorize 100 +channel \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-lockup-mono-navy.png"
"${magick_bin}" "${logo_dir}/radiuspilot-lockup-horizontal.png" \
  -channel RGB -fill '#FFFFFF' -colorize 100 +channel \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-lockup-mono-white.png"

"${magick_bin}" "${logo_dir}/radiuspilot-mark-1024.png" -resize 520x520 \
  -gravity center -background none -extent 1500x570 \
  "${work_dir}/stack-mark.png"
"${magick_bin}" "${logo_dir}/radiuspilot-wordmark.png" -resize 1360x \
  -gravity center -background none -extent 1500x350 \
  "${work_dir}/stack-wordmark.png"
"${magick_bin}" "${work_dir}/stack-mark.png" "${work_dir}/stack-wordmark.png" \
  -append -bordercolor none -border 40 \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-lockup-stacked.png"

"${magick_bin}" -background none -density 384 "${logo_dir}/favicon.svg" \
  "${work_dir}/favicon-master.png"
for size in 16 32 48; do
  "${magick_bin}" "${work_dir}/favicon-master.png" \
    -filter Lanczos -resize "${size}x${size}" \
    -strip -define png:compression-level=9 \
    "${logo_dir}/favicon-${size}.png"
done
"${magick_bin}" "${work_dir}/favicon-master.png" \
  -background none -define icon:auto-resize=256,128,64,48,32,16 \
  "${logo_dir}/radiuspilot.ico"

"${magick_bin}" -size 180x180 xc:'#F6F6F6' \
  \( "${logo_dir}/radiuspilot-mark-1024.png" -resize 148x148 \) \
  -gravity center -compose over -composite \
  -strip -define png:compression-level=9 \
  "${logo_dir}/apple-touch-icon.png"

"${magick_bin}" -size 512x512 xc:'#F6F6F6' \
  \( "${logo_dir}/radiuspilot-mark-1024.png" -resize 430x430 \) \
  -gravity center -compose over -composite \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-avatar-512.png"

"${magick_bin}" -size 1280x640 xc:'#F6F6F6' \
  \( "${logo_dir}/radiuspilot-lockup-horizontal.png" -resize 1120x \) \
  -gravity center -compose over -composite \
  -strip -define png:compression-level=9 \
  "${logo_dir}/github-social-preview.png"

"${magick_bin}" -size 1600x450 xc:'#F6F6F6' \
  \( "${logo_dir}/radiuspilot-lockup-horizontal.png" -resize 1320x \) \
  -gravity center -compose over -composite "${work_dir}/sheet-light.png"
"${magick_bin}" -size 1600x450 xc:'#061539' \
  \( "${logo_dir}/radiuspilot-lockup-mono-white.png" -resize 1320x \) \
  -gravity center -compose over -composite "${work_dir}/sheet-dark.png"
"${magick_bin}" -size 800x450 xc:'#F6F6F6' \
  \( "${logo_dir}/radiuspilot-mark-1024.png" -resize 330x330 \) \
  -gravity center -compose over -composite "${work_dir}/sheet-mark-light.png"
"${magick_bin}" -size 800x450 xc:'#061539' \
  \( "${logo_dir}/radiuspilot-mark-mono-white.png" -resize 330x330 \) \
  -gravity center -compose over -composite "${work_dir}/sheet-mark-dark.png"
"${magick_bin}" "${work_dir}/sheet-mark-light.png" "${work_dir}/sheet-mark-dark.png" \
  +append "${work_dir}/sheet-marks.png"
"${magick_bin}" "${work_dir}/sheet-light.png" "${work_dir}/sheet-dark.png" \
  "${work_dir}/sheet-marks.png" -append \
  -strip -define png:compression-level=9 \
  "${logo_dir}/radiuspilot-logo-sheet.png"

echo "RadiusPilot brand exports rebuilt in ${logo_dir}"
