#!/usr/bin/env bash
# Copyright 2026 Mist Tecnologia LTDA. All rights reserved.

# Runs lwIP's own unit tests (test/unit) against the Rust modules.
#
#   rust/test/unit/run.sh [OUT]
#
# Builds the tests twice with lwipopts.h here, once all C and once with the Rust modules
# in LWIP_RUST_MODULES (every ported module by default) in place of their C files, runs
# both, and fails unless every test has the same result in both: the same pass, or the
# same failure with the same message. The all-C build must also fail exactly the tests
# expected-failures.txt lists. Builds go to OUT (rust/target/unittests by default).
#
# Needs cmake, ninja, a C compiler, cargo, and the check library (CMAKE_PREFIX_PATH
# names a prefix it is installed under, if not a system one).

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/../../target/unittests}
modules=${LWIP_RUST_MODULES:-all}
cargo=${LWIP_RUST_CARGO:-$(command -v cargo)}
target=$("$(dirname "$cargo")/rustc" -vV | sed -n 's/^host: //p')

mkdir -p "$out"
for variant in c rust; do
  rust=()
  if [[ $variant == rust ]]; then
    rust=("-DLWIP_RUST_MODULES=$modules" "-DLWIP_RUST_CARGO=$cargo" "-DLWIP_RUST_TARGET=$target")
  fi
  cmake -S "$here" -B "$out/$variant" -G Ninja -DCMAKE_BUILD_TYPE=Debug "${rust[@]}" >/dev/null
  cmake --build "$out/$variant"
  # A failing test makes the run exit non-zero; the results are compared below.
  (cd "$out/$variant" && CK_TAP_LOG_FILE_NAME="$out/$variant.tap" ./lwip_unittests \
    >"$out/$variant.log" 2>&1) || true
done

# One line per test: "ok SUITE:test", or "not ok SUITE:test: message". A passing test's
# last checkpoint is left out: the C stack's mem_free goes through the tests'
# --wrap=mem_free, whose check moves it, and the Rust modules free inside their object.
results() {
  sed -E -e 's/^ok [0-9]+ - [^:]*:([^:]*:[^:]*):.*/ok \1/' \
    -e 's/^not ok [0-9]+ - [^:]*:/not ok /' "$1"
}
results "$out/c.tap" >"$out/c.results"
results "$out/rust.tap" >"$out/rust.results"
if ! diff -u "$out/c.results" "$out/rust.results"; then
  echo "run.sh: the Rust modules change these results (- C, + Rust)" >&2
  exit 1
fi

sed -n 's/^not ok \([^:]*:[^:]*\):.*/\1/p' "$out/c.results" | sort >"$out/c.failures"
sed -e '/^#/d' -e '/^$/d' -e 's/[[:space:]].*//' "$here/expected-failures.txt" | sort \
  >"$out/expected.failures"
if ! diff -u "$out/expected.failures" "$out/c.failures"; then
  echo "run.sh: the all-C build fails other tests than expected-failures.txt lists" >&2
  exit 1
fi

echo "run.sh: $(grep -c '^ok' "$out/c.results") passed and" \
  "$(grep -c '^not ok' "$out/c.results") failed as expected, the same with Rust" \
  "modules ($modules)"
