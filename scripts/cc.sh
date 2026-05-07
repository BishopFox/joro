#!/usr/bin/env bash
# scripts/cc.sh — invokes `zig cc` for the given target, papering over
# Go-vs-zig integration issues for linux and windows cross-builds.
# (darwin builds use Apple's clang directly — see .goreleaser.yaml.)
#
#   1. Go's ARM64-linux external-linker check (cmd/link/internal/ld/lib.go,
#      issues #15696, #22040) probes the linker with
#         $CC -fuse-ld=gold -Wl,--version
#      and refuses to link unless the output contains "GNU gold". zig
#      reports as "zig ld" and ignores -fuse-ld. We synthesise a "GNU gold"
#      version response. zig still links with LLD underneath, which handles
#      arm64 correctly (the original gold-vs-bfd issue doesn't apply to LLD).
#
#   2. zig has no concept of external linkers — strip -fuse-ld=* so it
#      doesn't error on the real link invocation.
#
# Usage (set as CC for cgo cross-compiles):
#   CC="$(pwd)/scripts/cc.sh <zig-target-triple>"
set -e

target="$1"
shift

for arg in "$@"; do
    if [ "$arg" = "-Wl,--version" ]; then
        echo "GNU gold 1.16 (zig $(zig version 2>/dev/null || echo 0.0) compatibility shim)"
        exit 0
    fi
done

args=()
for arg in "$@"; do
    case "$arg" in
        -fuse-ld=*) ;;
        *) args+=("$arg") ;;
    esac
done

exec zig cc -target "$target" "${args[@]}"
