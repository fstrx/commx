#!/usr/bin/env bash
# Build libcommx_android.so for each Android ABI into app/src/main/jniLibs.
# Needs: rustup targets aarch64-linux-android x86_64-linux-android, cargo-ndk,
# cmake, and an NDK (ANDROID_NDK_HOME, or the newest one in the SDK).
set -euo pipefail
cd "$(dirname "$0")"
PROFILE="${1:-release}"
SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
export ANDROID_NDK_HOME ANDROID_NDK="$ANDROID_NDK_HOME"
# libopus is built with cmake; point it at the NDK toolchain.
export CMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake"
export ANDROID_PLATFORM=android-26
flags=()
[ "$PROFILE" = "release" ] && flags+=(--release)
for abi in arm64-v8a x86_64; do
  ANDROID_ABI="$abi" cargo ndk -t "$abi" -P 26 -o app/src/main/jniLibs build -p commx-android "${flags[@]}"
done
