#!/usr/bin/env bash
# Build libmojit-gum.so for Android arm64 from the frida-gum submodule.
#
# Requirements:
#   - Android NDK r26 or newer, with NDK_ROOT set or auto-discovered.
#   - Python 3.10+ and Meson 1.3+ on PATH (frida-gum uses Meson).
#   - Ninja on PATH.
#
# Output:
#   build/android-arm64/gum/libmojit-gum.so
#
# Scope of this build:
#   - arch-arm64 only
#   - backend-arm64 + backend-linux + backend-elf + backend-posix
#   - bindings disabled (no JS VM)
#
# See gum/STRIP_LIST.md for the full rationale.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/gum/frida-gum"
BUILD="${ROOT}/build/android-arm64"
API_LEVEL="${ANDROID_API_LEVEL:-29}"   # Android 10+

if [[ ! -d "${SRC}" ]]; then
  echo "error: frida-gum submodule not initialized at ${SRC}" >&2
  echo "hint:  git submodule update --init --depth 1 gum/frida-gum" >&2
  exit 2
fi

# NDK discovery.
if [[ -z "${NDK_ROOT:-}" ]]; then
  for cand in \
      "${ANDROID_NDK_HOME:-}" \
      "${ANDROID_SDK_ROOT:-}/ndk/26"*".0."* \
      "${HOME}/Android/Sdk/ndk/26"*".0."* \
      "/opt/android-ndk"; do
    [[ -n "${cand}" && -d "${cand}" ]] && NDK_ROOT="${cand}" && break
  done
fi
if [[ -z "${NDK_ROOT:-}" || ! -d "${NDK_ROOT}" ]]; then
  echo "error: NDK r26+ not found. Set NDK_ROOT=/path/to/ndk/26.x.x" >&2
  exit 2
fi

TOOLCHAIN="${NDK_ROOT}/toolchains/llvm/prebuilt/linux-x86_64"
SYSROOT="${TOOLCHAIN}/sysroot"
TARGET="aarch64-linux-android${API_LEVEL}"

export CC="${TOOLCHAIN}/bin/${TARGET}-clang"
export CXX="${TOOLCHAIN}/bin/${TARGET}-clang++"
export AR="${TOOLCHAIN}/bin/llvm-ar"
export STRIP="${TOOLCHAIN}/bin/llvm-strip"

CROSS_FILE="${BUILD}/android-arm64.meson-cross"
mkdir -p "${BUILD}"

cat > "${CROSS_FILE}" <<EOF
[binaries]
c       = '${CC}'
cpp     = '${CXX}'
ar      = '${AR}'
strip   = '${STRIP}'
pkg-config = 'pkg-config'

[host_machine]
system     = 'android'
cpu_family = 'aarch64'
cpu        = 'aarch64'
endian     = 'little'

[properties]
needs_exe_wrapper = true
sys_root = '${SYSROOT}'
EOF

# The -Doption keys below follow frida-gum's meson.options. If a key is
# renamed upstream, the Meson step will fail loudly — update this script
# rather than silently turning options off.
meson setup "${BUILD}" "${SRC}" \
    --cross-file "${CROSS_FILE}" \
    --buildtype release \
    --default-library shared \
    --strip \
    -Dgumjs=disabled \
    -Dgumpp=disabled \
    -Dtests=disabled \
    -Dexamples=disabled \
    -Dintrospection=disabled

ninja -C "${BUILD}"

echo
echo "built libmojit-gum slice under ${BUILD}"
echo "next: link with gate/ + shell/ to produce mojit-shell (M1 exit criterion)"
