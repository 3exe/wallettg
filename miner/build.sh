#!/usr/bin/env bash
# Builds tgvanity on a Linux machine with an NVIDIA GPU (CUDA toolkit with nvcc required).
# Falls back to a CPU-only build when nvcc is missing.
set -euo pipefail
cd "$(dirname "$0")"

# OpenSSL headers (Ed25519 + SHA-256 on the CPU side)
if [ ! -f /usr/include/openssl/evp.h ]; then
  echo "Installing libssl-dev..."
  if [ "$(id -u)" = 0 ]; then apt-get update -qq && apt-get install -y -qq libssl-dev g++ >/dev/null
  else sudo apt-get update -qq && sudo apt-get install -y -qq libssl-dev g++ >/dev/null; fi
fi

NVCC="$(command -v nvcc || true)"
[ -z "$NVCC" ] && [ -x /usr/local/cuda/bin/nvcc ] && NVCC=/usr/local/cuda/bin/nvcc

if [ -n "$NVCC" ]; then
  echo "Building GPU version with $NVCC ..."
  # -arch=native picks the installed GPU; older CUDA versions need an explicit arch
  if ! "$NVCC" -O3 -std=c++17 -arch=native -o tgvanity vanity.cu -lcrypto -lpthread 2>/tmp/tgvanity-build.log; then
    CC=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | head -1 | tr -d '.' || true)
    CC=${CC:-86}
    echo "-arch=native not supported, building for sm_$CC ..."
    "$NVCC" -O3 -std=c++17 -arch=sm_$CC -o tgvanity vanity.cu -lcrypto -lpthread
  fi
else
  echo "nvcc not found: building CPU-only version (slow). Use an image with the CUDA toolkit (devel) for the GPU."
  g++ -O3 -march=native -std=c++17 -x c++ -o tgvanity vanity.cu -lcrypto -lpthread
fi

./tgvanity --selftest
echo
echo "Ready. Example:  ./tgvanity --suffix CASH"
