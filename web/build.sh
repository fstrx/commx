#!/usr/bin/env bash
# Build the browser client into web/dist (serve it with: commxd --web web/dist).
# Needs: rustup target wasm32-unknown-unknown, and wasm-bindgen-cli matching
# the wasm-bindgen version in Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release -p commx-web --target wasm32-unknown-unknown --manifest-path ../Cargo.toml
rm -rf dist && mkdir -p dist
wasm-bindgen --target web --no-typescript --out-dir dist ../target/wasm32-unknown-unknown/release/commx_web.wasm
cp index.html app.js style.css dist/
echo "built: $(du -sh dist | cut -f1) in web/dist"
