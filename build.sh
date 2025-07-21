#!/bin/bash

# Build script for WhatsApp Rust WASM module
set -e

echo "🔧 Building WhatsApp Rust WASM Signal Protocol..."

# Build the WASM module
echo "📦 Building WASM module..."
cd wacore-wasm
wasm-pack build --target web --out-dir pkg
cd ..

# Check if TypeScript is available for type checking
if command -v tsc &> /dev/null; then
    echo "📝 Checking TypeScript files..."
    tsc --noEmit --strict src/Types/Signal.ts src/Signal/libsignal.ts || echo "⚠️ TypeScript check failed (optional)"
else
    echo "ℹ️ TypeScript not found, skipping type checking"
fi

# Run Rust tests (excluding WASM crate which needs special setup)
echo "🧪 Running Rust tests..."
cargo test --workspace --exclude wacore-wasm

echo "✅ Build completed successfully!"
echo "📁 WASM files are in: wacore-wasm/pkg/"
echo "🌐 Open demo.html in a browser to test the integration"