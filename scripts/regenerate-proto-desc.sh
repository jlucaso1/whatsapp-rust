#!/usr/bin/env bash
# Regenerate waproto/src/whatsapp.desc from waproto/src/whatsapp.proto.
#
# Consumers of this crate never run this — they only need `cargo build`,
# which reads the committed `.desc` and writes Rust source to `OUT_DIR`.
# Editors of the `.proto` run this once per edit and commit both files.
#
# Requires `protoc` on PATH.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proto="$repo_root/waproto/src/whatsapp.proto"
desc="$repo_root/waproto/src/whatsapp.desc"
includes="$repo_root/waproto/src"

if ! command -v protoc >/dev/null 2>&1; then
  echo "error: protoc not on PATH; install protobuf-compiler" >&2
  exit 1
fi

protoc \
  --descriptor_set_out="$desc" \
  --include_imports \
  --include_source_info \
  -I"$includes" \
  "$proto"

echo "regenerated: $desc"
echo "commit both waproto/src/whatsapp.proto and waproto/src/whatsapp.desc"
