#!/usr/bin/env python3
"""Parse iai-callgrind stdout into github-action-benchmark's customSmallerIsBetter JSON.

Only extracts the Instructions metric (deterministic, CI-stable).

Input format (from cargo bench with iai-callgrind):
    binary_benchmark::marshal_group::bench_marshal_allocating
      Instructions:                       94637|86391                (+9.54498%) [+1.09545x]
      L1 Hits:                           146980|122791               ...
      ...

Output format (customSmallerIsBetter):
    [{"name": "binary_benchmark::marshal_group::bench_marshal_allocating", "unit": "instructions", "value": 94637}]
"""

import json
import re
import sys

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)


def parse_iai_output(text: str) -> list[dict]:
    results = []
    current_bench = None

    for raw_line in text.splitlines():
        line = strip_ansi(raw_line)
        stripped = line.strip()

        # Benchmark name: non-indented line that doesn't start with known metric prefixes
        # and isn't a cargo/compiler message
        if (
            not line.startswith(" ")
            and not line.startswith("\t")
            and stripped
            and not stripped.startswith(("Compiling", "Finished", "Running", "Iai-Callgrind", "iai_callgrind"))
            and "::" in stripped
        ):
            current_bench = stripped
            continue

        # Instructions line
        if current_bench and stripped.startswith("Instructions:"):
            match = re.search(r"Instructions:\s+(\d+)", stripped)
            if match:
                results.append(
                    {
                        "name": current_bench,
                        "unit": "instructions",
                        "value": int(match.group(1)),
                    }
                )
            current_bench = None

    return results


def main():
    text = sys.stdin.read()
    results = parse_iai_output(text)

    if not results:
        print("ERROR: No benchmarks parsed from input", file=sys.stderr)
        sys.exit(1)

    json.dump(results, sys.stdout, indent=2)
    print(f"\nParsed {len(results)} benchmarks", file=sys.stderr)


if __name__ == "__main__":
    main()
