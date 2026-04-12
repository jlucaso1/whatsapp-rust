#!/usr/bin/env python3
"""Generate a collapsed markdown PR comment comparing current vs baseline benchmarks.

Reads current results from bench_results.json and baseline from gh-pages data.js.
Groups benchmarks into regressions, improvements, and unchanged.
"""

import json
import re
import sys

THRESHOLD = 0.02  # 2%


def load_baseline(data_js_path: str, bench_name: str) -> dict[str, int]:
    """Extract the latest data point per benchmark from gh-pages data.js."""
    text = open(data_js_path).read()
    # data.js format: window.BENCHMARK_DATA = { ... };
    json_str = re.sub(r"^window\.BENCHMARK_DATA\s*=\s*", "", text).rstrip().rstrip(";")
    data = json.loads(json_str)

    baseline = {}
    entries = data.get("entries", {}).get(bench_name, [])
    if entries:
        latest = entries[-1]
        for bench in latest.get("benches", []):
            baseline[bench["name"]] = bench["value"]
    return baseline


def format_value(v: int) -> str:
    return f"{v:,}"


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <bench_results.json> <data.js>", file=sys.stderr)
        sys.exit(1)

    current_path, data_js_path = sys.argv[1], sys.argv[2]
    bench_name = "whatsapp-rust benchmarks"

    current_data = json.load(open(current_path))
    baseline = load_baseline(data_js_path, bench_name)

    if not baseline:
        print("No baseline data found, skipping comment", file=sys.stderr)
        sys.exit(0)

    regressions = []
    improvements = []
    unchanged = []

    for entry in current_data:
        name = entry["name"]
        cur = entry["value"]
        prev = baseline.get(name)
        if prev is None:
            continue

        ratio = cur / prev
        pct = (ratio - 1) * 100

        row = {
            "name": name,
            "cur": cur,
            "prev": prev,
            "ratio": ratio,
            "pct": pct,
        }

        if ratio > 1 + THRESHOLD:
            regressions.append(row)
        elif ratio < 1 - THRESHOLD:
            improvements.append(row)
        else:
            unchanged.append(row)

    regressions.sort(key=lambda r: r["ratio"], reverse=True)
    improvements.sort(key=lambda r: r["ratio"])

    lines = []
    lines.append("<!-- benchmark-comment -->")
    lines.append("## Benchmark Results\n")

    if regressions:
        lines.append(
            f"**{len(regressions)} regression(s)** detected (>{THRESHOLD * 100:.0f}% threshold):\n"
        )
        lines.append("| Benchmark | Current | Baseline | Change |")
        lines.append("|-----------|---------|----------|--------|")
        for r in regressions:
            lines.append(
                f"| `{r['name']}` | {format_value(r['cur'])} | {format_value(r['prev'])} | +{r['pct']:.1f}% |"
            )
        lines.append("")

    if improvements:
        lines.append(f"**{len(improvements)} improvement(s):**\n")
        lines.append("| Benchmark | Current | Baseline | Change |")
        lines.append("|-----------|---------|----------|--------|")
        for r in improvements:
            lines.append(
                f"| `{r['name']}` | {format_value(r['cur'])} | {format_value(r['prev'])} | {r['pct']:.1f}% |"
            )
        lines.append("")

    if unchanged:
        lines.append(
            f"<details>\n<summary>{len(unchanged)} unchanged benchmark(s)</summary>\n"
        )
        lines.append("| Benchmark | Current | Baseline | Change |")
        lines.append("|-----------|---------|----------|--------|")
        for r in unchanged:
            sign = "+" if r["pct"] >= 0 else ""
            lines.append(
                f"| `{r['name']}` | {format_value(r['cur'])} | {format_value(r['prev'])} | {sign}{r['pct']:.1f}% |"
            )
        lines.append("\n</details>")

    if not regressions and not improvements:
        lines.append("No significant changes detected.")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
