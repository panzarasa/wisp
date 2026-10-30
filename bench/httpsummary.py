"""Prints the medians of an HTTP benchmark run, one line per server and case.

    python3 bench/httpsummary.py [RESULTS_DIR]

RESULTS_DIR is what bench/run.sh writes (default bench/results). Standard
library only; bench/report.py renders the PDF instead.
"""

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import median

NAME = {"server": "wisp", "baseline": "gnet da solo"}
SCENARIO = {"hello": "GET /", "param": "GET /users/:id", "echo": "POST /echo"}


def main():
    results = Path(sys.argv[1] if len(sys.argv) > 1 else "bench/results")

    usage = {}
    with open(results / "usage.csv") as f:
        for row in csv.DictReader(f):
            usage[(row["target"], row["scenario"], row["conns"], row["rep"])] = row

    runs = defaultdict(list)
    pattern = re.compile(r"(\w+?)_(\w+?)_c(\d+)_r(\d+)\.json")
    for path in sorted((results / "raw").glob("*.json")):
        m = pattern.fullmatch(path.name)
        if not m:
            continue
        try:
            r = json.loads(path.read_text())["result"]
        except (json.JSONDecodeError, KeyError):
            print(f"warning: skipping {path.name}: not a bombardier report", file=sys.stderr)
            continue
        u = usage.get(m.groups())
        seconds = r["timeTakenSeconds"]
        runs[(m[2], int(m[3]), m[1])].append({
            "rps": r["req2xx"] / seconds,
            "errors": r["req1xx"] + r["req3xx"] + r["req4xx"] + r["req5xx"] + r["others"],
            "p50": r["latency"]["percentiles"]["50"],
            "p90": r["latency"]["percentiles"]["90"],
            "p99": r["latency"]["percentiles"]["99"],
            "cpu": int(u["server_cpu_ticks"]) / 100 / seconds if u else float("nan"),
            "rss": float(u["server_peak_rss_kb"]) / 1024 if u else float("nan"),
        })

    print("Mediana delle ripetizioni. Latenza in microsecondi; CPU server: secondi di CPU")
    print("per secondo di prova (1.00 = un core pieno); RAM: picco di memoria del server.")
    order = list(SCENARIO)
    last = None
    for scenario, conns, target in sorted(runs, key=lambda k: (order.index(k[0]), k[1], -median(x["rps"] for x in runs[k]))):
        rs = runs[(scenario, conns, target)]
        if (scenario, conns) != last:
            last = (scenario, conns)
            print(f"\n{SCENARIO[scenario]}, {conns} connessioni")
            print(f"{'server':<14} {'rip':>3} {'req/s':>10} {'p50':>7} {'p90':>7} {'p99':>7} {'CPU srv':>8} {'RAM MiB':>8} {'errori':>7}")
        med = lambda key: median(x[key] for x in rs)
        print(f"{NAME.get(target, target):<14} {len(rs):>3} {med('rps'):>10.0f} {med('p50'):>7.0f} {med('p90'):>7.0f} "
              f"{med('p99'):>7.0f} {med('cpu'):>8.2f} {med('rss'):>8.1f} {sum(x['errors'] for x in rs):>7}")


if __name__ == "__main__":
    main()
