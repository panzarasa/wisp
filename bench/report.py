# /// script
# requires-python = ">=3.10"
# dependencies = ["reportlab>=4"]
# ///
"""Renders the PDF report of a benchmark run.

    uv run bench/report.py [RESULTS_DIR] [OUTPUT_PDF]

RESULTS_DIR is what bench/run.sh writes: raw/*.json (bombardier), usage.csv,
meta.env and, optionally, microbench.txt and notes.txt (free text about the
run, one paragraph per line).
"""

import csv
import json
import math
import re
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import median

from reportlab.graphics.shapes import Circle, Drawing, Line, PolyLine, Rect, String
from reportlab.lib.colors import HexColor, white
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Text is set in Helvetica with the PDF built-in encoding: keep to characters
# of Windows-1252 (no arrows, no "approximately equal", no minus sign U+2212).

INK = HexColor("#0b0b0b")
INK_2 = HexColor("#52514e")
MUTED = HexColor("#898781")
GRID = HexColor("#e1e0d9")
AXIS = HexColor("#c3c2b7")
PLANE = HexColor("#f6f6f3")

# One colour per server, the same in every chart.
TARGETS = ("baseline", "server")
NAME = {"baseline": "gnet da solo", "server": "gnet + wildcat"}
COLOR = {"baseline": HexColor("#2a78d6"), "server": HexColor("#eb6834")}

SCENARIO = {
    "hello": "GET /",
    "param": "GET /users/:id",
    "echo": "POST /echo",
}

PERCENTILES = ("50", "75", "90", "95", "99")

PAGE_W, PAGE_H = A4
MARGIN = 48
WIDTH = PAGE_W - 2 * MARGIN

FONT, BOLD = "Helvetica", "Helvetica-Bold"


# --- data -------------------------------------------------------------------


@dataclass
class Run:
    rps: float
    requests: int
    errors: int
    latency: dict  # percentile -> microseconds
    latency_mean: float
    latency_max: float
    cpu_seconds: float = math.nan  # server CPU time during the run
    rss_kb: float = math.nan  # server peak resident memory
    client_cpu_seconds: float = math.nan
    seconds: float = math.nan


def load(results: Path):
    """Returns {(target, scenario, conns): [Run, ...]} and the run metadata."""
    usage = {}
    with open(results / "usage.csv") as f:
        for row in csv.DictReader(f):
            key = (row["target"], row["scenario"], int(row["conns"]), int(row["rep"]))
            usage[key] = row

    runs = defaultdict(list)
    pattern = re.compile(r"(\w+?)_(\w+?)_c(\d+)_r(\d+)\.json")
    for path in sorted((results / "raw").glob("*.json")):
        m = pattern.fullmatch(path.name)
        if not m:
            continue
        target, scenario, conns, rep = m[1], m[2], int(m[3]), int(m[4])

        try:
            r = json.loads(path.read_text())["result"]
        except (json.JSONDecodeError, KeyError):
            # What an interrupted run leaves behind.
            print(f"warning: skipping {path.name}: not a bombardier report", file=sys.stderr)
            continue
        ok = r["req2xx"]
        run = Run(
            rps=ok / r["timeTakenSeconds"],
            requests=ok,
            errors=r["req1xx"] + r["req3xx"] + r["req4xx"] + r["req5xx"] + r["others"],
            latency={p: r["latency"]["percentiles"][p] for p in PERCENTILES},
            latency_mean=r["latency"]["mean"],
            latency_max=r["latency"]["max"],
            seconds=r["timeTakenSeconds"],
        )
        if u := usage.get((target, scenario, conns, rep)):
            run.cpu_seconds = int(u["server_cpu_ticks"]) / 100
            run.rss_kb = float(u["server_peak_rss_kb"])
            run.client_cpu_seconds = float(u["client_cpu_seconds"] or "nan")
        runs[(target, scenario, conns)].append(run)

    meta = {}
    for line in (results / "meta.env").read_text().splitlines():
        key, _, value = line.partition("=")
        meta[key] = value

    return dict(runs), meta


def med(runs, value):
    return median(value(r) for r in runs)


def load_microbench(path: Path):
    """Parses `go test -bench` output into [(name, ns/op, allocs/op)]."""
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        m = re.match(r"Benchmark(\S+?)(?:-\d+)?\s+\d+\s+([\d.]+) ns/op.*?(\d+) allocs/op", line)
        if m:
            rows.append((m[1], float(m[2]), int(m[3])))
    return rows


# --- formatting (Italian conventions) ----------------------------------------


def num(x, decimals=0):
    s = f"{x:,.{decimals}f}"
    return s.replace(",", "\x00").replace(".", ",").replace("\x00", ".")


def compact(x):
    if x >= 1e6:
        return num(x / 1e6, 1) + "M"
    if x >= 1e3:
        return num(x / 1e3) + "k"
    return num(x)


def latency(us):
    if us >= 10_000:
        return num(us / 1000, 1) + " ms"
    if us >= 1000:
        return num(us / 1000, 2) + " ms"
    return num(us) + " µs"


def percent(x, decimals=1):
    sign = "+" if x > 0 else "–" if x < 0 else ""
    return f"{sign}{num(abs(x), decimals)}%"


def nice_ticks(lo, hi, target=4):
    """Round tick values covering [lo, hi]."""
    span = hi - lo
    if span <= 0:
        return [lo]
    raw = span / target
    mag = 10 ** math.floor(math.log10(raw))
    step = next(m * mag for m in (1, 2, 2.5, 5, 10) if m * mag >= raw)
    first = math.floor(lo / step) * step
    ticks = []
    t = first
    while t < hi + step * 0.999:
        ticks.append(round(t, 10))
        t += step
    return ticks


# --- drawing helpers ---------------------------------------------------------


def text(d, x, y, s, size=8, color=INK_2, anchor="start", font=FONT):
    d.add(String(x, y, s, fontName=font, fontSize=size, fillColor=color, textAnchor=anchor))


def hline(d, x1, x2, y, color=GRID, width=0.5):
    d.add(Line(x1, y, x2, y, strokeColor=color, strokeWidth=width))


def column(d, x, y, w, h, color):
    """A column standing on y: rounded at the data end, square at the baseline."""
    if h <= 0:
        return
    r = min(4, w / 2, h)
    d.add(Rect(x, y, w, h, rx=r, ry=r, fillColor=color, strokeColor=None))
    d.add(Rect(x, y, w, h - r, fillColor=color, strokeColor=None))


def bar(d, x, y, w, h, color):
    """A horizontal bar growing right from x."""
    if w <= 0:
        return
    r = min(4, h / 2, w)
    d.add(Rect(x, y, w, h, rx=r, ry=r, fillColor=color, strokeColor=None))
    d.add(Rect(x, y, w - r, h, fillColor=color, strokeColor=None))


def dot(d, x, y, color, r=3.2):
    # The white ring keeps overlapping dots legible.
    d.add(Circle(x, y, r, fillColor=color, strokeColor=white, strokeWidth=1.2))


def legend(d, x, y, targets=TARGETS):
    for t in targets:
        d.add(Rect(x, y - 1, 8, 8, rx=2, ry=2, fillColor=COLOR[t], strokeColor=None))
        text(d, x + 12, y, NAME[t], 8.5, INK_2)
        x += 12 + stringWidth(NAME[t], FONT, 8.5) + 18
    return x


# --- charts ------------------------------------------------------------------


def throughput_chart(runs, conns):
    """Median requests/s per connection count; whiskers span min-max of the runs."""
    h, left, right, top, bottom = 210, 40, 6, 44, 34
    d = Drawing(WIDTH, h)
    x0, x1, y0, y1 = left, WIDTH - right, bottom, h - top

    series = {t: [runs[(t, "hello", c)] for c in conns] for t in TARGETS}
    top_value = max(r.rps for t in TARGETS for group in series[t] for r in group)
    ticks = nice_ticks(0, top_value * 1.02)
    scale = (y1 - y0) / ticks[-1]

    for t in ticks:
        y = y0 + t * scale
        hline(d, x0, x1, y, AXIS if t == 0 else GRID)
        text(d, x0 - 6, y - 2.8, compact(t), 8, MUTED, "end")

    legend(d, x0, h - 12)

    bar_w, gap = 22, 2
    slot = (x1 - x0) / len(conns)
    for i, c in enumerate(conns):
        cx = x0 + slot * (i + 0.5)
        tops = []
        for j, t in enumerate(TARGETS):
            group = series[t][i]
            value = med(group, lambda r: r.rps)
            bx = cx - bar_w - gap / 2 + j * (bar_w + gap)
            column(d, bx, y0, bar_w, value * scale, COLOR[t])

            lo, hi = min(r.rps for r in group), max(r.rps for r in group)
            mx = bx + bar_w / 2
            d.add(Line(mx, y0 + lo * scale, mx, y0 + hi * scale, strokeColor=INK, strokeWidth=1))
            for v in (lo, hi):
                d.add(Line(mx - 3, y0 + v * scale, mx + 3, y0 + v * scale, strokeColor=INK, strokeWidth=1))
            tops.append((value, hi))

        delta = (tops[1][0] / tops[0][0] - 1) * 100
        label_y = y0 + max(hi for _, hi in tops) * scale + 7
        text(d, cx, label_y, percent(delta), 8.5, INK, "middle", BOLD)
        text(d, cx, y0 - 13, num(c), 8.5, INK_2, "middle")

    text(d, (x0 + x1) / 2, 4, "connessioni simultanee", 8, MUTED, "middle")
    return d


def runs_chart(runs, conns):
    """Every single run as a dot, on a zoomed axis, to show noise against difference."""
    h, left, right, top, bottom = 170, 40, 6, 14, 34
    d = Drawing(WIDTH, h)
    x0, x1, y0, y1 = left, WIDTH - right, bottom, h - top

    values = [r.rps for t in TARGETS for c in conns for r in runs[(t, "hello", c)]]
    ticks = nice_ticks(min(values), max(values))
    lo, hi = ticks[0], ticks[-1]
    scale = (y1 - y0) / (hi - lo)

    for t in ticks:
        y = y0 + (t - lo) * scale
        hline(d, x0, x1, y)
        text(d, x0 - 6, y - 2.8, compact(t), 8, MUTED, "end")

    slot = (x1 - x0) / len(conns)
    for i, c in enumerate(conns):
        cx = x0 + slot * (i + 0.5)
        for j, t in enumerate(TARGETS):
            group = runs[(t, "hello", c)]
            gx = cx + (j - 0.5) * 44
            step = min(7, 30 / max(len(group), 1))
            for k, r in enumerate(group):
                dot(d, gx + (k - (len(group) - 1) / 2) * step, y0 + (r.rps - lo) * scale, COLOR[t])
            m = y0 + (med(group, lambda r: r.rps) - lo) * scale
            d.add(Line(gx - 19, m, gx + 19, m, strokeColor=INK, strokeWidth=1))
        text(d, cx, y0 - 13, num(c), 8.5, INK_2, "middle")

    text(d, (x0 + x1) / 2, 4, "connessioni simultanee", 8, MUTED, "middle")
    return d


def latency_chart(runs, conns):
    """Small multiples: the latency percentiles at each connection count."""
    h, top, bottom, gutter = 176, 40, 20, 14
    d = Drawing(WIDTH, h)
    legend(d, 0, h - 12)

    panel_w = (WIDTH - gutter * (len(conns) - 1)) / len(conns)
    for i, c in enumerate(conns):
        px = i * (panel_w + gutter)
        x0, x1, y0, y1 = px + 26, px + panel_w - 4, bottom, h - top

        lines = {
            t: [med(runs[(t, "hello", c)], lambda r, p=p: r.latency[p]) for p in PERCENTILES]
            for t in TARGETS
        }
        top_value = max(v for t in TARGETS for v in lines[t])
        unit, div = ("ms", 1000) if top_value >= 2000 else ("µs", 1)
        ticks = nice_ticks(0, top_value / div, 3)
        scale = (y1 - y0) / ticks[-1]

        text(d, px, h - 30, f"{num(c)} connessioni", 8.5, INK, font=BOLD)
        text(d, px + panel_w - 4, h - 30, unit, 8, MUTED, "end")

        for t in ticks:
            y = y0 + t * scale
            hline(d, x0 - 4, x1, y, AXIS if t == 0 else GRID)
            text(d, x0 - 7, y - 2.8, num(t, 0 if t == int(t) else 1), 7.5, MUTED, "end")

        xs = [x0 + 6 + k * (x1 - x0 - 12) / (len(PERCENTILES) - 1) for k in range(len(PERCENTILES))]
        for k, p in enumerate(PERCENTILES):
            text(d, xs[k], y0 - 11, "p" + p, 7.5, MUTED, "middle")

        for t in TARGETS:
            ys = [y0 + v / div * scale for v in lines[t]]
            points = [coord for pair in zip(xs, ys) for coord in pair]
            d.add(PolyLine(points, strokeColor=COLOR[t], strokeWidth=2, strokeLineJoin=1, strokeLineCap=1))
            for x, y in zip(xs, ys):
                dot(d, x, y, COLOR[t], 2.8)
    return d


def routes_chart(rows):
    """rows: [(label, target, requests/s)] as horizontal bars with the value at the tip."""
    bar_h, pitch, label_w, top = 14, 26, 196, 26
    h = top + pitch * len(rows) + 4
    d = Drawing(WIDTH, h)
    legend(d, 0, h - 12)

    x0 = label_w
    room = WIDTH - x0 - 78  # space for the value after the longest bar
    scale = room / max(v for _, _, v in rows)

    d.add(Line(x0, 2, x0, h - top + 4, strokeColor=AXIS, strokeWidth=0.5))
    for i, (label, target, value) in enumerate(rows):
        y = h - top - pitch * (i + 1) + (pitch - bar_h) / 2
        text(d, x0 - 8, y + 4, label, 8.5, INK_2, "end")
        bar(d, x0, y, value * scale, bar_h, COLOR[target])
        text(d, x0 + value * scale + 6, y + 4, num(value) + " req/s", 8.5, INK)
    return d


def tiles(items):
    """A row of stat tiles: [(label, value, unit, note)]."""
    h, gap = 62, 8
    d = Drawing(WIDTH, h)
    w = (WIDTH - gap * (len(items) - 1)) / len(items)
    for i, (label, value, unit, note) in enumerate(items):
        x = i * (w + gap)
        d.add(Rect(x, 0, w, h, rx=5, ry=5, fillColor=PLANE, strokeColor=None))
        text(d, x + 10, h - 16, label, 8, INK_2)
        text(d, x + 10, h - 38, value, 17, INK, font=BOLD)
        text(d, x + 10 + stringWidth(value, BOLD, 17) + 4, h - 38, unit, 8.5, INK_2)
        text(d, x + 10, 9, note, 7.5, MUTED)
    return d


# --- document ----------------------------------------------------------------

BODY = ParagraphStyle("body", fontName=FONT, fontSize=9.5, leading=13.5, textColor=INK, spaceAfter=6)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=8, leading=11, textColor=INK_2, spaceAfter=4)
TITLE = ParagraphStyle("title", fontName=BOLD, fontSize=21, leading=25, textColor=INK, spaceAfter=3)
LEAD = ParagraphStyle("lead", parent=BODY, fontSize=10.5, leading=14.5, textColor=INK_2, spaceAfter=10)
H2 = ParagraphStyle("h2", fontName=BOLD, fontSize=12.5, leading=16, textColor=INK, spaceBefore=14, spaceAfter=3)
CAPTION = ParagraphStyle("caption", parent=SMALL, spaceAfter=6)
BULLET = ParagraphStyle("bullet", parent=BODY, leftIndent=11, bulletIndent=0, spaceAfter=3)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=8.5, leading=11.5, spaceAfter=0)


def table(header, rows, widths, align=None, group_every=0):
    """A quiet table: hairlines only, numbers right-aligned."""
    align = align or ["LEFT"] + ["RIGHT"] * (len(header) - 1)
    style = [
        ("FONT", (0, 0), (-1, 0), FONT, 7.8),
        ("TEXTCOLOR", (0, 0), (-1, 0), MUTED),
        ("FONT", (0, 1), (-1, -1), FONT, 8.5),
        ("TEXTCOLOR", (0, 1), (-1, -1), INK),
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, AXIS),
        ("LINEBELOW", (0, 1), (-1, -2), 0.4, GRID),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("RIGHTPADDING", (-1, 0), (-1, -1), 0),
    ]
    for i, a in enumerate(align):
        style.append(("ALIGN", (i, 0), (i, -1), a))
    if group_every:
        for r in range(group_every, len(rows), group_every):
            style.append(("LINEBELOW", (0, r), (-1, r), 0.6, AXIS))
    t = Table([header] + rows, colWidths=widths, hAlign="LEFT", repeatRows=1)
    t.setStyle(TableStyle(style))
    return t


def swatch(target):
    return f'<font color="{COLOR[target].hexval().replace("0x", "#")}">&#9632;</font> {NAME[target]}'


def build(results: Path, output: Path):
    runs, meta = load(results)

    conns = sorted({c for (t, s, c) in runs if s == "hello"})
    conns = [c for c in conns if all((t, "hello", c) in runs for t in TARGETS)]
    if not conns:
        sys.exit(f"no complete 'hello' results in {results}")

    def rps(target, c, scenario="hello"):
        return med(runs[(target, scenario, c)], lambda r: r.rps)

    def lat(target, c, p, scenario="hello"):
        return med(runs[(target, scenario, c)], lambda r: r.latency[p])

    def cpu_per_request(target, c, scenario="hello"):
        return med(runs[(target, scenario, c)], lambda r: r.cpu_seconds / r.requests * 1e6)

    def delta(c):
        return (rps("server", c) / rps("baseline", c) - 1) * 100

    def overlapping(c):
        b, s = runs[("baseline", "hello", c)], runs[("server", "hello", c)]
        return max(r.rps for r in s) >= min(r.rps for r in b) and max(r.rps for r in b) >= min(r.rps for r in s)

    reps = max(len(v) for v in runs.values())
    ref = max(conns, key=lambda c: rps("baseline", c))
    total_requests = sum(r.requests for v in runs.values() for r in v)
    total_errors = sum(r.errors for v in runs.values() for r in v)
    deltas = [delta(c) for c in conns]
    layer_cpu = cpu_per_request("server", ref) - cpu_per_request("baseline", ref)
    loops = meta.get("LOOPS", "?")
    single_core = loops == "1"

    story = []
    add = story.append

    add(Paragraph("gnet da solo e gnet + wildcat", TITLE))
    add(Paragraph(
        "Quanto costa mettere sopra gnet un livello HTTP fatto da noi: parser wildcat incorporato, "
        "controlli sul framing e router.", LEAD))

    if delta(ref) < 0:
        verdict = (f"il livello HTTP costa il <b>{num(-delta(ref), 1)}%</b> del throughput, "
                   f"cioè circa {num(layer_cpu, 2)} µs di CPU in più per richiesta")
    else:
        verdict = f"il livello HTTP non ha un costo misurabile (differenza {percent(delta(ref))})"
    spread = (f"Tra {num(conns[0])} e {num(conns[-1])} connessioni la differenza va da "
              f"{percent(max(deltas))} a {percent(min(deltas))}. ") if len(conns) > 1 else ""
    errors = ("Nessuna richiesta è fallita" if total_errors == 0
              else f"{num(total_errors)} richieste non hanno avuto una risposta 2xx")
    add(Paragraph(
        f"Con {num(ref)} connessioni, {'su un solo core' if single_core else f'con {loops} event loop'}, "
        f"gnet da solo serve <b>{num(rps('baseline', ref))}</b> "
        f"richieste al secondo e gnet + wildcat <b>{num(rps('server', ref))}</b>: {verdict}. {spread}"
        f"La latenza al 99° percentile passa da {latency(lat('baseline', ref, '99'))} a "
        f"{latency(lat('server', ref, '99'))}. {errors} su {num(total_requests / 1e6, 1)} milioni.", BODY))
    add(Spacer(1, 4))

    add(tiles([
        (NAME["baseline"], num(rps("baseline", ref)), "req/s", f"{num(ref)} connessioni, mediana di {reps}"),
        (NAME["server"], num(rps("server", ref)), "req/s", f"{num(ref)} connessioni, mediana di {reps}"),
        ("Differenza di throughput", percent(delta(ref)), "", "rispetto a gnet da solo"),
        ("CPU in più per richiesta", ("+" if layer_cpu >= 0 else "–") + num(abs(layer_cpu), 2), "µs",
         f"{num(cpu_per_request('baseline', ref), 2)} contro {num(cpu_per_request('server', ref), 2)} µs"),
    ]))

    # Throughput

    add(Paragraph("Throughput", H2))
    add(Paragraph(
        f"Richieste al secondo su <font face='{BOLD}'>GET /</font>, mediana di {reps} ripetizioni da "
        f"{meta.get('DURATION', '?')}. Il segmento nero è l'intervallo tra la ripetizione peggiore e la "
        f"migliore; sopra ogni coppia, la differenza di gnet + wildcat rispetto a gnet da solo.", CAPTION))
    add(throughput_chart(runs, conns))

    rows = []
    for c in conns:
        b, s = runs[("baseline", "hello", c)], runs[("server", "hello", c)]
        rows.append([
            num(c),
            num(rps("baseline", c)),
            f"{num(min(r.rps for r in b))} – {num(max(r.rps for r in b))}",
            num(rps("server", c)),
            f"{num(min(r.rps for r in s))} – {num(max(r.rps for r in s))}",
            percent(delta(c)) + (" *" if overlapping(c) else ""),
        ])
    add(Spacer(1, 6))
    add(table(
        ["Connessioni", "gnet da solo (req/s)", "min – max", "gnet + wildcat (req/s)", "min – max", "Differenza"],
        rows, [62, 92, 104, 100, 104, 37]))
    if any(overlapping(c) for c in conns):
        add(Spacer(1, 3))
        add(Paragraph("* Gli intervalli min–max dei due server si sovrappongono: a questo livello la "
                      "differenza è dentro la variabilità tra ripetizioni.", SMALL))

    block = [
        Paragraph("Le singole ripetizioni", H2),
        Paragraph(
            "Ogni punto è una ripetizione, la linea è la mediana. L'asse verticale è ingrandito e non parte "
            "da zero: serve a confrontare la distanza tra i due server con la dispersione delle misure, "
            "non le grandezze.", CAPTION),
        runs_chart(runs, conns),
    ]
    add(KeepTogether(block))

    # Latency

    block = [
        Paragraph("Latenza", H2),
        Paragraph(
            "Percentili della latenza misurata da bombardier, mediana delle ripetizioni. Ogni riquadro ha la "
            "propria scala. bombardier è a ciclo chiuso (ogni connessione aspetta la risposta prima di "
            "inviare la richiesta successiva), quindi la latenza cresce con le connessioni quasi per "
            "costruzione: conta il confronto tra i due server a parità di connessioni.", CAPTION),
        latency_chart(runs, conns),
    ]
    add(KeepTogether(block))

    # Routes

    extra = sorted({c for (t, s, c) in runs if s != "hello"})
    if extra:
        c = extra[0]
        rows = []
        if ("baseline", "hello", c) in runs:
            rows.append((f"{SCENARIO['hello']}  (nessun parsing)", "baseline", rps("baseline", c)))
        if ("server", "hello", c) in runs:
            rows.append((f"{SCENARIO['hello']}  (rotta statica)", "server", rps("server", c)))
        if ("server", "param", c) in runs:
            rows.append((f"{SCENARIO['param']}  (rotta con parametro)", "server", rps("server", c, "param")))
        if ("server", "echo", c) in runs:
            body = int(meta.get("BODY_BYTES", 0))
            size = f"{num(body / 1024)} KiB" if body >= 1024 else f"{body} byte"
            rows.append((f"{SCENARIO['echo']}  (body di {size})", "server", rps("server", c, "echo")))
        block = [
            Paragraph("Le rotte del livello HTTP", H2),
            Paragraph(
                f"Richieste al secondo con {num(c)} connessioni, mediana di {reps} ripetizioni. La rotta con "
                f"parametro attraversa l'albero del router invece della mappa delle rotte statiche; "
                f"l'echo legge il body e lo rimanda indietro.", CAPTION),
            routes_chart(rows),
        ]
        add(KeepTogether(block))

    # Full table

    rows = []
    keys = [(s, c, t) for s in SCENARIO for c in sorted({k[2] for k in runs if k[1] == s})
            for t in TARGETS if (t, s, c) in runs]
    for s, c, t in keys:
        group = runs[(t, s, c)]
        rows.append([
            Paragraph(swatch(t), CELL),
            SCENARIO[s],
            num(c),
            num(rps(t, c, s)),
            latency(lat(t, c, "50", s)),
            latency(lat(t, c, "90", s)),
            latency(lat(t, c, "99", s)),
            latency(med(group, lambda r: r.latency_max)),
            num(cpu_per_request(t, c, s), 2) + " µs",
            num(med(group, lambda r: r.cpu_seconds / r.seconds * 100)) + "%",
            num(med(group, lambda r: r.rss_kb) / 1024, 1) + " MiB",
        ])
    block = [
        Paragraph("Tutti i numeri", H2),
        Paragraph(
            "Mediane delle ripetizioni. «CPU/richiesta» è il tempo di CPU del processo server (utente + "
            "sistema, da /proc) diviso per le richieste servite; «CPU server» è lo stesso tempo in "
            "percentuale di un core; «RSS» è il picco di memoria residente del server.", CAPTION),
        table(
            ["Server", "Richiesta", "Conn.", "req/s", "p50", "p90", "p99", "max", "CPU/richiesta",
             "CPU server", "RSS"],
            rows, [82, 60, 30, 44, 41, 41, 41, 44, 60, 52, 44],
            align=["LEFT", "LEFT"] + ["RIGHT"] * 9),
    ]
    add(KeepTogether(block))

    # Micro-benchmark

    micro = load_microbench(results / "microbench.txt")
    if micro:
        labels = {
            "ParseTypical": "wildcat: solo parsing di una richiesta tipica",
            "Process/static": "livello HTTP completo, rotta statica (GET /)",
            "Process/param": "livello HTTP completo, rotta con parametro (GET /users/42)",
        }
        rows = [[labels.get(name, name), num(ns) + " ns", str(allocs)] for name, ns, allocs in micro
                if name in labels]
        if rows:
            block = [
                Paragraph("Il livello HTTP in isolamento", H2),
                Paragraph(
                    "Micro-benchmark di Go (<font face='Courier'>go test -bench</font>) eseguiti nella stessa "
                    "macchina virtuale durante la costruzione dell'immagine: nessun socket, solo il codice "
                    "che gnet + wildcat esegue in più per ogni richiesta. È la controprova della differenza "
                    "di CPU per richiesta misurata sotto carico.", CAPTION),
                table(["Cosa", "Tempo per richiesta", "Allocazioni"], rows, [300, 110, 89]),
            ]
            add(KeepTogether(block))

    # What is compared

    add(Paragraph("Che cosa si confronta", H2))
    add(Paragraph(
        f"<b>{NAME['baseline']}</b> (cmd/baseline) non conosce HTTP: cerca la riga vuota che chiude una "
        "richiesta e risponde con un blocco di byte preparato una volta al secondo, identico per qualunque "
        "metodo e percorso. Non è un server usabile: è il tetto di ciò che gnet può fare con questo "
        "traffico.", BODY))
    add(Paragraph(
        f"<b>{NAME['server']}</b> (cmd/server) per ogni richiesta esegue il parser wildcat incorporato "
        "(wildcat/wildcat.go), valida versione, Content-Length, Connection e Transfer-Encoding, cerca la "
        "rotta nel router e costruisce la risposta (status, Date, Content-Type, Content-Length). "
        "Per <font face='Courier'>GET /</font> i due server inviano gli stessi 144 byte, quindi la "
        "differenza misurata è solo il lavoro del livello HTTP.", BODY))

    # Method

    add(Paragraph("Ambiente e metodo", H2))
    mem = int(meta.get("VM_MEM_KB", 0)) / 1048576
    env = [
        ["Macchina", f"{meta.get('HOST_CPU') or 'n/d'}, {meta.get('HOST_OS') or 'n/d'}"],
        ["Container", f"Docker, Alpine {meta.get('ALPINE', '?')}, Linux {meta.get('KERNEL', '?')} "
                      f"({meta.get('ARCH', '?')}), {meta.get('VM_CPUS', '?')} CPU e {num(mem, 1)} GiB visibili"],
        ["Software", f"{meta.get('GO_VERSION', '?')}, gnet {meta.get('GNET_VERSION', '?')}, "
                     f"bombardier {meta.get('BOMBARDIER_VERSION', '?')} (client fasthttp, HTTP/1.1 keep-alive)"],
        ["Server", f"{loops} event loop, vincolato alla CPU {meta.get('SERVER_CPUS', '?')} con taskset"],
        ["Generatore di carico", f"bombardier vincolato alle CPU {meta.get('CLIENT_CPUS', '?')}, "
                                 f"stesso container, interfaccia di loopback"],
        ["Misura", f"{reps} ripetizioni da {meta.get('DURATION', '?')} per ogni punto, dopo "
                   f"{meta.get('WARMUP', '?')} di riscaldamento; server riavviato a ogni ripetizione; "
                   f"ordine dei due server alternato"],
        ["Eseguito il", meta.get("DATE", "?").replace("T", " ").replace("Z", " UTC")],
    ]
    t = Table([[Paragraph(k, CELL), Paragraph(v, CELL)] for k, v in env], colWidths=[110, WIDTH - 110], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, GRID),
        ("LEFTPADDING", (0, 0), (0, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
    ]))
    add(t)

    add(Paragraph("Come leggere questi numeri", H2))
    if single_core:
        cores = ("Il server ha <b>un solo core</b> e un solo event loop, apposta: se il generatore di carico "
                 "non ha più CPU del server diventa lui il collo di bottiglia e i due server sembrano uguali. "
                 "Questi numeri non dicono come scala gnet su più core.")
    else:
        cores = (f"Il server usa {loops} event loop: verificare nella tabella che «CPU server» sia vicino al "
                 "100% per ogni loop, altrimenti il collo di bottiglia è il generatore di carico e la "
                 "differenza tra i due server risulta schiacciata.")
    limits = [
        cores,
        "La risposta è di 13 byte e l'handler non fa nulla: è il caso in cui il livello HTTP pesa di più "
        "in percentuale. Con handler reali (database, JSON, I/O) lo stesso costo fisso per richiesta "
        "incide molto meno.",
        "Client e server sono nello stesso container e parlano sul loopback: non c'è rete reale, e una "
        "parte del tempo misurato è del kernel e di bombardier, uguale per entrambi.",
        "È una macchina virtuale su un computer non dedicato: le ripetizioni alternate e le mediane "
        "riducono il rumore, non lo eliminano. Il grafico delle singole ripetizioni mostra quanto è largo.",
    ]
    for item in limits:
        add(Paragraph(item, BULLET, bulletText="•"))

    notes = results / "notes.txt"
    if notes.exists() and notes.read_text().strip():
        add(Paragraph("Note su questa esecuzione", H2))
        for line in notes.read_text().splitlines():
            if line.strip():
                add(Paragraph(line.strip(), BODY))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(FONT, 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, 26, "gnet da solo e gnet + wildcat · bench/report.py")
        canvas.drawRightString(PAGE_W - MARGIN, 26, str(doc.page))
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(output), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=44, bottomMargin=46,
        title="gnet da solo e gnet + wildcat", author="bench/report.py")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


if __name__ == "__main__":
    here = Path(__file__).parent
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else here / "results"
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else here / "report.pdf"
    build(results, output)
    print(output)
