#!/bin/sh
# Builds the benchmark image, runs the HTTP benchmarks (run.sh) in it and
# prints the medians (bench/results/summary.txt): wisp against Fiber and
# fasthttp.
#
#   bench/bench.sh                         full run (about 25 minutes)
#   REPS=1 DURATION=3s bench/bench.sh      quick look
#   TARGETS="baseline server" REPORT=1 bench/bench.sh
#                                          wisp against gnet alone, with the
#                                          PDF report (bench/report.pdf, needs
#                                          uv: https://docs.astral.sh/uv/)
#
# Needs Docker ("colima start"). Parameters (see run.sh): TARGETS DURATION
# WARMUP REPS CONNS EXTRA_CONNS SERVER_CPUS CLIENT_CPUS LOOPS BODY_BYTES.
set -eu

cd "$(dirname "$0")/.."

IMAGE=wisp-bench
RESULTS=${RESULTS:-$PWD/bench/results}

docker build -q -f bench/Dockerfile -t "$IMAGE" . > /dev/null

if [ "$(uname)" = Darwin ]; then
    HOST_CPU=$(sysctl -n machdep.cpu.brand_string)
    HOST_OS="macOS $(sw_vers -productVersion)"
else
    HOST_CPU=$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)
    HOST_OS=$(uname -sr)
fi

mkdir -p "$RESULTS"
docker run --rm \
    -v "$RESULTS:/out" \
    -e HOST_CPU="$HOST_CPU" -e HOST_OS="$HOST_OS" \
    -e TARGETS -e DURATION -e WARMUP -e REPS -e CONNS -e EXTRA_CONNS \
    -e SERVER_CPUS -e CLIENT_CPUS -e LOOPS -e BODY_BYTES \
    "$IMAGE"

python3 bench/httpsummary.py "$RESULTS" | tee "$RESULTS/summary.txt"

if [ "${REPORT:-0}" = 1 ]; then
    uv run --quiet bench/report.py "$RESULTS" bench/report.pdf
    echo "report: bench/report.pdf"
fi
