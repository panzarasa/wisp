#!/bin/sh
# Builds the benchmark image and runs the WebSocket benchmarks (wsrun.sh)
# in it: gnet + httpd against gorilla/websocket on net/http.
#
#   bench/wsbench.sh                        full run (about 20 minutes)
#   REPS=1 DURATION=3s bench/wsbench.sh     quick look
#
# Needs Docker ("colima start"). Parameters (see wsrun.sh): DURATION WARMUP
# REPS SERVER_CPUS CLIENT_CPUS LOOPS ECHO_CONNS PACED_CONNS PACED_RATES
# CHAT_MEMBERS IDLE_CONNS IDLE_HOLD. Results in bench/results-ws/ (summary.txt for the medians).
set -eu

cd "$(dirname "$0")/.."

IMAGE=wisp-bench
RESULTS=${RESULTS:-$PWD/bench/results-ws}

docker build -q -f bench/Dockerfile -t "$IMAGE" . > /dev/null

if [ "$(uname)" = Darwin ]; then
    HOST_CPU=$(sysctl -n machdep.cpu.brand_string)
    HOST_OS="macOS $(sw_vers -productVersion)"
else
    HOST_CPU=$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo)
    HOST_OS=$(uname -sr)
fi

# Tens of thousands of connections: file descriptors, ephemeral ports and a
# listen backlog to match (all three are per container).
mkdir -p "$RESULTS"
docker run --rm \
    -v "$RESULTS:/out" \
    --ulimit nofile=262144:262144 \
    --sysctl net.ipv4.ip_local_port_range="1024 65000" \
    --sysctl net.core.somaxconn=4096 \
    -e HOST_CPU="$HOST_CPU" -e HOST_OS="$HOST_OS" \
    -e DURATION -e WARMUP -e REPS -e SERVER_CPUS -e CLIENT_CPUS -e LOOPS \
    -e ECHO_CONNS -e PACED_CONNS -e PACED_RATES -e CHAT_MEMBERS -e IDLE_CONNS -e IDLE_HOLD \
    --entrypoint /usr/local/bin/run-wsbench \
    "$IMAGE"
