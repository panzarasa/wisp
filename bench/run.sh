#!/bin/sh
# HTTP benchmarks: runs inside the benchmark image (see Dockerfile);
# bench.sh is the host side.
#
# TARGETS are the servers, by binary name: server (wisp), fiber, fasthttp and
# baseline (gnet alone, which only answers "GET /"). All serve the same
# routes with the same responses:
#
#   hello  GET /                 at each of CONNS connections
#   param  GET /users/42         at EXTRA_CONNS connections
#   echo   POST /echo, BODY_BYTES at EXTRA_CONNS connections
#
# Each run starts one server pinned to SERVER_CPUS, warms it up, loads it with
# bombardier pinned to CLIENT_CPUS over the loopback interface, and stops it.
# Server and load generator never share a core, and there is no Docker
# networking between them.
#
# Output in $OUT:
#   raw/<target>_<scenario>_c<conns>_r<rep>.json   bombardier's JSON report
#   usage.csv                                      CPU time and peak RSS per run
#   meta.env                                       environment and parameters
set -eu

OUT=${OUT:-/out}
DURATION=${DURATION:-10s}
WARMUP=${WARMUP:-3s}
REPS=${REPS:-5}
TARGETS=${TARGETS:-server fiber fasthttp}
CONNS=${CONNS:-16 64 256 1024}
EXTRA_CONNS=${EXTRA_CONNS-256}
SERVER_CPUS=${SERVER_CPUS:-0}
CLIENT_CPUS=${CLIENT_CPUS:-1-3}
LOOPS=${LOOPS:-1}
BODY_BYTES=${BODY_BYTES:-1024}

ADDR=127.0.0.1:8080
BODY_FILE=/tmp/body.bin

rm -rf "$OUT/raw"
mkdir -p "$OUT/raw"
yes 0123456789abcdef | tr -d '\n' | head -c "$BODY_BYTES" > "$BODY_FILE"

{
    cat /etc/bench-build.env
    echo "DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "KERNEL=$(uname -r)"
    echo "ARCH=$(uname -m)"
    echo "ALPINE=$(cat /etc/alpine-release)"
    echo "VM_CPUS=$(nproc)"
    echo "VM_MEM_KB=$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    echo "HOST_CPU=${HOST_CPU:-}"
    echo "HOST_OS=${HOST_OS:-}"
    echo "DURATION=$DURATION"
    echo "WARMUP=$WARMUP"
    echo "REPS=$REPS"
    echo "TARGETS=$TARGETS"
    echo "CONNS=$CONNS"
    echo "EXTRA_CONNS=$EXTRA_CONNS"
    echo "SERVER_CPUS=$SERVER_CPUS"
    echo "CLIENT_CPUS=$CLIENT_CPUS"
    echo "LOOPS=$LOOPS"
    echo "BODY_BYTES=$BODY_BYTES"
} > "$OUT/meta.env"

echo "target,scenario,conns,rep,server_cpu_ticks,server_peak_rss_kb,client_cpu_seconds" > "$OUT/usage.csv"

# cpu_ticks PID: user + system CPU time in clock ticks (1/100 s).
cpu_ticks() {
    awk '{print $14 + $15}' "/proc/$1/stat"
}

# load DURATION CONNS SCENARIO: runs bombardier, JSON report on stdout.
load() {
    case $3 in
        hello) set -- "$1" "$2" "http://$ADDR/" ;;
        param) set -- "$1" "$2" "http://$ADDR/users/42" ;;
        echo)  set -- "$1" "$2" -m POST -f "$BODY_FILE" -H "Content-Type: application/octet-stream" "http://$ADDR/echo" ;;
    esac
    load_duration=$1 load_conns=$2
    shift 2
    taskset -c "$CLIENT_CPUS" bombardier -c "$load_conns" -d "$load_duration" -l -p r -o json "$@"
}

# run TARGET SCENARIO CONNS REP
run() {
    target=$1 scenario=$2 conns=$3 rep=$4

    taskset -c "$SERVER_CPUS" "$target" -addr "$ADDR" -loops "$LOOPS" > /tmp/server.log 2>&1 &
    pid=$!
    until nc -z 127.0.0.1 8080 2>/dev/null; do
        kill -0 "$pid" 2>/dev/null || { cat /tmp/server.log; exit 1; }
        sleep 0.1
    done

    load "$WARMUP" "$conns" "$scenario" > /dev/null

    before=$(cpu_ticks "$pid")
    # The shell's `times` gives the CPU time of its children: here, bombardier.
    client=$( (load "$DURATION" "$conns" "$scenario" > "$OUT/raw/${target}_${scenario}_c${conns}_r${rep}.json"; times) | awk 'NR == 2 {
        split($1, u, /[ms]/); split($2, s, /[ms]/); print u[1] * 60 + u[2] + s[1] * 60 + s[2] }')
    after=$(cpu_ticks "$pid")
    rss=$(awk '/VmHWM/ {print $2}' "/proc/$pid/status")

    kill "$pid"
    wait "$pid" 2>/dev/null || true

    echo "$target,$scenario,$conns,$rep,$((after - before)),$rss,$client" >> "$OUT/usage.csv"
    printf '%-9s %-6s c=%-5s rep %s  %8.0f req/s\n' "$target" "$scenario" "$conns" "$rep" \
        "$(sed -E 's/.*"timeTakenSeconds":([0-9.]+).*"req2xx":([0-9]+).*/\2 \1/' "$OUT/raw/${target}_${scenario}_c${conns}_r${rep}.json" | awk '{print $1 / $2}')"
}

for rep in $(seq "$REPS"); do
    # Every other repetition the servers go in reverse order, so slow drift
    # of the machine does not favour one of them.
    order=$TARGETS
    if [ $((rep % 2)) -eq 0 ]; then order=$(echo "$TARGETS" | tr ' ' '\n' | sed '1!G;h;$!d' | tr '\n' ' '); fi

    for conns in $CONNS; do
        for target in $order; do
            run "$target" hello "$conns" "$rep"
        done
    done

    # Routes gnet alone does not have.
    for conns in $EXTRA_CONNS; do
        for scenario in param echo; do
            for target in $order; do
                [ "$target" = baseline ] || run "$target" "$scenario" "$conns" "$rep"
            done
        done
    done
done

echo "done: results in $OUT"
