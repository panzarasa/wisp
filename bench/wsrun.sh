#!/bin/sh
# WebSocket benchmarks: runs inside the benchmark image (see Dockerfile), like
# run.sh does for HTTP; wsbench.sh is the host side.
#
# Two servers with the same endpoints: "wisp" is cmd/server (httpd on gnet,
# one event loop), "gorilla" is bench/rivals/gorilla (gorilla/websocket on
# net/http). Each run starts a fresh server pinned to SERVER_CPUS, loads it
# with wsload pinned to CLIENT_CPUS over the loopback interface, and stops it.
#
#   echo   request/response with 128-byte binary messages, at ECHO_CONNS
#          connections; then 64 connections with 16 messages in flight each,
#          and 64 connections with 16 KiB messages
#   paced  the same echo at a fixed pace (PACED_RATES messages per second
#          over PACED_CONNS connections), sent evenly by one busy-waiting
#          pacer. Request/response gives the faster server more load, so its
#          latencies do not compare; these do
#   chat   one publisher, every 64-byte message to CHAT_MEMBERS members
#   idle   IDLE_CONNS connections that exchanged one message: server memory
#          per connection and CPU spent on idle connections
#
# Output in $OUT: results.jsonl (one line per run, see cmd/wsload), summary.txt
# (medians), meta.env.
set -eu

OUT=${OUT:-/out}
DURATION=${DURATION:-10s}
WARMUP=${WARMUP:-2s}
REPS=${REPS:-3}
SERVER_CPUS=${SERVER_CPUS:-0}
CLIENT_CPUS=${CLIENT_CPUS:-1-3}
LOOPS=${LOOPS:-1}
ECHO_CONNS=${ECHO_CONNS:-16 64 256 1024}
PACED_CONNS=${PACED_CONNS:-64 256}
PACED_RATES=${PACED_RATES:-100000 300000}
CHAT_MEMBERS=${CHAT_MEMBERS:-100 1000 5000}
IDLE_CONNS=${IDLE_CONNS:-1000 10000 50000}
IDLE_HOLD=${IDLE_HOLD:-5s}

ADDR=127.0.0.1:8080

mkdir -p "$OUT"
: > "$OUT/results.jsonl"

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
    echo "SERVER_CPUS=$SERVER_CPUS"
    echo "CLIENT_CPUS=$CLIENT_CPUS"
    echo "LOOPS=$LOOPS"
    echo "ECHO_CONNS=$ECHO_CONNS"
    echo "PACED_CONNS=$PACED_CONNS"
    echo "PACED_RATES=$PACED_RATES"
    echo "CHAT_MEMBERS=$CHAT_MEMBERS"
    echo "IDLE_CONNS=$IDLE_CONNS"
    echo "IDLE_HOLD=$IDLE_HOLD"
} > "$OUT/meta.env"

# measure TARGET REP WSLOAD_ARGS...
measure() {
    target=$1 rep=$2
    shift 2
    case $target in
        wisp)    bin=server ;;
        gorilla) bin=gorilla ;;
    esac

    taskset -c "$SERVER_CPUS" "$bin" -addr "$ADDR" -loops "$LOOPS" > /tmp/server.log 2>&1 &
    pid=$!
    until nc -z 127.0.0.1 8080 2>/dev/null; do
        kill -0 "$pid" 2>/dev/null || { cat /tmp/server.log; exit 1; }
        sleep 0.1
    done

    if ! taskset -c "$CLIENT_CPUS" wsload -addr "$ADDR" -target "$target" -rep "$rep" \
        -server-pid "$pid" -d "$DURATION" -warmup "$WARMUP" "$@" >> "$OUT/results.jsonl"; then
        echo "  ^ failed: $target $*" >&2
        cat /tmp/server.log >&2
    fi

    kill "$pid"
    wait "$pid" 2>/dev/null || true
}

for rep in $(seq "$REPS"); do
    echo "--- repetition $rep of $REPS"
    # Alternate which server goes first, so slow drift of the machine does
    # not favour one of them.
    if [ $((rep % 2)) -eq 1 ]; then order="wisp gorilla"; else order="gorilla wisp"; fi

    for conns in $ECHO_CONNS; do
        for t in $order; do measure "$t" "$rep" -mode echo -conns "$conns" -size 128; done
    done
    for t in $order; do measure "$t" "$rep" -mode echo -conns 64 -size 128 -pipeline 16; done
    for t in $order; do measure "$t" "$rep" -mode echo -conns 64 -size 16384; done
    for conns in $PACED_CONNS; do
        for rate in $PACED_RATES; do
            for t in $order; do measure "$t" "$rep" -mode echo -conns "$conns" -size 128 -rate "$rate" -pacers 1; done
        done
    done

    for members in $CHAT_MEMBERS; do
        for t in $order; do measure "$t" "$rep" -mode chat -conns "$members" -size 64 -window 16; done
    done

    # -d is the idle time here; four source addresses, for the ports.
    for conns in $IDLE_CONNS; do
        for t in $order; do measure "$t" "$rep" -mode idle -conns "$conns" -d "$IDLE_HOLD" -src-ips 4; done
    done
done

wsload -summary "$OUT/results.jsonl" | tee "$OUT/summary.txt"
echo "done: results in $OUT"
