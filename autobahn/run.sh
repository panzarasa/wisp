#!/bin/sh
# Runs the Autobahn TestSuite (fuzzingclient mode), the reference conformance
# test for RFC 6455, against the /ws/echo endpoint of cmd/server.
#
#   autobahn/run.sh        a few minutes; needs Docker ("colima start")
#
# The server runs inside the Autobahn container, next to the test client,
# with permessage-deflate enabled, which cases 12.* and 13.* test. The HTML
# report ends up in autobahn/reports/index.html.
set -eu

cd "$(dirname "$0")/.."

# The Autobahn image exists only for amd64.
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o autobahn/bin/server ./cmd/server
rm -rf autobahn/reports
mkdir -p autobahn/reports

docker run --rm --platform linux/amd64 \
    -v "$PWD/autobahn:/autobahn" \
    --entrypoint sh crossbario/autobahn-testsuite -c '
        /autobahn/bin/server -addr 127.0.0.1:9001 -loops 2 -ws-max-message 33554432 \
            > /autobahn/reports/server.log 2>&1 &
        sleep 1
        wstest -m fuzzingclient -s /autobahn/fuzzingclient.json > /autobahn/reports/wstest.log 2>&1'

# Summary: how many cases ended with each outcome, and the ones that failed.
python3 - autobahn/reports/index.json <<'PY'
import json, sys, collections
report = json.load(open(sys.argv[1]))
for agent, cases in report.items():
    counts = collections.Counter(c["behavior"] for c in cases.values())
    print(agent + ": " + ", ".join(f"{n} {b}" for b, n in sorted(counts.items())))
    for case, c in sorted(cases.items(), key=lambda kv: [int(x) for x in kv[0].split(".")]):
        if c["behavior"] not in ("OK", "INFORMATIONAL") or c["behaviorClose"] not in ("OK", "INFORMATIONAL"):
            print(f"  {case}: {c['behavior']} (close: {c['behaviorClose']})")
PY
echo "report: autobahn/reports/index.html"
