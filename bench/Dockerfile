# Benchmark image: Alpine with the load generators (bombardier for HTTP,
# wsload for WebSocket) and the servers under test: wisp (cmd/server), gnet
# alone (cmd/baseline) and the rivals of bench/rivals (fiber, fasthttp,
# gorilla).
# Build from the repository root:  docker build -f bench/Dockerfile -t wisp-bench .

FROM golang:1.26-alpine AS build

ENV CGO_ENABLED=0

# bombardier first: it only changes when its version does.
ARG BOMBARDIER_VERSION=v1.2.6
RUN GOBIN=/out go install github.com/codesenberg/bombardier@${BOMBARDIER_VERSION}

WORKDIR /src
COPY go.mod go.sum ./
COPY bench/rivals/go.mod bench/rivals/go.sum bench/rivals/
RUN go mod download && cd bench/rivals && go mod download
COPY . .
RUN go build -trimpath -o /out/baseline ./cmd/baseline \
 && go build -trimpath -o /out/server ./cmd/server \
 && go build -trimpath -o /out/wsload ./cmd/wsload \
 && cd bench/rivals \
 && go build -trimpath -o /out/fiber ./fiber \
 && go build -trimpath -o /out/fasthttp ./fasthttp \
 && go build -trimpath -o /out/gorilla ./gorilla

RUN { \
      echo "GO_VERSION=$(go env GOVERSION)"; \
      echo "GNET_VERSION=$(go list -m -f '{{.Version}}' github.com/panjf2000/gnet/v2)"; \
      echo "BOMBARDIER_VERSION=${BOMBARDIER_VERSION}"; \
      cd bench/rivals; \
      echo "FIBER_VERSION=$(go list -m -f '{{.Version}}' github.com/gofiber/fiber/v3)"; \
      echo "FASTHTTP_VERSION=$(go list -m -f '{{.Version}}' github.com/valyala/fasthttp)"; \
      echo "GORILLA_VERSION=$(go list -m -f '{{.Version}}' github.com/gorilla/websocket)"; \
    } > /out/build.env

FROM alpine:3.22

# taskset, to keep server and load generator on separate cores.
RUN apk add --no-cache util-linux-misc

COPY --from=build /out/baseline /out/server /out/bombardier /out/wsload \
     /out/fiber /out/fasthttp /out/gorilla /usr/local/bin/
COPY --from=build /out/build.env /etc/bench-build.env
COPY bench/run.sh /usr/local/bin/run-bench
COPY bench/wsrun.sh /usr/local/bin/run-wsbench

VOLUME /out
ENTRYPOINT ["/usr/local/bin/run-bench"]
