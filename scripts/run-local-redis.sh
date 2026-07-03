#!/usr/bin/env bash
# Local Redis for development (`make local-redis`, D3: standalone Redis).
#
# Default: `docker run --rm --name cloudflow-redis -p <port>:6379 redis:7` in
# the foreground (Ctrl-C stops it). `--stop` stops it from another shell.
#
# No-docker fallback: if `docker` is not on PATH (or the daemon is not
# reachable), spawns a local `redis-server --port <port> --save ''` in the
# foreground instead -- this keeps `scripts/run-integration-tests.sh` (which
# needs a Redis without requiring Docker) and plain local dev working on the
# same script/entry point.
set -euo pipefail

CONTAINER_NAME="cloudflow-redis"
PORT="${CF_REDIS_PORT:-6379}"
PIDFILE="${TMPDIR:-/tmp}/cloudflow-local-redis.pid"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--stop] [--port PORT]

Starts a local Redis for CloudFlow development: docker's redis:7 image if
docker is available, otherwise a plain 'redis-server' process (D3:
standalone Redis via hiredis -- no cluster mode needed for two streams).

Runs in the foreground; Ctrl-C stops it. From another shell:

  $(basename "$0") --stop     stop the named container / local redis-server

Options:
  --port PORT   port to listen on (default 6379, or \$CF_REDIS_PORT)
  --stop        stop a previously started instance and exit
  -h, --help    this message
EOF
}

stop_mode=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stop)
            stop_mode=1
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

have_docker() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

if [[ "$stop_mode" -eq 1 ]]; then
    stopped=0
    if have_docker && docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
        echo "stopping docker container '$CONTAINER_NAME'"
        docker stop "$CONTAINER_NAME" >/dev/null
        stopped=1
    fi
    if [[ -f "$PIDFILE" ]]; then
        pid="$(cat "$PIDFILE" 2>/dev/null || true)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "stopping local redis-server (pid $pid)"
            kill "$pid"
            stopped=1
        fi
        rm -f "$PIDFILE"
    fi
    if [[ "$stopped" -eq 0 ]]; then
        echo "no running '$CONTAINER_NAME' found (docker container or local redis-server)" >&2
    fi
    exit 0
fi

if have_docker; then
    echo "starting redis:7 in docker (container: $CONTAINER_NAME, port: $PORT)"
    exec docker run --rm --name "$CONTAINER_NAME" -p "${PORT}:6379" redis:7
fi

echo "docker not available -- falling back to a local redis-server process" >&2
if ! command -v redis-server >/dev/null 2>&1; then
    echo "error: neither docker nor redis-server is available on PATH" >&2
    exit 1
fi

echo "$$" > "$PIDFILE"
echo "starting local redis-server on 127.0.0.1:$PORT (pidfile: $PIDFILE)"
exec redis-server --port "$PORT" --save ''
