#!/usr/bin/env bash
set -euo pipefail

docker run --rm -p 6379:6379 redis:7
