#!/bin/sh
# Capture a failed guest graph before the session wrapper releases its services.
set -eu
trap 'pw-dump > /tmp/magicdesk-audio-graph.json 2>/dev/null || :' EXIT
timeout 5 paplay --raw --format=float32le --rate=48000 --channels=2 --latency-msec=30
