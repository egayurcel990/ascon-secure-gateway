#!/usr/bin/env bash
set -euo pipefail

mkdir -p captures
OUTPUT="${1:-captures/ascon-demo.pcap}"

echo "Capturing TCP traffic on port 8000 to: $OUTPUT"
echo "Run 'cd client && python3 demo.py' in another terminal."
echo "Stop capture with Ctrl+C."

sudo tcpdump -i any port 8000 -w "$OUTPUT"
