#!/bin/bash
set -euo pipefail

echo "HTTP Latency Monitor Test Script"
echo "================================"
echo ""
echo "This script will:"
echo "1. Start the HTTP server"
echo "2. Wait for it to be ready"
echo "3. Make some test requests"
echo ""
echo "Please run the monitor in another terminal with:"
echo "  make run-monitor"
echo "  (or if that fails with sudo issues: make build-monitor && sudo ./monitor)"
echo ""
echo "Press Enter to continue..."
read -r -p "Press Enter to continue..." _

# Build the server if not already built
if [ ! -f "./server" ]; then
    echo "Building server..."
    make build
fi

# Start the server
echo "Starting HTTP server..."
./server &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Make test requests
echo ""
echo "Making test requests..."
for i in {1..10}; do
    echo "Request $i:"
    curl -s http://localhost:8080
    sleep 1
done

# Build the monitor if missing
if [ ! -f "./monitor" ]; then
    echo "Building monitor (requires Go & clang)..."
    make build-monitor
fi

# Start the monitor (sudo) and capture its output
MONITOR_LOG=$(mktemp /tmp/monitor_output.XXXXXX)
echo "Starting eBPF monitor (sudo)..."
sudo ./monitor >"$MONITOR_LOG" 2>&1 &
MON_PID=$!

# Give the monitor a moment to load
sleep 1

# Clean up
echo ""
echo "Stopping server..."
kill $SERVER_PID

echo "Stopping monitor..."
sudo kill $MON_PID
wait $MON_PID 2>/dev/null || true

echo ""
echo "========== eBPF Monitor Output =========="
cat "$MONITOR_LOG"
rm "$MONITOR_LOG"

echo "Test completed!" 