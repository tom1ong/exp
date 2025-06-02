#!/bin/bash

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
read

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

# Clean up
echo ""
echo "Stopping server..."
kill $SERVER_PID

echo "Test completed!" 