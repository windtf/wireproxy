#!/bin/bash
# Cleanup on exit
trap 'kill $(jobs -p) 2>/dev/null' EXIT

echo "Starting Mock Server..."
go run mock_server.go &
MOCK_PID=$!

echo "Starting Wireproxy Server (Remote Peer)..."
./wireproxy -c server.conf &
SERVER_PID=$!

echo "Starting Wireproxy Client (Local Peer)..."
./wireproxy -c client.conf &
CLIENT_PID=$!

echo "Starting Test Client..."
RESPONSE=$(go run test_client.go)
echo "Test Result: $RESPONSE"

if [[ "$RESPONSE" == *"PONG"* ]]; then
    echo "SUCCESS: Integration test passed!"
    exit 0
else
    echo "FAILURE: Integration test failed."
    exit 1
fi
