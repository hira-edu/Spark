#!/bin/bash

# Rocket C2 Framework - Complete Rebuild Script
# This script rebuilds the frontend, regenerates statik embeddings, compiles the server, and restarts it

set -e  # Exit on any error

echo "================================"
echo "Rocket C2 Framework Rebuild"
echo "================================"

# Step 1: Build Frontend
echo ""
echo "Step 1: Building frontend..."
cd /root/Rocket/web
NODE_ENV=production npx webpack --mode production
if [ $? -eq 0 ]; then
    echo "✓ Frontend build successful"
    ls -lh /root/Rocket/web/dist/index.html
else
    echo "✗ Frontend build failed"
    exit 1
fi

# Step 2: Regenerate Statik Embeddings
echo ""
echo "Step 2: Regenerating statik embeddings..."
cd /root/Rocket
~/go/bin/statik -src=./web/dist -dest=./server/embed -f -ns=web -p=web
if [ $? -eq 0 ]; then
    echo "✓ Statik embeddings generated"
    ls -lh /root/Rocket/server/embed/web/statik.go
else
    echo "✗ Statik generation failed"
    exit 1
fi

# Step 3: Build Server
echo ""
echo "Step 3: Building Go server..."
cd /root/Rocket
COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "dev")
echo "Git commit: $COMMIT"
CGO_ENABLED=0 go build -ldflags "-s -w -X 'Rocket/server/config.Commit=$COMMIT'" -tags=jsoniter -o ./rocket-server Rocket/server
if [ $? -eq 0 ]; then
    echo "✓ Server build successful"
    ls -lh /root/Rocket/rocket-server
else
    echo "✗ Server build failed"
    exit 1
fi

# Step 4: Stop Current Server
echo ""
echo "Step 4: Stopping current server..."
ps aux | grep rocket-server | grep -v grep
pkill -f rocket-server || true
sleep 2
if ps aux | grep rocket-server | grep -v grep > /dev/null; then
    echo "⚠ Server still running, force killing..."
    pkill -9 -f rocket-server || true
    sleep 1
fi
echo "✓ Server stopped"

# Step 5: Start New Server
echo ""
echo "Step 5: Starting new server..."
cd /root/Rocket
nohup ./rocket-server > /tmp/rocket-server.log 2>&1 &
SERVER_PID=$!
echo "Server started with PID: $SERVER_PID"

# Step 6: Verify Server is Running
echo ""
echo "Step 6: Verifying server status..."
sleep 3
if ps -p $SERVER_PID > /dev/null; then
    echo "✓ Server is running"
    ps aux | grep rocket-server | grep -v grep
    echo ""
    echo "================================"
    echo "Rebuild Complete!"
    echo "================================"
    echo "Server PID: $SERVER_PID"
    echo "Log file: /tmp/rocket-server.log"
    echo ""
    echo "Recent logs:"
    tail -20 /tmp/rocket-server.log
else
    echo "✗ Server failed to start"
    echo "Check logs at /tmp/rocket-server.log"
    tail -50 /tmp/rocket-server.log
    exit 1
fi
