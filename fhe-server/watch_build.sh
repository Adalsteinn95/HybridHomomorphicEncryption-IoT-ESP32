#!/bin/bash
set -e

# Step 1: Initial build (if needed)
if [ ! -d "build" ]; then
    mkdir build
fi
cd build
cmake .. && make -j$(nproc)
cd ..

# Function to start the MQTT client in the background.
run_client() {
    echo "Starting MQTT client..."
    ./build/mqtt_client &
    CLIENT_PID=$!
}

# Start the client for the first time.
run_client

# Step 2: Watch for changes in the src/ directory and rebuild/restart client when changes occur.
echo "Watching for changes in the src/ directory..."
while inotifywait -r -e modify,create,delete src; do
    echo "Changes detected. Rebuilding..."
    # Kill the currently running client.
    kill $CLIENT_PID || true

    # Rebuild the project.
    cd build && make -j$(nproc) && cd ..

    # Restart the MQTT client.
    run_client
    echo "Rebuild complete and client restarted."
done
