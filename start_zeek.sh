#!/bin/bash
set -e

cd /home/taki/AnomalySpike

if pgrep -f "zeek -i" > /dev/null; then
    echo "Zeek is already running. Skipping start."
    exit 0
fi


CONFIG="/home/taki/AnomalySpike/config/monitoring.json"

INTERFACE=$(python3 -c '
import json
with open("'"$CONFIG"'") as f:
    print(json.load(f)["interface"])
')

echo "Starting Zeek on interface: $INTERFACE"

exec sudo /opt/zeek/bin/zeek \
    -i "$INTERFACE" \
    /home/taki/AnomalySpike/config/zeek/anomalyspike.zeek
