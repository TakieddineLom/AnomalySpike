#!/bin/bash
set -e

CONFIG="/home/taki/AnomalyStrike/config/monitoring.json"

INTERFACE=$(python3 -c '
import json
with open("'"$CONFIG"'") as f:
    print(json.load(f)["interface"])
')

echo "Starting Suricata on interface: $INTERFACE"

exec /usr/bin/suricata \
    --af-packet="$INTERFACE" \
    -c /etc/suricata/suricata.yaml \
    --pidfile /run/suricata.pid
