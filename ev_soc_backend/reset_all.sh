#!/usr/bin/env bash

API_URL="http://127.0.0.1:8000/api/v1"

echo "=========================================================="
echo "[+] Resetting Fleet State Across All 3 Stations"
echo "=========================================================="

for sid in EVSE-ALPHA-01 EVSE-BETA-02 EVSE-GAMMA-03; do
  curl -s -X POST "$API_URL/reset-station?station_id=$sid" &
done; wait

echo ""
echo "=========================================================="
echo "[+] Fleet state successfully restored to HEALTHY."
echo "=========================================================="