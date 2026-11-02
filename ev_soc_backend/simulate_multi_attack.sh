#!/usr/bin/env bash

API_URL="http://127.0.0.1:8000/api/v1"

echo "=========================================================="
echo "[+] Starting Concurrent Attack Injections (3 Stations)"
echo "=========================================================="

# Strictly 3 active stations
declare -A ATTACK_MAP=(
  ["EVSE-ALPHA-01"]="BRUTE_FORCE|HIGH|192.168.1.100"
  ["EVSE-BETA-02"]="THERMAL_RUNAWAY|CRITICAL|10.0.4.15"
  ["EVSE-GAMMA-03"]="DOS_FLOOD|HIGH|172.16.0.44"
)

inject_attack() {
  local station_id="$1"
  local attack_type="$2"
  local severity="$3"
  local source_ip="$4"

  echo "[*] Triggering: $attack_type on $station_id ($severity)..."

  curl -s -X POST "$API_URL/inject-attack" \
    -H "Content-Type: application/json" \
    -d '{
      "station_id": "'"$station_id"'",
      "attack_type": "'"$attack_type"'",
      "severity": "'"$severity"'",
      "source_ip": "'"$source_ip"'",
      "intensity": 1.0
    }' | jq -c '{station: .incident.station_id, attack: .incident.title, status: .status}' &
}

for station in "${!ATTACK_MAP[@]}"; do
  IFS='|' read -r attack severity ip <<< "${ATTACK_MAP[$station]}"
  inject_attack "$station" "$attack" "$severity" "$ip"
done

wait

echo "=========================================================="
echo "[+] Concurrent Attack Injection Completed."
echo "=========================================================="