# attack_thermal.py
import requests

TARGET_URL = "http://127.0.0.1:8000/api/v1/simulate-attack"

def launch_thermal_attack(station_id: str):
    payload = {
        "station_id": station_id,
        "attack_type": "THERMAL_RUNAWAY"
    }
    print(f"[*] Injecting THERMAL_RUNAWAY payload into {station_id}...")
    
    response = requests.post(TARGET_URL, params=payload)
    if response.status_code == 200:
        data = response.json()
        print("[+] Attack Injected Successfully!")
        print(f"    - Health Status: {data.get('health_status')}")
        print(f"    - Risk Score:    {data.get('risk_score')}")
        print(f"    - Anomaly Flags: {data.get('anomaly_flags')}")
    else:
        print(f"[-] Failed with status code {response.status_code}: {response.text}")

if __name__ == "__main__":
    launch_thermal_attack("EVSE-BETA-02")