#!/usr/bin/env python3
"""
ChargeShield-SOAR Live Demonstration Launcher
Sends schema-compliant telemetry payloads to match Pydantic model specs.
"""

import time
import requests
import sys

TARGET_URL = "http://10.233.163.253:8000/api/v1/telemetry"

def get_base_telemetry():
    """Returns a full baseline dictionary matching Pydantic validation requirements."""
    return {
        "device_id": "ESP32_EVSE_NODE_01",
        "client_ip": "10.233.163.253",
        "bus_voltage_v": 230.0,
        "line_current_a": 16.0,
        "active_power_kw": 3.68,
        "temperature_c": 35.0,
        "cpu_utilization_pct": 25.0,
        "packet_iat_mean_ms": 100.0,
        "payload_frame_bytes": 128,
        "failed_auth_attempts": 0,
        "voltage_std_dev_5s": 0.5
    }

def send_payload(payload):
    try:
        response = requests.post(TARGET_URL, json=payload, timeout=2)
        if response.status_code == 200:
            print(f"[>] Telemetry Accepted (200 OK) | Payload: {payload['client_ip']}")
        else:
            print(f"[!] Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[!] Connection Error: {e}")

def simulate_dos_attack():
    print("\n[=== LAUNCHING DOS FLOODING ATTACK ===]")
    for _ in range(15):
        payload = get_base_telemetry()
        payload.update({
            "cpu_utilization_pct": 98.0,  # CPU Spike > 90%
            "packet_iat_mean_ms": 2.1      # Low inter-arrival time
        })
        send_payload(payload)
        time.sleep(0.1)

def simulate_payload_injection():
    print("\n[=== LAUNCHING PAYLOAD INJECTION ATTACK ===]")
    for _ in range(5):
        payload = get_base_telemetry()
        payload.update({
            "bus_voltage_v": 480.0,        # Voltage Anomaly > 400V
            "line_current_a": 80.0,
            "active_power_kw": 38.4,
            "payload_frame_bytes": 2500    # Oversized Frame (> 2000 Bytes)
        })
        send_payload(payload)
        time.sleep(0.3)

def simulate_brute_force():
    print("\n[=== LAUNCHING BRUTE FORCE ATTACK ===]")
    for attempt in range(1, 12):
        payload = get_base_telemetry()
        payload.update({
            "failed_auth_attempts": attempt # Trigger threshold >= 10
        })
        send_payload(payload)
        time.sleep(0.2)

def main():
    while True:
        print("\n=============================================")
        print("   ChargeShield-SOAR Live Attack Console     ")
        print("=============================================")
        print("1. Launch DoS Flooding Attack")
        print("2. Launch Malformed Payload Injection Attack")
        print("3. Launch Brute Force Authentication Attack")
        print("4. Exit")
        
        choice = input("\nSelect attack scenario [1-4]: ").strip()
        
        if choice == "1":
            simulate_dos_attack()
        elif choice == "2":
            simulate_payload_injection()
        elif choice == "3":
            simulate_brute_force()
        elif choice == "4":
            sys.exit(0)

if __name__ == "__main__":
    main()