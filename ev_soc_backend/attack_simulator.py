import random
import time
import requests

TARGET_URL = "http://127.0.0.1:8000/api/v1/telemetry"


def simulate_dos_flooding(attacker_ip="192.168.1.105"):
  """Simulates a high-frequency telemetry flood (DoS) to exhaust system resources."""
  print(f"[!] Starting DoS Flooding attack simulation from {attacker_ip}...")

  headers = {
      "Content-Type": "application/json",
      "X-Forwarded-For": attacker_ip,  # Simulates target client IP
  }

  for i in range(100):
    payload = {
        "bus_voltage_v": 230.0,
        "line_current_a": 15.0,
        "active_power_kw": 3.45,
        "temperature_c": 42.0,
        "cpu_utilization_pct": 98.5,  # Anomaly: CPU spiked
        "free_heap_bytes": 1200,  # Anomaly: Low free heap
        "failed_auth_attempts": 0,
        "packet_retransmission_pct": 25.4,  # Anomaly: High packet drop
    }

    try:
      resp = requests.post(
          TARGET_URL, json=payload, headers=headers, timeout=1
      )
      print(f"[{i+1}/100] Sent flood payload | Status: {resp.status_code}")
    except requests.exceptions.RequestException as e:
      print(f"[{i+1}/100] Connection blocked or dropped: {e}")

    time.sleep(0.02)  # Burst traffic (~50 req/sec)


def simulate_unauthorized_access(attacker_ip="192.168.1.108"):
  """Simulates brute-force authentication attempts."""
  print(
      f"\n[!] Starting Unauthorized Access attack simulation from"
      f" {attacker_ip}..."
  )

  headers = {"X-Forwarded-For": attacker_ip}

  for i in range(15):
    payload = {
        "bus_voltage_v": 230.0,
        "line_current_a": 0.0,
        "active_power_kw": 0.0,
        "temperature_c": 35.0,
        "cpu_utilization_pct": 12.0,
        "free_heap_bytes": 28000,
        "failed_auth_attempts": i + 1,  # Rapidly increasing failed auth count
        "packet_retransmission_pct": 1.0,
    }

    resp = requests.post(TARGET_URL, json=payload, headers=headers)
    print(f"Auth Attempt {i+1} | Status: {resp.status_code}")
    time.sleep(0.1)


if __name__ == "__main__":
  simulate_dos_flooding()
  time.sleep(2)
  simulate_unauthorized_access()