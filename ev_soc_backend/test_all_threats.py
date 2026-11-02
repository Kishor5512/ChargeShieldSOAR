import json
import time
import requests

API_URL = "http://127.0.0.1:8000/api/v1/telemetry"

TEST_SUITE = {
    "NORMAL_BASELINE": {
        "bus_voltage_v": 230.0,
        "line_current_a": 16.0,
        "active_power_kw": 3.68,
        "temperature_c": 30.0,
        "cpu_utilization_pct": 18.0,
        "free_heap_bytes": 120000,
        "context_switch_rate": 200,
        "round_trip_time_ms": 25.0,
        "failed_auth_attempts": 0,
        "packet_retransmission_pct": 0.2,
        "payload_frame_bytes": 300,
        "voltage_std_dev_5s": 0.2,
        "power_gradient_kw_sec": 0.05,
        "packet_iat_mean_ms": 50.0,
        "historical_spike_index": 0,
    },
    "DOS_FLOODING (Class 1)": {
        "bus_voltage_v": 230.0,
        "line_current_a": 16.0,
        "active_power_kw": 3.68,
        "temperature_c": 35.0,
        "cpu_utilization_pct": 98.5,
        "free_heap_bytes": 1200,
        "context_switch_rate": 8500,
        "round_trip_time_ms": 450.0,
        "failed_auth_attempts": 25,
        "packet_retransmission_pct": 78.4,
        "payload_frame_bytes": 1480,
        "voltage_std_dev_5s": 0.3,
        "power_gradient_kw_sec": 0.08,
        "packet_iat_mean_ms": 0.1,
        "historical_spike_index": 1,
    },
    "UNAUTHORIZED_ACCESS (Class 2)": {
        "bus_voltage_v": 230.0,
        "line_current_a": 16.0,
        "active_power_kw": 3.68,
        "temperature_c": 32.0,
        "cpu_utilization_pct": 55.0,
        "free_heap_bytes": 105000,
        "context_switch_rate": 800,
        "round_trip_time_ms": 180.0,
        "failed_auth_attempts": 42,
        "packet_retransmission_pct": 12.5,
        "payload_frame_bytes": 180,
        "voltage_std_dev_5s": 0.15,
        "power_gradient_kw_sec": 0.02,
        "packet_iat_mean_ms": 320.0,
        "historical_spike_index": 0,
    },
    "DATA_TAMPERING (Class 3)": {
        "bus_voltage_v": 480.0,
        "line_current_a": 0.0,
        "active_power_kw": 22.5,
        "temperature_c": 28.0,
        "cpu_utilization_pct": 22.0,
        "free_heap_bytes": 118000,
        "context_switch_rate": 310,
        "round_trip_time_ms": 35.0,
        "failed_auth_attempts": 0,
        "packet_retransmission_pct": 1.2,
        "payload_frame_bytes": 1250,
        "voltage_std_dev_5s": 8.50,
        "power_gradient_kw_sec": 5.20,
        "packet_iat_mean_ms": 85.0,
        "historical_spike_index": 1,
    },
    "RECON_SCANNING (Class 4)": {
        "bus_voltage_v": 230.0,
        "line_current_a": 16.0,
        "active_power_kw": 3.68,
        "temperature_c": 30.0,
        "cpu_utilization_pct": 78.0,
        "free_heap_bytes": 95000,
        "context_switch_rate": 4500,
        "round_trip_time_ms": 12.0,
        "failed_auth_attempts": 3,
        "packet_retransmission_pct": 4.5,
        "payload_frame_bytes": 64,
        "voltage_std_dev_5s": 0.2,
        "power_gradient_kw_sec": 0.01,
        "packet_iat_mean_ms": 2.5,
        "historical_spike_index": 0,
    },
    "HOST_MALWARE (Class 5)": {
        "bus_voltage_v": 285.0,
        "line_current_a": 65.0,
        "active_power_kw": 18.5,
        "temperature_c": 78.0,
        "cpu_utilization_pct": 99.1,
        "free_heap_bytes": 8500,
        "context_switch_rate": 6200,
        "round_trip_time_ms": 110.0,
        "failed_auth_attempts": 0,
        "packet_retransmission_pct": 18.5,
        "payload_frame_bytes": 512,
        "voltage_std_dev_5s": 24.8,
        "power_gradient_kw_sec": 14.2,
        "packet_iat_mean_ms": 12.0,
        "historical_spike_index": 1,
    },
}


def run_benchmark():
  print(f"{'VECTOR NAME':<32} | {'THREAT':<7} | {'CLASS DETECTED':<22} | {'CONF':<6} | {'RISK'}")
  print("-" * 80)

  for test_label, payload in TEST_SUITE.items():
    try:
      resp = requests.post(API_URL, json=payload, timeout=5)
      if resp.status_code == 200:
        data = resp.json()
        threat = "YES" if data.get("is_threat") else "NO"
        details = data.get("threat_details", {})
        predicted_class = details.get("attack_type", "UNKNOWN")
        confidence = f"{details.get('classification_confidence', 0.0):.2f}"
        risk = data.get("risk_metrics", {}).get("calculated_risk_score", 0.0)

        print(f"{test_label:<32} | {threat:<7} | {predicted_class:<22} | {confidence:<6} | {risk}")
      else:
        print(f"{test_label:<32} | ERROR {resp.status_code}: {resp.text}")
    except Exception as e:
      print(f"{test_label:<32} | CONNECTION FAILED: {str(e)}")
    time.sleep(0.5)


if __name__ == "__main__":
  run_benchmark()





'''|curl -X POST http://127.0.0.1:8000/api/v1/telemetry -H "Content-Type: application/json" -d '{
  "bus_voltage_v": 230.0, "line_current_a": 16.0, "active_power_kw": 3.68, "temperature_c": 35.0,
  "cpu_utilization_pct": 98.5, "free_heap_bytes": 1200, "context_switch_rate": 8500,
  "round_trip_time_ms": 450.0, "failed_auth_attempts": 25, "packet_retransmission_pct": 78.4,
  "payload_frame_bytes": 1480, "voltage_std_dev_5s": 0.3, "power_gradient_kw_sec": 0.08,
  "packet_iat_mean_ms": 0.1, "historical_spike_index": 1
}'


curl -X POST http://127.0.0.1:8000/api/v1/telemetry -H "Content-Type: application/json" -d '{
  "bus_voltage_v": 230.0, "line_current_a": 16.0, "active_power_kw": 3.68, "temperature_c": 32.0,
  "cpu_utilization_pct": 55.0, "free_heap_bytes": 105000, "context_switch_rate": 800,
  "round_trip_time_ms": 180.0, "failed_auth_attempts": 42, "packet_retransmission_pct": 12.5,
  "payload_frame_bytes": 180, "voltage_std_dev_5s": 0.15, "power_gradient_kw_sec": 0.02,
  "packet_iat_mean_ms": 320.0, "historical_spike_index": 0
}'

curl -X POST http://127.0.0.1:8000/api/v1/telemetry -H "Content-Type: application/json" -d '{
  "bus_voltage_v": 480.0, "line_current_a": 0.0, "active_power_kw": 22.5, "temperature_c": 28.0,
  "cpu_utilization_pct": 22.0, "free_heap_bytes": 118000, "context_switch_rate": 310,
  "round_trip_time_ms": 35.0, "failed_auth_attempts": 0, "packet_retransmission_pct": 1.2,
  "payload_frame_bytes": 1250, "voltage_std_dev_5s": 8.50, "power_gradient_kw_sec": 5.20,
  "packet_iat_mean_ms": 85.0, "historical_spike_index": 1
}'


curl -X POST http://127.0.0.1:8000/api/v1/telemetry -H "Content-Type: application/json" -d '{
  "bus_voltage_v": 230.0, "line_current_a": 16.0, "active_power_kw": 3.68, "temperature_c": 30.0,
  "cpu_utilization_pct": 78.0, "free_heap_bytes": 95000, "context_switch_rate": 4500,
  "round_trip_time_ms": 12.0, "failed_auth_attempts": 3, "packet_retransmission_pct": 4.5,
  "payload_frame_bytes": 64, "voltage_std_dev_5s": 0.2, "power_gradient_kw_sec": 0.01,
  "packet_iat_mean_ms": 2.5, "historical_spike_index": 0
}'


curl -X POST http://127.0.0.1:8000/api/v1/telemetry -H "Content-Type: application/json" -d '{
  "bus_voltage_v": 285.0, "line_current_a": 65.0, "active_power_kw": 18.5, "temperature_c": 78.0,
  "cpu_utilization_pct": 99.1, "free_heap_bytes": 8500, "context_switch_rate": 6200,
  "round_trip_time_ms": 110.0, "failed_auth_attempts": 0, "packet_retransmission_pct": 18.5,
  "payload_frame_bytes": 512, "voltage_std_dev_5s": 24.8, "power_gradient_kw_sec": 14.2,
  "packet_iat_mean_ms": 12.0, "historical_spike_index": 1
}'|'''