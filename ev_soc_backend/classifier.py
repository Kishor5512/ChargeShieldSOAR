from typing import Any, Dict, Tuple


class TelemetryThreatClassifier:
  """Independent heuristic scoring engine that analyzes EV telemetry metrics

  and determines the most likely security threat vector without relying
  on explicit attack payload flags.
  """

  @staticmethod
  def classify(data: Any) -> Tuple[str | None, float, float]:
    scores = {
        "BRUTE_FORCE": 0.0,
        "INJECTION": 0.0,
        "ANOMALOUS_TELEMETRY": 0.0,
        "DOS_FLOODING": 0.0,
    }

    # 1. Evaluate BRUTE FORCE indicators
    if data.failed_auth_attempts >= 20:
      scores["BRUTE_FORCE"] += 0.85
      if data.line_current_a < 1.0:  # Idle line current during auth spam
        scores["BRUTE_FORCE"] += 0.15

    # 2. Evaluate INJECTION / DATA TAMPERING indicators
    if data.bus_voltage_v >= 450.0:
      scores["INJECTION"] += 0.60
    if data.payload_frame_bytes >= 4000:
      scores["INJECTION"] += 0.40

    # 3. Evaluate ANOMALOUS TELEMETRY (Thermal / Electrical drift) indicators
    if data.temperature_c >= 80.0:
      scores["ANOMALOUS_TELEMETRY"] += 0.50
    if data.voltage_std_dev_5s >= 6.0:
      scores["ANOMALOUS_TELEMETRY"] += 0.50

    # 4. Evaluate DOS FLOODING indicators
    if data.cpu_utilization_pct >= 95.0:
      scores["DOS_FLOODING"] += 0.50
    if data.packet_iat_mean_ms <= 1.5:
      scores["DOS_FLOODING"] += 0.50

    # Find the attack type with the highest confidence score
    best_threat = max(scores, key=scores.get)
    max_score = scores[best_threat]

    # Threshold for considering an anomaly detected
    if max_score < 0.70:
      return None, 0.0, 0.0  # Normal traffic or low confidence

    # Map to confidence and risk scores based on detected vector
    if best_threat == "DOS_FLOODING":
      return "DOS_FLOODING", 0.98, 91.5
    elif best_threat == "INJECTION":
      return "INJECTION", 0.92, 88.0
    elif best_threat == "BRUTE_FORCE":
      return "BRUTE_FORCE", 0.95, 82.0
    elif best_threat == "ANOMALOUS_TELEMETRY":
      return "ANOMALOUS_TELEMETRY", 0.89, 79.0

    return None, 0.0, 0.0