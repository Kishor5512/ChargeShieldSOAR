from enum import Enum
from ml_engine import MLAnomalyDetector
from models import HealthStatus, RiskScoreDetails, TelemetryData


class SecurityAction(str, Enum):
    NONE = "NONE"
    POWER_ISOLATION = "POWER_ISOLATION"
    REVOKE_SESSION_AUTH = "REVOKE_SESSION_AUTH"
    RATE_LIMIT_TRAFFIC = "RATE_LIMIT_TRAFFIC"


class AdaptiveRiskEngine:

    def __init__(self) -> None:
        self._spike_history: dict[str, int] = {}
        self.ml_detector = MLAnomalyDetector()

    def reset_station_history(self, station_id: str) -> None:
        """Resets historical anomaly spike count for a specific station."""
        self._spike_history[station_id] = 0

    def calculate_risk(self, telemetry: TelemetryData) -> RiskScoreDetails:
        station_id = telemetry.station_id
        if station_id not in self._spike_history:
            self._spike_history[station_id] = 0

        flags: list[str] = []

        # 1. Safely evaluate ML Isolation Forest Anomaly
        try:
            is_ml_anomaly, ml_risk_score = self.ml_detector.predict_anomaly(telemetry)
            if is_ml_anomaly:
                flags.append("ML_ISOLATION_FOREST_ANOMALY")
        except Exception:
            ml_risk_score = 15.0  # Fallback baseline score if ML model fails

        # 2. Rule-Based Telemetry Threshold Checks
        if telemetry.temperature_c > 75.0:
            flags.append("HIGH_TEMPERATURE")
        if telemetry.failed_auth_attempts >= 5:
            flags.append("BRUTE_FORCE_SUSPECTED")
        if telemetry.network_latency_ms > 300.0:
            flags.append("NETWORK_DEGRADATION")

        # 3. Update Spike History & Penalty Calculation
        if flags:
            self._spike_history[station_id] += 1
        elif self._spike_history[station_id] > 0:
            # Gradually decay history count on normal ticks
            self._spike_history[station_id] -= 1

        history_penalty = min(self._spike_history[station_id] * 2.0, 20.0)
        final_risk = min(max(ml_risk_score + history_penalty, 0.0), 100.0)

        # 4. Map Health Status, Edge Security Actions, and User Notifications
        vehicle_id = getattr(telemetry, "vehicle_id", station_id)

        if final_risk < 30.0:
            status = HealthStatus.HEALTHY
            edge_action = SecurityAction.NONE
            user_msg = f"EV Charging normal for vehicle [{vehicle_id}]."
        elif final_risk < 70.0:
            status = HealthStatus.DEGRADED
            edge_action = SecurityAction.RATE_LIMIT_TRAFFIC
            user_msg = f"WARNING: Anomaly detected on station {station_id}. Traffic rate-limited."
        else:
            status = HealthStatus.CRITICAL
            if "HIGH_TEMPERATURE" in flags:
                edge_action = SecurityAction.POWER_ISOLATION
                user_msg = f"CRITICAL: Thermal overload on {vehicle_id}! Triggering POWER_ISOLATION."
            elif "BRUTE_FORCE_SUSPECTED" in flags:
                edge_action = SecurityAction.REVOKE_SESSION_AUTH
                user_msg = f"CRITICAL: Unauthorized hijack attempt on {vehicle_id}! Revoking session auth."
            else:
                edge_action = SecurityAction.POWER_ISOLATION
                user_msg = f"CRITICAL: Cyber threat detected on {station_id}! Isolating session."

        return RiskScoreDetails(
            risk_score=round(final_risk, 2),
            health_status=status,
            anomaly_flags=flags,
            historical_spike_count=self._spike_history[station_id],
            user_notification=user_msg,
            automated_edge_action=edge_action,
        )