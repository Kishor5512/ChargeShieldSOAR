import uuid
from typing import Optional
from models import IncidentExplanation, RiskScoreDetails, TelemetryData


class AIIncidentExplanationEngine:
    @staticmethod
    def generate_explanation(
        telemetry: TelemetryData, risk: RiskScoreDetails
    ) -> Optional[IncidentExplanation]:
        if not risk.anomaly_flags:
            return None

        flags = set(risk.anomaly_flags)
        title = "Anomalous Activity Detected"
        root_cause = "Unknown System Abnormality"
        mitigations = ["Monitor system metrics", "Review logs"]
        confidence = 0.75

        if "BRUTE_FORCE_SUSPECTED" in flags or "ML_ISOLATION_FOREST_ANOMALY" in flags:
            title = "Potential Cyber Attack / Host Impairment"
            root_cause = f"High failed auths ({telemetry.failed_auth_attempts}) or abnormal vector state."
            mitigations = ["Rate limit API requests", "Isolate gateway endpoint"]
            confidence = 0.90

        summary = f"Station {telemetry.station_id} is operating at {risk.health_status.value} status."

        return IncidentExplanation(
            incident_id=f"INC-{uuid.uuid4().hex[:8].upper()}",
            station_id=telemetry.station_id,
            timestamp=telemetry.timestamp,
            title=title,
            summary=summary,
            root_cause=root_cause,
            confidence_score=confidence,
            recommended_mitigation=mitigations,
        )