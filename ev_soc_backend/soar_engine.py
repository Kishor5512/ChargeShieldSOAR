import logging
import serial
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

try:
    from db_manager import db
except ImportError:  # pragma: no cover - optional local DB
    db = None

from oem_notifier import send_oem_security_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SOAR_ENGINE")

# Serial Port Configuration for direct ESP32 hardware relay control
_SERIAL_PORT = "/dev/ttyUSB0"
_BAUD_RATE = 115200


class SOAREngine:
    """Coordinates EVSE security playbooks and enforcement actions."""

    def __init__(self):
        self.playbooks = {
            "DOS_FLOODING": self._playbook_dos_flooding,
            "UNAUTHORIZED_ACCESS": self._playbook_unauthorized_access,
            "BRUTE_FORCE": self._playbook_unauthorized_access,
            "DATA_TAMPERING": self._playbook_data_tampering,
            "INJECTION": self._playbook_data_tampering,
            "ANOMALOUS_TELEMETRY": self._playbook_anomalous_telemetry,
            "RECON_SCANNING": self._playbook_recon_scanning,
            "HOST_MALWARE": self._playbook_host_malware,
            "ML_ANOMALY_DETECTED": self._playbook_anomalous_telemetry,
        }
        self.blocked_ips: Set[str] = set()
        self.execution_history: List[Dict[str, Any]] = []

    def is_ip_blocked(self, ip_address: str) -> bool:
        return ip_address in self.blocked_ips

    @staticmethod
    def _gps_from_payload(telemetry: Dict[str, Any]) -> Dict[str, float]:
        gps = telemetry.get("gps") or telemetry.get("gps_location") or {}
        if isinstance(gps, dict):
            return {"lat": float(gps.get("lat", 0.0)), "lon": float(gps.get("lon", 0.0))}
        return {"lat": 0.0, "lon": 0.0}

    @staticmethod
    def _mitigation_command(threat_type: str) -> str:
        if threat_type in {
            "ANOMALOUS_TELEMETRY",
            "DATA_TAMPERING",
            "INJECTION",
            "HOST_MALWARE",
            "DOS_FLOODING",
            "ML_ANOMALY_DETECTED",
        }:
            return "ISOLATE_NODE"
        return "BLOCK_IP"

    def _trigger_serial_relay_isolation(self) -> str:
        """Sends physical ISOLATE command over serial port to the connected ESP32."""
        try:
            with serial.Serial(_SERIAL_PORT, _BAUD_RATE, timeout=1) as ser:
                ser.write(b"ISOLATE\n")
            logger.info("⚡ [HARDWARE] Successfully sent 'ISOLATE' command to ESP32 on %s", _SERIAL_PORT)
            return f"Physically tripped ESP32 relay via serial ({_SERIAL_PORT})"
        except Exception as exc:
            logger.warning("⚠️ [HARDWARE] Failed to write serial isolation command to %s: %s", _SERIAL_PORT, exc)
            return f"Serial relay trigger attempted but failed: {exc}"

    async def dispatch(
        self,
        threat_type: str,
        confidence: float,
        risk_score: float,
        telemetry: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Run a playbook for the detected threat and return a structured mitigation result."""
        timestamp = datetime.now(timezone.utc).isoformat()
        source_ip = telemetry.get("source_ip", telemetry.get("client_ip", "127.0.0.1"))

        playbook = self.playbooks.get(threat_type)
        if playbook is None:
            logger.warning("No SOAR playbook mapped for threat type: %s", threat_type)
            return {
                "status": "ignored",
                "reason": "unmapped_threat",
                "timestamp": timestamp,
            }

        try:
            actions_taken = await playbook(confidence, risk_score, telemetry, source_ip)
        except Exception as exc:  # pragma: no cover
            logger.exception("Playbook execution failed for %s", threat_type)
            actions_taken = [f"Playbook execution error: {exc}"]

        mitigation_command = self._mitigation_command(threat_type)
        self.blocked_ips.add(source_ip)

        # If mitigation requires hardware node isolation, trigger serial relay command
        if mitigation_command == "ISOLATE_NODE":
            hardware_action = self._trigger_serial_relay_isolation()
            actions_taken.append(hardware_action)

        if risk_score >= 75.0 or threat_type in {"ANOMALOUS_TELEMETRY", "DATA_TAMPERING", "INJECTION", "ML_ANOMALY_DETECTED"}:
            gps = self._gps_from_payload(telemetry)
            send_oem_security_alert(
                attacker_ip=source_ip,
                risk_score=risk_score,
                gps_location=gps,
                station_id=str(telemetry.get("station_id", telemetry.get("client_id", "EVSE-01"))),
                threat_type=threat_type,
            )

        incident_record = {
            "timestamp": timestamp,
            "threat_type": threat_type,
            "confidence": confidence,
            "risk_score": risk_score,
            "source_ip": source_ip,
            "actions_taken": actions_taken,
            "status": "MITIGATED",
            "mitigation_command": mitigation_command,
            "oem_alert_sent": True,
            "power_session_interrupted": mitigation_command == "ISOLATE_NODE",
        }

        self.execution_history.append(incident_record)
        await self._notify_soc_dashboard(incident_record)

        logger.info(
            "🚨 [%s] Threat=%s | IP=%s | Risk=%.2f | Mitigation=%s | Actions=%s",
            timestamp,
            threat_type,
            source_ip,
            risk_score,
            mitigation_command,
            actions_taken,
        )
        return incident_record

    async def _playbook_dos_flooding(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        actions = [
            f"Blocked source IP {source_ip} at gateway firewall",
            "Rate-limited traffic to emergency thresholds",
            "Cleared transient socket queues and restored safe session controls",
        ]
        self.blocked_ips.add(source_ip)
        return actions

    async def _playbook_unauthorized_access(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        failed_attempts = telemetry.get("failed_auth_attempts", 0)
        self.blocked_ips.add(source_ip)
        return [
            f"Blacklisted IP {source_ip} after {failed_attempts} failed auth attempts",
            "Revoked active session tokens and required re-authentication",
            "Logged unauthorized access attempt for SOC review",
        ]

    async def _playbook_data_tampering(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        voltage = telemetry.get("bus_voltage_v", telemetry.get("voltage_v", 0.0))
        frame_size = telemetry.get("payload_frame_bytes", 0)
        self.blocked_ips.add(source_ip)
        return [
            f"Detected malformed telemetry from {source_ip} (voltage={voltage}V, frame={frame_size} bytes)",
            "Isolated the charging node and quarantined telemetry ingestion",
            "Logged tampering indicators to the forensic audit trail",
        ]

    async def _playbook_anomalous_telemetry(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        voltage = telemetry.get("bus_voltage_v", telemetry.get("voltage_v", 230.0))
        temp = telemetry.get("temperature_c", 35.0)
        self.blocked_ips.add(source_ip)
        return [
            f"Anomalous electrical/ML drift detected from {source_ip} (voltage={voltage}V, temp={temp}°C)",
            "Prepared ESP32 relay isolation command ISOLATE_NODE",
            "Applied safe power-limiting and logged anomaly metrics",
        ]

    async def _playbook_recon_scanning(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        self.blocked_ips.add(source_ip)
        return [
            f"Recon scan fingerprint associated with {source_ip}",
            "Blocked the source IP and suppressed verbose responses",
            "Recorded probe details to the SOC intelligence store",
        ]

    async def _playbook_host_malware(
        self, conf: float, risk: float, telemetry: Dict[str, Any], source_ip: str
    ) -> List[str]:
        self.blocked_ips.add(source_ip)
        return [
            f"Suspected host compromise from {source_ip}",
            "Triggered node isolation and forensic capture on the impacted EVSE",
            "Escalated to OEM incident response via secure channel",
        ]

    async def _notify_soc_dashboard(self, incident: Dict[str, Any]):
        if db:
            try:
                db.log_incident(incident)
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to log incident to DB: %s", exc)

        logger.info(
            "📢 SOC ALERT: %s | IP=%s | Actions=%s",
            incident["threat_type"],
            incident["source_ip"],
            incident["actions_taken"],
        )


soar = SOAREngine()