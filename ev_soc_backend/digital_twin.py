import random
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from incident_engine import AIIncidentExplanationEngine
from models import StationState, TelemetryData
from risk_engine import AdaptiveRiskEngine


class EVSEDigitalTwin:

    def __init__(self, station_ids: List[str]):
        self.station_ids = station_ids
        self.risk_engine = AdaptiveRiskEngine()
        self.explainer = AIIncidentExplanationEngine()
        self.states: Dict[str, StationState] = {}
        self.active_attacks: Dict[str, str] = {}  # Tracks active attack_type per station
        self._initialize_stations()

    def _initialize_stations(self):
        for sid in self.station_ids:
            self.initialize_station(sid)

    def initialize_station(self, station_id: str):
        """Initializes or resets a single station state."""
        self.active_attacks.pop(station_id, None)
        telemetry = TelemetryData(
            station_id=station_id,
            timestamp=datetime.now(timezone.utc),
            power_kw=50.0,
            voltage_v=230.0,
            current_a=217.0,
            temperature_c=35.0,
            cpu_utilization_pct=15.0,
            network_latency_ms=25.0,
            failed_auth_attempts=0,
            packet_loss_pct=0.0,
        )
        risk = self.risk_engine.calculate_risk(telemetry)
        self.states[station_id] = StationState(
            station_id=station_id,
            is_active=True,
            active_attack_type=None,
            telemetry=telemetry,
            risk_details=risk,
        )

    def reset_station(self, station_id: str):
        """Clears active attack state and resets metrics to baseline."""
        self.initialize_station(station_id)

    def evaluate_risk(self, station_id: str) -> Optional[StationState]:
        if station_id not in self.states:
            return None

        state = self.states[station_id]
        state.telemetry.timestamp = datetime.now(timezone.utc)
        
        risk = self.risk_engine.calculate_risk(state.telemetry)
        incident = self.explainer.generate_explanation(state.telemetry, risk)

        state.risk_details = risk
        state.latest_incident = incident
        return state

    def tick(self) -> Tuple[Dict[str, StationState], List[dict]]:
        new_events = []
        for sid, state in self.states.items():
            if not state.is_active:
                continue

            # 1. If an attack is actively injected, maintain distorted attack telemetry
            if sid in self.active_attacks:
                attack_type = self.active_attacks[sid]
                state.active_attack_type = attack_type
                telemetry = self._generate_attack_telemetry(sid, attack_type)
            else:
                # 2. Baseline behavior with ambient background anomalies
                inject_anomaly = random.random() < 0.15
                if inject_anomaly:
                    temp = round(random.uniform(70.0, 90.0), 1)
                    cpu = round(random.uniform(80.0, 99.0), 1)
                    auth_fail = random.randint(5, 12)
                    lat = round(random.uniform(200.0, 500.0), 1)
                else:
                    temp = round(random.uniform(30.0, 45.0), 1)
                    cpu = round(random.uniform(10.0, 35.0), 1)
                    auth_fail = random.randint(0, 1)
                    lat = round(random.uniform(15.0, 45.0), 1)

                state.active_attack_type = None
                telemetry = TelemetryData(
                    station_id=sid,
                    timestamp=datetime.now(timezone.utc),
                    power_kw=round(random.uniform(45.0, 55.0), 1),
                    voltage_v=round(random.uniform(225.0, 235.0), 1),
                    current_a=round(random.uniform(200.0, 220.0), 1),
                    temperature_c=temp,
                    cpu_utilization_pct=cpu,
                    network_latency_ms=lat,
                    failed_auth_attempts=auth_fail,
                    packet_loss_pct=round(
                        random.uniform(0.0, 2.0) if lat < 200 else random.uniform(8.0, 20.0),
                        1,
                    ),
                )

            risk = self.risk_engine.calculate_risk(telemetry)
            incident = self.explainer.generate_explanation(telemetry, risk)

            state.telemetry = telemetry
            state.risk_details = risk
            state.latest_incident = incident

            if risk.anomaly_flags:
                new_events.append({
                    "station_id": sid,
                    "event_type": "ANOMALY_DETECTED",
                    "message": f"Flags: {', '.join(risk.anomaly_flags)}",
                    "risk_score": risk.risk_score,
                    "timestamp": telemetry.timestamp.isoformat(),
                })

        return self.states, new_events

    def _generate_attack_telemetry(self, station_id: str, attack_type: str) -> TelemetryData:
        now = datetime.now(timezone.utc)
        if attack_type == "BRUTE_FORCE":
            return TelemetryData(
                station_id=station_id, timestamp=now, power_kw=50.0, voltage_v=230.0,
                current_a=217.0, temperature_c=45.0, cpu_utilization_pct=88.0,
                network_latency_ms=120.0, failed_auth_attempts=random.randint(15, 25), packet_loss_pct=2.5
            )
        elif attack_type == "THERMAL_RUNAWAY":
            return TelemetryData(
                station_id=station_id, timestamp=now, power_kw=150.0, voltage_v=480.0,
                current_a=312.0, temperature_c=round(random.uniform(95.0, 105.0), 1),
                cpu_utilization_pct=65.0, network_latency_ms=45.0, failed_auth_attempts=0, packet_loss_pct=0.2
            )
        elif attack_type == "DOS_FLOOD":
            return TelemetryData(
                station_id=station_id, timestamp=now, power_kw=22.0, voltage_v=220.0,
                current_a=100.0, temperature_c=52.0, cpu_utilization_pct=99.0,
                network_latency_ms=round(random.uniform(1000.0, 1500.0), 1), failed_auth_attempts=3, packet_loss_pct=42.0
            )
        elif attack_type in ["MITM_OCPP_TAMPERING", "VOLTAGE_SURGE"]:
            return TelemetryData(
                station_id=station_id, timestamp=now, power_kw=180.0, voltage_v=560.0,
                current_a=320.0, temperature_c=68.0, cpu_utilization_pct=70.0,
                network_latency_ms=450.0, failed_auth_attempts=5, packet_loss_pct=15.0
            )
        elif attack_type == "UNAUTHORIZED_HIJACK_ATTEMPT":
            return TelemetryData(
                station_id=station_id, timestamp=now, power_kw=0.0, voltage_v=230.0,
                current_a=0.0, temperature_c=42.0, cpu_utilization_pct=75.0,
                network_latency_ms=350.0, failed_auth_attempts=12, packet_loss_pct=5.0
            )
        
        # Fallback for unknown attack types
        return TelemetryData(
            station_id=station_id, timestamp=now, power_kw=0.0, voltage_v=230.0,
            current_a=0.0, temperature_c=60.0, cpu_utilization_pct=90.0,
            network_latency_ms=500.0, failed_auth_attempts=10, packet_loss_pct=20.0
        )

    def initialize_station(self, station_id: str):
        """Initializes or resets a single station state."""
        self.active_attacks.pop(station_id, None)
        
        # Clear risk history in adaptive risk engine
        if hasattr(self.risk_engine, "reset_station_history"):
            self.risk_engine.reset_station_history(station_id)

        telemetry = TelemetryData(
            station_id=station_id,
            timestamp=datetime.now(timezone.utc),
            power_kw=50.0,
            voltage_v=230.0,
            current_a=217.0,
            temperature_c=35.0,
            cpu_utilization_pct=15.0,
            network_latency_ms=25.0,
            failed_auth_attempts=0,
            packet_loss_pct=0.0,
        )
        risk = self.risk_engine.calculate_risk(telemetry)
        self.states[station_id] = StationState(
            station_id=station_id,
            is_active=True,
            active_attack_type=None,
            telemetry=telemetry,
            risk_details=risk,
        )