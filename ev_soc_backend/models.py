from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import AliasChoices, BaseModel, Field


class HealthStatus(str, Enum):
  HEALTHY = "HEALTHY"
  DEGRADED = "DEGRADED"
  CRITICAL = "CRITICAL"


class SeverityLevel(str, Enum):
  LOW = "LOW"
  MEDIUM = "MEDIUM"
  HIGH = "HIGH"
  CRITICAL = "CRITICAL"


class TelemetryData(BaseModel):
  station_id: str = Field(
      default="EVSE-ALPHA-01", description="Unique EVSE station identifier"
  )
  timestamp: datetime = Field(
      default_factory=lambda: datetime.now(timezone.utc),
      description="Telemetry timestamp (UTC)",
  )

  # Flexible aliases to match both raw ML dataset and SOC frontend names
  power_kw: float = Field(
      ...,
      ge=0.0,
      validation_alias=AliasChoices("power_kw", "active_power_kw"),
      description="Active charging power in kW",
  )
  voltage_v: float = Field(
      ...,
      ge=0.0,
      validation_alias=AliasChoices("voltage_v", "bus_voltage_v"),
      description="RMS line voltage in Volts",
  )
  current_a: float = Field(
      ...,
      ge=0.0,
      validation_alias=AliasChoices("current_a", "line_current_a"),
      description="Line current in Amperes",
  )
  temperature_c: float = Field(
      ..., description="Operating temperature in Celsius"
  )
  cpu_utilization_pct: float = Field(
      ..., ge=0.0, le=100.0, description="CPU usage percentage"
  )
  network_latency_ms: float = Field(
      ...,
      ge=0.0,
      validation_alias=AliasChoices("network_latency_ms", "round_trip_time_ms"),
      description="Round-trip latency in milliseconds",
  )
  failed_auth_attempts: int = Field(
      ..., ge=0, description="Failed login or OCPP authentication attempts"
  )
  packet_loss_pct: float = Field(
      ...,
      ge=0.0,
      le=100.0,
      validation_alias=AliasChoices(
          "packet_loss_pct", "packet_retransmission_pct"
      ),
      description="Network packet loss percentage",
  )

  # ML Model Specific Telemetry Features (Optional with Defaults)
  free_heap_bytes: Optional[int] = Field(
      120000, ge=0, description="Available heap memory"
  )
  context_switch_rate: Optional[int] = Field(
      200, ge=0, description="OS context switches per sec"
  )
  payload_frame_bytes: Optional[int] = Field(
      300, ge=0, description="Telemetry frame payload size"
  )
  voltage_std_dev_5s: Optional[float] = Field(
      0.2, ge=0.0, description="Voltage standard deviation over 5s"
  )
  power_gradient_kw_sec: Optional[float] = Field(
      0.05, description="Power ramp rate"
  )
  packet_iat_mean_ms: Optional[float] = Field(
      50.0, ge=0.0, description="Mean packet inter-arrival time"
  )
  historical_spike_index: Optional[int] = Field(
      0, ge=0, description="Spike anomaly index"
  )

  model_config = {
      "populate_by_name": True,
      "json_schema_extra": {
          "example": {
              "station_id": "EVSE-ALPHA-01",
              "bus_voltage_v": 230.1,
              "line_current_a": 32.0,
              "active_power_kw": 7.36,
              "temperature_c": 35.0,
              "cpu_utilization_pct": 22.5,
              "free_heap_bytes": 120000,
              "context_switch_rate": 200,
              "round_trip_time_ms": 25.0,
              "failed_auth_attempts": 0,
              "packet_retransmission_pct": 0.0,
              "payload_frame_bytes": 300,
              "voltage_std_dev_5s": 0.2,
              "power_gradient_kw_sec": 0.05,
              "packet_iat_mean_ms": 50.0,
              "historical_spike_index": 0,
          }
      },
  }


class RiskScoreDetails(BaseModel):
  risk_score: float = Field(
      ..., ge=0.0, le=100.0, description="Calculated threat risk score (0-100)"
  )
  health_status: HealthStatus = Field(..., description="Station health status")
  anomaly_flags: list[str] = Field(
      default_factory=list, description="Active anomaly detection flags"
  )
  historical_spike_count: int = Field(
      0, ge=0, description="Count of historical risk score spikes"
  )


class IncidentExplanation(BaseModel):
  incident_id: str = Field(..., description="Unique incident identifier")
  station_id: str = Field(..., description="Target station identifier")
  timestamp: datetime = Field(
      default_factory=lambda: datetime.now(timezone.utc),
      description="Incident detection timestamp",
  )
  title: str = Field(..., description="Brief title of the incident")
  summary: str = Field(..., description="Detailed incident summary")
  root_cause: str = Field(..., description="Identified or suspected root cause")
  confidence_score: float = Field(
      ..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0"
  )
  recommended_mitigation: list[str] = Field(
      default_factory=list, description="List of recommended mitigation steps"
  )


class StationState(BaseModel):
  station_id: str = Field(..., description="Unique station identifier")
  is_active: bool = Field(
      True, description="Whether the station is currently operational"
  )
  active_attack_type: Optional[str] = Field(
      None, description="Active attack simulation type if present"
  )
  telemetry: TelemetryData = Field(
      ..., description="Latest telemetry data snapshot"
  )
  risk_details: RiskScoreDetails = Field(
      ..., description="Current threat risk evaluation"
  )
  latest_incident: Optional[IncidentExplanation] = Field(
      None, description="Most recent security incident"
  )


class TimelineEvent(BaseModel):
  event_id: str = Field(..., description="Unique event identifier")
  station_id: str = Field(..., description="Associated station identifier")
  timestamp: datetime = Field(
      default_factory=lambda: datetime.now(timezone.utc),
      description="Event timestamp",
  )
  event_type: str = Field(..., description="Category/type of security event")
  message: str = Field(..., description="Detailed log message")
  risk_score_at_event: float = Field(
      ..., ge=0.0, le=100.0, description="Risk score at event time"
  )


class AttackInjectionRequest(BaseModel):
  station_id: str = Field(
      ..., examples=["EVSE-ALPHA-01"], description="Target EVSE station identifier"
  )
  attack_type: str = Field(
      ...,
      examples=["MITM_OCPP_TAMPERING"],
      description="Type of cyber attack to simulate",
  )
  severity: SeverityLevel = Field(
      SeverityLevel.HIGH,
      examples=[SeverityLevel.CRITICAL],
      description="Severity level: LOW, MEDIUM, HIGH, CRITICAL",
  )
  source_ip: Optional[str] = Field(
      "192.168.1.100",
      examples=["10.0.4.15"],
      description="Simulated attacker IP address",
  )
  intensity: float = Field(
      1.0,
      ge=0.1,
      le=10.0,
      description="Multiplier for telemetry distortion (0.1 to 10.0)",
  )
  custom_payload: dict[str, Any] = Field(
      default_factory=dict,
      examples=[{"fake_meter_val": 99999, "malicious_frame": "0xDEADBEEF"}],
      description=(
          "Arbitrary payload overrides for complex exploit scenarios"
      ),
  )