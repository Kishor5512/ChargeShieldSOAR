import logging
import os
from typing import Any, Dict, List

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# --------------------------------------------------------------------------
# INTEGRATION: Import database, ML engine & SOAR engine instances
# --------------------------------------------------------------------------
try:
  from db_manager import db
except ImportError:
  db = None

from ml_engine import predict_anomaly
from soar_engine import soar

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ChargeShieldSOAR")

app = FastAPI(title="ChargeShield-SOAR Backend", version="2.0.0")

# Enable CORS for frontend dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-Memory History Buffer for real-time frontend charts
telemetry_history: List[Dict[str, Any]] = []


# --------------------------------------------------------------------------
# WebSocket Connection Manager
# --------------------------------------------------------------------------
class ConnectionManager:

  def __init__(self):
    self.active_connections: List[WebSocket] = []

  async def connect(self, websocket: WebSocket):
    await websocket.accept()
    self.active_connections.append(websocket)
    logger.info(
        "WebSocket client connected. Total connections:"
        f" {len(self.active_connections)}"
    )

  def disconnect(self, websocket: WebSocket):
    if websocket in self.active_connections:
      self.active_connections.remove(websocket)
      logger.info("WebSocket client disconnected.")

  async def broadcast(self, data: dict):
    for connection in list(self.active_connections):
      try:
        await connection.send_json(data)
      except Exception as e:
        logger.error(f"Error broadcasting to WS client: {e}")
        self.disconnect(connection)


manager = ConnectionManager()


# --------------------------------------------------------------------------
# Pydantic Schema for Telemetry Validation (Includes Button Support)
# --------------------------------------------------------------------------
class TelemetryData(BaseModel):
  station_id: str = "EVSE-SERIAL-NODE-01"
  bus_voltage_v: float
  line_current_a: float
  active_power_kw: float
  temperature_c: float
  button_pressed: bool = False  # Physical push button state
  cpu_utilization_pct: float
  free_heap_bytes: int
  context_switch_rate: int
  round_trip_time_ms: float
  failed_auth_attempts: int
  packet_retransmission_pct: float
  payload_frame_bytes: int
  voltage_std_dev_5s: float
  power_gradient_kw_sec: float
  packet_iat_mean_ms: float
  historical_spike_index: int


# --------------------------------------------------------------------------
# Middleware for SOAR Enforcement (Returns clean JSON 403 on block)
# --------------------------------------------------------------------------
@app.middleware("http")
async def check_ip_blocklist(request: Request, call_next):
  # Automatically extract real client IP (whether ESP32 over Wi-Fi or local test script)
  client_ip = request.client.host
  if soar.is_ip_blocked(client_ip) and request.url.path.startswith(
      "/api/v1/telemetry"
  ):
    logger.warning(f"⛔ Blocked request rejected from blacklisted IP: {client_ip}")
    return JSONResponse(
        status_code=403,
        content={
            "detail": f"IP {client_ip} is blacklisted by ChargeShield SOAR engine."
        },
    )
  response = await call_next(request)
  return response


# --------------------------------------------------------------------------
# Core Endpoints
# --------------------------------------------------------------------------
@app.get("/")
async def root():
  return {"status": "online", "system": "ChargeShield-SOAR with ML Engine"}


@app.get("/health")
async def health():
  return {
      "status": "healthy",
      "blocked_ips_count": len(soar.blocked_ips),
      "db_status": "connected" if db else "standalone",
  }


@app.get("/dashboard")
async def serve_dashboard():
  html_path = "index.html"
  if os.path.exists(html_path):
    return FileResponse(html_path)
  return JSONResponse(
      status_code=404,
      content={"detail": "index.html dashboard file not found in directory."},
  )


# --------------------------------------------------------------------------
# Telemetry Ingestion Endpoint (ML & SOAR Pipeline Trigger)
# --------------------------------------------------------------------------
@app.post("/api/v1/telemetry")
async def receive_telemetry(data: TelemetryData, request: Request):
  # Captures the actual network IP of the ESP32 or client sending the POST request
  client_ip = request.client.host
  telemetry_dict = data.dict()
  telemetry_dict["source_ip"] = client_ip

  # Log incoming telemetry with real client source IP
  logger.info(
      f"📥 Received Telemetry from Wi-Fi Node [{client_ip}] -> Station:"
      f" {data.station_id}, Voltage: {data.bus_voltage_v}V, Temp:"
      f" {data.temperature_c}°C, Button Pressed: {data.button_pressed}"
  )

  # 1. Run inference using your trained ML model
  try:
    is_ml_anomaly, ml_risk_score = predict_anomaly(
        voltage=data.bus_voltage_v,
        current=data.line_current_a,
        temp=data.temperature_c,
    )
  except Exception as e:
    logger.error(f"ML Engine inference error: {e}")
    is_ml_anomaly, ml_risk_score = False, 20.0

  # 2. Store raw/live telemetry payload in SQLite database
  if db:
    db_payload = {
        "timestamp": telemetry_dict.get("timestamp"),
        "client_id": data.station_id,
        "voltage": data.bus_voltage_v,
        "current": data.line_current_a,
        "soc": 80.0,
        "temperature": data.temperature_c,
        "source_ip": client_ip,
    }
    db.log_telemetry(db_payload)

  # 3. Hybrid Threat Classifier (Button, Rules, & Trained Isolation Forest ML Model)
  threat_type = None
  confidence = 0.0
  risk_score = ml_risk_score

  if data.button_pressed:
    threat_type = "EMERGENCY_STOP"
    confidence = 1.0
    risk_score = 100.0
  elif data.failed_auth_attempts >= 10:
    threat_type = "BRUTE_FORCE"
    confidence = 0.95
    risk_score = 85.0
  elif data.bus_voltage_v >= 400.0 or data.payload_frame_bytes >= 3000:
    threat_type = "INJECTION"
    confidence = 0.92
    risk_score = 88.0
  elif is_ml_anomaly:
    threat_type = "ML_ANOMALY_DETECTED"
    confidence = 0.91
    risk_score = max(ml_risk_score, 75.0)

  # 4. Trigger SOAR Engine if an attack or ML anomaly is identified
  soar_result = None
  if threat_type:
    soar_result = await soar.dispatch(
        threat_type=threat_type,
        confidence=confidence,
        risk_score=risk_score,
        telemetry=telemetry_dict,
    )

  # 5. Maintain timeline history & Broadcast via WebSockets
  telemetry_history.append(telemetry_dict)
  if len(telemetry_history) > 100:
    telemetry_history.pop(0)

  broadcast_payload = {
      "telemetry": telemetry_dict,
      "soar_event": soar_result,
      "is_blocked": soar.is_ip_blocked(client_ip),
  }
  await manager.broadcast(broadcast_payload)

  return {
      "status": "mitigated" if soar_result else "processed",
      "client_ip": client_ip,
      "threat_detected": threat_type,
      "ml_anomaly_flag": is_ml_anomaly,
      "calculated_risk_score": risk_score,
      "soar_actions": (
          soar_result.get("actions_taken") if soar_result else []
      ),
  }


# --------------------------------------------------------------------------
# WebSocket Endpoint
# --------------------------------------------------------------------------
@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
  await manager.connect(websocket)
  try:
    while True:
      await websocket.receive_text()
  except WebSocketDisconnect:
    manager.disconnect(websocket)


# --------------------------------------------------------------------------
# Audit Logs & Admin Endpoints
# --------------------------------------------------------------------------
@app.get("/api/v1/timeline")
async def get_timeline():
  return telemetry_history


@app.get("/api/v1/admin/blocked-ips")
async def get_blocked_ips():
  return {"blocked_ips": list(soar.blocked_ips)}


@app.get("/api/v1/admin/audit-logs")
async def get_audit_logs(limit: int = 50):
  """Fetches stored security incidents from SQLite database."""
  if db:
    return db.fetch_all_logs(limit=limit)
  return soar.execution_history[-limit:]


@app.post("/api/v1/admin/unblock")
async def unblock_ip(ip: str = Query(..., description="IP address to unblock")):
  if soar.is_ip_blocked(ip):
    soar.blocked_ips.remove(ip)
    logger.info(f"✅ Admin unblocked IP: {ip}")
    return {
        "status": "success",
        "message": f"IP {ip} unblocked.",
        "active_blocked_ips": list(soar.blocked_ips),
    }
  return {
      "status": "ignored",
      "message": f"IP {ip} was not in blocklist.",
      "active_blocked_ips": list(soar.blocked_ips),
  }


if __name__ == "__main__":
  import uvicorn

  uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)