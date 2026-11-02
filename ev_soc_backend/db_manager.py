import logging
import sqlite3
from typing import Any, Dict, List, Optional
from datetime import datetime

logger = logging.getLogger("DB_MANAGER")


class DatabaseManager:

  def __init__(self, db_path: str = "chargeshield_soar.db"):
    self.db_path = db_path
    self._init_db()

  def get_connection(self):
    conn = sqlite3.connect(self.db_path)
    conn.row_factory = sqlite3.Row
    return conn

  def _init_db(self):
    """Initializes tables with default timestamps for automated logging."""
    query_security = """
        CREATE TABLE IF NOT EXISTS security_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            origin_ip TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            confidence REAL NOT NULL,
            soar_action TEXT NOT NULL
        );
        """

    # Table specifically for raw/preprocessed ESP32 Telemetry transfers
    query_telemetry = """
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            client_id TEXT NOT NULL,
            voltage REAL NOT NULL,
            current REAL NOT NULL,
            soc REAL NOT NULL,
            temperature REAL NOT NULL,
            origin_ip TEXT NOT NULL
        );
        """
    try:
      with self.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query_security)
        cursor.execute(query_telemetry)
        conn.commit()
      logger.info("Database initialized with Security & Telemetry tables.")
    except Exception as e:
      logger.error(f"Failed to initialize database: {e}")

  def log_telemetry(self, esp32_data: Dict[str, Any]) -> bool:
    """Stores incoming raw/live ESP32 telemetry frames into the SQL database."""
    query = """
        INSERT INTO telemetry_logs (
            timestamp, client_id, voltage, current, soc, temperature, origin_ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
        """
    # Fallback to current UTC ISO format if timestamp is missing
    ts = esp32_data.get("timestamp") or datetime.utcnow().isoformat()
    
    try:
      with self.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            query,
            (
                ts,
                esp32_data.get("client_id", "ESP32_NODE_01"),
                float(esp32_data.get("voltage", 0.0)),
                float(esp32_data.get("current", 0.0)),
                float(esp32_data.get("soc", 80.0)),
                float(esp32_data.get("temperature", 0.0)),
                esp32_data.get("source_ip", "127.0.0.1"),
            ),
        )
        conn.commit()
      return True
    except Exception as e:
      logger.error(f"Error inserting telemetry record: {e}")
      return False

  def log_incident(self, incident_record: Dict[str, Any]) -> bool:
    """Stores SOAR execution results directly into the structured SQL table."""
    query = """
        INSERT INTO security_logs (
            timestamp, origin_ip, threat_category, confidence, soar_action
        ) VALUES (?, ?, ?, ?, ?);
        """
    ts = incident_record.get("timestamp") or datetime.utcnow().isoformat()
    actions = incident_record.get("actions_taken", [])
    
    if any(
        "Blacklisted" in action
        or "Blackholed" in action
        or "Enforced" in action
        for action in actions
    ):
      soar_action = "IP Blocked"
    elif incident_record.get("status") == "BENIGN":
      soar_action = "Pass-Through"
    else:
      soar_action = actions[0] if actions else "Mitigated"

    confidence_val = incident_record.get("confidence", 0.0)
    if confidence_val <= 1.0:
      confidence_val = round(confidence_val * 100, 1)

    try:
      with self.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            query,
            (
                ts,
                incident_record.get("source_ip", "127.0.0.1"),
                incident_record.get("threat_type", "Anomalous Telemetry"),
                confidence_val,
                soar_action,
            ),
        )
        conn.commit()
      return True
    except Exception as e:
      logger.error(f"Error inserting security incident record: {e}")
      return False


# Global instance
db = DatabaseManager()