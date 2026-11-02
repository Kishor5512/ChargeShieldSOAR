import logging
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
import pandas as pd

logger = logging.getLogger("ML_ENGINE")

_BASE_DIR = Path(__file__).resolve().parent
_MODEL_PATH = _BASE_DIR / "isolation_forest_model.pkl"
_SCALER_PATH = _BASE_DIR / "feature_scaler.pkl"

_model = None
_scaler = None

_FEATURE_COLUMNS = [
    "bus_voltage_v",
    "line_current_a",
    "active_power_kw",
    "temperature_c",
    "cpu_utilization_pct",
    "free_heap_bytes",
    "context_switch_rate",
    "round_trip_time_ms",
    "failed_auth_attempts",
    "packet_retransmission_pct",
    "payload_frame_bytes",
    "voltage_std_dev_5s",
    "power_gradient_kw_sec",
    "packet_iat_mean_ms",
    "historical_spike_index",
]


def _load_artifacts():
    """Load the trained Isolation Forest model and scaler once at import time."""
    global _model, _scaler

    if _model is not None and _scaler is not None:
        return

    if not _MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Missing trained ML model: {_MODEL_PATH}. Run model training before inference."
        )
    if not _SCALER_PATH.exists():
        raise FileNotFoundError(
            f"Missing feature scaler: {_SCALER_PATH}. Run model training before inference."
        )

    _model = joblib.load(_MODEL_PATH)
    _scaler = joblib.load(_SCALER_PATH)
    logger.info("ML artifacts loaded from %s and %s", _MODEL_PATH, _SCALER_PATH)


def _build_feature_vector(voltage: float, current: float, temp: float) -> pd.DataFrame:
    """Map the simplified live API into the full EVSE feature schema expected by the model."""
    active_power_kw = (voltage * current) / 1000.0
    return pd.DataFrame(
        [{
            "bus_voltage_v": voltage,
            "line_current_a": current,
            "active_power_kw": active_power_kw,
            "temperature_c": temp,
            "cpu_utilization_pct": 35.0,
            "free_heap_bytes": 120000.0,
            "context_switch_rate": 250.0,
            "round_trip_time_ms": 25.0,
            "failed_auth_attempts": 0,
            "packet_retransmission_pct": 0.0,
            "payload_frame_bytes": 256,
            "voltage_std_dev_5s": 0.5,
            "power_gradient_kw_sec": 0.05,
            "packet_iat_mean_ms": 50.0,
            "historical_spike_index": 0,
        }], columns=_FEATURE_COLUMNS)


def predict_anomaly(voltage: float, current: float, temp: float) -> Tuple[bool, float]:
    """Run a live anomaly check using the trained EVSE Isolation Forest model.

    Accepts the simplified 3-signal API used by the edge telemetry layer and expands it to the
    15-field schema expected by the stored model. Returns (is_anomaly, risk_score).
    """
    _load_artifacts()

    try:
        voltage = float(voltage)
        current = float(current)
        temp = float(temp)
    except (TypeError, ValueError):
        raise ValueError("Voltage, current, and temperature must be numeric values.")

    features = _build_feature_vector(voltage, current, temp)
    scaled_features = _scaler.transform(features)
    prediction = int(_model.predict(scaled_features)[0])
    decision_score = float(_model.decision_function(scaled_features)[0])

    risk_score = float(np.clip((0.5 - decision_score) * 80.0, 0.0, 100.0))
    is_anomaly = prediction == -1
    if is_anomaly:
        risk_score = max(risk_score, 75.0)
    else:
        risk_score = min(risk_score, 45.0)

    return is_anomaly, round(risk_score, 2)
