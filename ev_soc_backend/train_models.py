import glob
import os
import joblib
import kagglehub
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ==========================================
# 1. FETCH DATASET DIRECTLY FROM KAGGLE HUB
# ==========================================
print("⏳ Step 1: Accessing dataset via kagglehub...")
path = kagglehub.dataset_download(
    "mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"
)

print(f"📁 Kaggle Hub Cache Path: {path}")

# Search for all CSV files in the downloaded directory
csv_files = glob.glob(os.path.join(path, "**", "*.csv"), recursive=True)
if not csv_files:
    raise FileNotFoundError(
        "❌ Could not find any CSV files in the Kaggle Hub directory."
    )

# Sort CSVs by file size in descending order to pick the main composite dataset file
csv_files.sort(key=lambda f: os.path.getsize(f), reverse=True)
target_csv = csv_files[0]

size_mb = os.path.getsize(target_csv) / (1024 * 1024)
print(f"✅ Selected main dataset file: {target_csv} ({size_mb:.2f} MB)")

# ==========================================
# 2. EXTRACT & MAP FEATURES TO SCHEMAS
# ==========================================
print("⏳ Step 2: Processing raw dataset via chunked sampling...")

chunk_list = []
chunk_size = 50000
samples_per_chunk = 2000

for chunk in pd.read_csv(target_csv, chunksize=chunk_size, low_memory=False):
    if len(chunk) > samples_per_chunk:
        chunk_list.append(chunk.sample(n=samples_per_chunk, random_state=42))
    else:
        chunk_list.append(chunk)

df_raw = pd.concat(chunk_list, axis=0).reset_index(drop=True)
n = len(df_raw)
print(f"✅ Sampled {n} total rows across all dataset chunks.")

# Master Attack Class Mapping
attack_map = {
    "Normal": 0,
    "DDoS_UDP": 1, "DDoS_TCP": 1, "DDoS_HTTP": 1, "DoS_HTTP": 1, "DDoS_ICMP": 1,
    "Password_Bruteforce": 2, "Password": 2, "Unauthorized_Access": 2,
    "SQL_injection": 3, "Modbus_inspection": 3,
    "Port_Scanning": 4, "Vulnerability_scanner": 4, "Fingerprinting": 4,
    "Backdoor": 5, "Ransomware": 5, "XSS": 5, "Uploading": 5,
}

label_col = "Attack_type" if "Attack_type" in df_raw.columns else "Attack_label"
raw_labels = df_raw[label_col].astype(str).str.strip() if label_col in df_raw.columns else pd.Series(["Normal"] * n)
attack_ids = raw_labels.map(attack_map).fillna(0).astype(int).to_numpy()

# Safe numeric extractor
def get_numeric_col(df, col_name, default_val):
    if col_name in df.columns:
        return pd.to_numeric(df[col_name], errors='coerce').fillna(default_val).to_numpy()
    return np.full(n, default_val)

# Extract real network packet lengths and RTT
payload_bytes = get_numeric_col(df_raw, "frame.len", 300.0)
rtt_ms = get_numeric_col(df_raw, "rtt", 25.0)
tcp_retrans = get_numeric_col(df_raw, "tcp.analysis.retransmission", 0.0)

# Generate realistic conditioned EVSE telemetry based on attack signatures
cpu_util = np.where(attack_ids == 1, np.random.uniform(85.0, 100.0, n), np.random.uniform(15.0, 40.0, n))
failed_auth = np.where(attack_ids == 2, np.random.randint(5, 25, n), np.zeros(n, dtype=int))
rtt_conditioned = np.where(attack_ids == 1, rtt_ms * np.random.uniform(3.0, 10.0, n), rtt_ms)
bus_voltage = np.where(attack_ids == 3, np.random.normal(230.0, 12.0, n), np.random.normal(230.0, 1.5, n))
voltage_std = np.where(attack_ids == 3, np.random.uniform(2.0, 8.0, n), np.random.uniform(0.1, 0.5, n))
ctx_switches = np.where(attack_ids == 4, np.random.normal(1200, 200, n), np.random.normal(200, 30, n))
power_grad = np.where(attack_ids == 5, np.random.uniform(0.5, 2.5, n), np.random.uniform(0.01, 0.1, n))

mapped_df = pd.DataFrame({
    "bus_voltage_v": bus_voltage,
    "line_current_a": np.random.normal(32.0, 1.5, n),
    "active_power_kw": np.random.normal(7.36, 0.5, n),
    "temperature_c": np.where(attack_ids == 1, np.random.normal(55.0, 5.0, n), np.random.normal(35.0, 3.0, n)),
    "cpu_utilization_pct": cpu_util,
    "free_heap_bytes": np.where(attack_ids == 1, np.random.normal(20000, 5000, n), np.random.normal(120000, 10000, n)),
    "context_switch_rate": ctx_switches,
    "round_trip_time_ms": rtt_conditioned,
    "failed_auth_attempts": failed_auth,
    "packet_retransmission_pct": tcp_retrans * 100.0,
    "payload_frame_bytes": payload_bytes,
    "voltage_std_dev_5s": voltage_std,
    "power_gradient_kw_sec": power_grad,
    "packet_iat_mean_ms": get_numeric_col(df_raw, "tcp.time_delta", 50.0),
    "historical_spike_index": np.where(attack_ids != 0, 1, 0),
    "attack_class_id": attack_ids
})

os.makedirs("data", exist_ok=True)
csv_output = "data/master_evse_iiot_dataset.csv"
mapped_df.to_csv(csv_output, index=False)
print(f"✅ Preprocessed dataset saved to: {csv_output}")
# ==========================================
# 3. SPLIT & SCALE DATA
# ==========================================
feature_cols = [col for col in mapped_df.columns if col != "attack_class_id"]
X = mapped_df[feature_cols]
y = mapped_df["attack_class_id"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ==========================================
# 4. TRAIN SUPERVISED MODEL (XGBoost)
# ==========================================
print("\n[1/2] Training Supervised XGBoost Classifier...")

supervised_model = xgb.XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    objective="multi:softprob",
    num_class=len(np.unique(y)),
    random_state=42,
    eval_metric="mlogloss",
)

supervised_model.fit(X_train, y_train)

y_pred_sup = supervised_model.predict(X_test)
print("\n--- Supervised XGBoost Classification Report ---")
print(classification_report(y_test, y_pred_sup, digits=4))

# ==========================================
# 5. TRAIN UNSUPERVISED MODEL (Isolation Forest)
# ==========================================
print("\n[2/2] Training Unsupervised Isolation Forest...")

# Train exclusively on clean/normal traffic
X_train_normal_scaled = X_train_scaled[y_train == 0]

unsupervised_model = IsolationForest(
    n_estimators=100, contamination=0.05, random_state=42, n_jobs=-1
)

unsupervised_model.fit(X_train_normal_scaled)

raw_iso_preds = unsupervised_model.predict(X_test_scaled)
iso_pred_binary = np.where(raw_iso_preds == -1, 1, 0)
actual_anomaly_binary = np.where(y_test != 0, 1, 0)

print("\n--- Unsupervised Isolation Forest Report ---")
print(
    classification_report(
        actual_anomaly_binary, iso_pred_binary, target_names=["Normal", "Anomaly"]
    )
)

anomaly_scores = unsupervised_model.decision_function(X_test_scaled)
print(
    f"Isolation Forest ROC-AUC Score: {roc_auc_score(actual_anomaly_binary, -anomaly_scores):.4f}"
)

# ==========================================
# 6. EXPORT ARTIFACTS
# ==========================================
print("\nSaving trained model weights...")
supervised_model.save_model("xgboost_evse_model.json")
joblib.dump(unsupervised_model, "isolation_forest_model.pkl")
joblib.dump(scaler, "feature_scaler.pkl")

print("✅ Pipeline complete! Artifacts are ready for FastAPI.")