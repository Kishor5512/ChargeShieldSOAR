import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier

# Set global visual style
sns.set_theme(style="whitegrid")
plt.rcParams.update({'font.size': 11})

# ==========================================
# 1. DATASET GENERATION
# ==========================================
def generate_evse_dataset(n_samples=5000, random_state=42):
    np.random.seed(random_state)
    classes = [0, 1, 2, 3, 4]  # 0: Normal, 1: DoS, 2: Injection, 3: Brute Force, 4: Anomaly
    probabilities = [0.60, 0.10, 0.10, 0.10, 0.10]
    labels = np.random.choice(classes, size=n_samples, p=probabilities)
    
    data = []
    for lbl in labels:
        if lbl == 0:  # Normal
            data.append([np.random.normal(230.0, 2.0), np.random.normal(16.0, 0.5), np.random.normal(35.0, 2.0), np.random.uniform(10, 25), 0, np.random.uniform(40.0, 60.0), 250])
        elif lbl == 1:  # DoS Flooding
            data.append([np.random.normal(230.0, 1.0), np.random.normal(32.0, 1.0), np.random.normal(45.0, 3.0), np.random.uniform(92, 100), 0, np.random.uniform(0.5, 3.0), 1450])
        elif lbl == 2:  # Payload Injection
            data.append([np.random.normal(480.0, 20.0), np.random.normal(120.0, 5.0), np.random.normal(95.0, 5.0), np.random.uniform(60, 85), 2, np.random.uniform(15.0, 25.0), 4096])
        elif lbl == 3:  # Brute Force
            data.append([230.0, 0.0, 36.0, np.random.uniform(40, 65), np.random.randint(15, 80), np.random.uniform(10.0, 20.0), 320])
        elif lbl == 4:  # Anomalous Telemetry
            data.append([np.random.normal(160.0, 15.0), np.random.normal(28.5, 2.0), np.random.normal(82.0, 4.0), np.random.uniform(30, 50), 0, np.random.uniform(40.0, 50.0), 250])

    cols = ["bus_voltage_v", "line_current_a", "temperature_c", "cpu_utilization_pct", "failed_auth_attempts", "packet_iat_mean_ms", "payload_frame_bytes"]
    df = pd.DataFrame(data, columns=cols)
    df["target"] = labels
    return df

# ==========================================
# 2. MODEL DEFINITIONS
# ==========================================
def heuristic_predict(df):
    preds = []
    for _, row in df.iterrows():
        if row["cpu_utilization_pct"] > 90.0 or row["packet_iat_mean_ms"] < 5.0:
            preds.append(1)  # DoS
        elif row["bus_voltage_v"] > 400.0 or row["payload_frame_bytes"] > 2000:
            preds.append(2)  # Injection
        elif row["failed_auth_attempts"] >= 10:
            preds.append(3)  # Brute Force
        elif row["temperature_c"] > 75.0:
            preds.append(4)  # Anomaly
        else:
            preds.append(0)  # Normal
    return np.array(preds)

class HybridModel:
    def __init__(self):
        self.rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)

    def fit(self, X, y):
        self.rf.fit(X, y)

    def predict(self, X):
        preds = []
        for _, row in X.iterrows():
            # Tier-1 Fast Heuristic Bypass
            if row["cpu_utilization_pct"] > 90.0 or row["packet_iat_mean_ms"] < 5.0:
                preds.append(1)
            elif row["bus_voltage_v"] > 400.0 or row["payload_frame_bytes"] > 2000:
                preds.append(2)
            elif row["failed_auth_attempts"] >= 10:
                preds.append(3)
            elif row["temperature_c"] > 75.0:
                preds.append(4)
            else:
                # Tier-2 Machine Learning Prediction
                row_data = row.values.reshape(1, -1)
                preds.append(self.rf.predict(row_data)[0])
        return np.array(preds)

# ==========================================
# 3. BENCHMARK EXECUTION
# ==========================================
def main():
    print("⏳ Generating Telemetry Data...")
    df = generate_evse_dataset(n_samples=5000)
    X = df.drop(columns=["target"])
    y = df["target"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    models = {
        "Heuristic Rules Only": None,
        "Support Vector Machine": SVC(kernel='rbf', C=1.0, random_state=42),
        "Random Forest Only": RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42),
        "XGBoost Classifier": XGBClassifier(n_estimators=50, max_depth=6, random_state=42),
        "ChargeShield Hybrid": HybridModel()
    }

    results = []

    print("\n🚀 Benchmarking Models...\n")
    for name, model in models.items():
        start_time = time.perf_counter()

        if name == "Heuristic Rules Only":
            y_pred = heuristic_predict(X_test)
            train_time = 0.0
        elif name == "ChargeShield Hybrid":
            model.fit(X_train, y_train)
            train_time = 0.0
            y_pred = model.predict(X_test)
        else:
            model.fit(X_train, y_train)
            train_time = 0.0
            y_pred = model.predict(X_test)

        elapsed_ms = ((time.perf_counter() - start_time) / len(X_test)) * 1000.0  # Latency per sample in ms

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average='weighted')
        rec = recall_score(y_test, y_pred, average='weighted')
        f1 = f1_score(y_test, y_pred, average='weighted')

        results.append({
            "Model": name,
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1-Score": f1,
            "Latency (ms/sample)": elapsed_ms
        })

    results_df = pd.DataFrame(results)

    print("="*80)
    print("MODEL COMPARISON BENCHMARK TABLE")
    print("="*80)
    print(results_df.to_string(index=False))

    # ==========================================
    # 4. PLOTTING COMPARISON CHARTS
    # ==========================================
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle("Model Performance Comparison for EVSE Threat Detection", fontsize=16, fontweight='bold')

    # Plot 1: F1-Score vs Accuracy
    results_df.plot(x="Model", y=["Accuracy", "F1-Score"], kind="bar", ax=axes[0], color=['#0284c7', '#16a34a'])
    axes[0].set_title("1. Detection Performance Metrics")
    axes[0].set_ylabel("Score (0.0 - 1.0)")
    axes[0].set_ylim([0.7, 1.02])
    axes[0].tick_params(axis='x', rotation=30)
    axes[0].legend(loc="lower right")

    # Plot 2: Processing Latency Comparison
    bars = axes[1].bar(results_df["Model"], results_df["Latency (ms/sample)"], color='#dc2626')
    axes[1].set_title("2. Inference Latency (Lower is Better)")
    axes[1].set_ylabel("Time per Sample (ms)")
    axes[1].tick_params(axis='x', rotation=30)

    for bar in bars:
        yval = bar.get_height()
        axes[1].text(bar.get_x() + bar.get_width()/2.0, yval + 0.002, f'{yval:.3f} ms', ha='center', va='bottom', fontweight='bold')

    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    main()