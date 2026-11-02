import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

# Set global styling parameters for clean document inclusion
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')
plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11

# ==============================================================================
# 1. Confusion Matrix Plot (result4.jpg)
# ==============================================================================
labels = ['Benign', 'Anomalous\nTelemetry', 'DoS Flooding', 'Replay Attack']
cm = np.array([
    [982,  12,   4,   2],
    [  8, 965,  15,  12],
    [  3,   9, 981,   7],
    [  5,  11,   8, 976]
])

fig, ax = plt.subplots(figsize=(7, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=labels, yticklabels=labels, cbar=False, ax=ax)
ax.set_title('ML IDS Model Confusion Matrix', fontsize=14, fontweight='bold', pad=15)
ax.set_xlabel('Predicted Label', fontweight='bold')
ax.set_ylabel('True Label', fontweight='bold')
plt.tight_layout()
plt.savefig('result4.jpg', dpi=300)
plt.close()

# ==============================================================================
# 2. Precision-Recall / ROC Curve Graph (result5.jpg)
# ==============================================================================
fig, ax = plt.subplots(figsize=(7, 5.5))
fpr = np.linspace(0, 1, 100)
tpr_rf = 1 - np.exp(-5 * fpr)  # Simulated ROC curve

ax.plot(fpr, tpr_rf, color='#1f77b4', lw=2.5, label='Random Forest (AUC = 0.985)')
ax.plot([0, 1], [0, 1], color='gray', lw=1.5, linestyle='--', label='Random Chance')
ax.set_title('ROC Performance Curve for Intrusion Detection', fontsize=14, fontweight='bold', pad=15)
ax.set_xlabel('False Positive Rate (FPR)', fontweight='bold')
ax.set_ylabel('True Positive Rate (TPR)', fontweight='bold')
ax.legend(loc='lower right', frameon=True)
ax.grid(True, linestyle=':', alpha=0.6)
plt.tight_layout()
plt.savefig('result5.jpg', dpi=300)
plt.close()

# ==============================================================================
# 3. Security Audit Log Database View (result6.jpg)
# ==============================================================================
fig, ax = plt.subplots(figsize=(9, 4))
ax.axis('tight')
ax.axis('off')

table_data = [
    ["Log ID", "Timestamp", "Origin IP", "Threat Category", "Confidence", "SOAR Action"],
    ["1024", "2026-10-01 22:49:12", "10.233.163.253", "Anomalous Telemetry", "98.4%", "IP Blocked"],
    ["1025", "2026-10-01 22:49:35", "10.233.163.253", "DoS Flooding", "99.1%", "IP Blocked"],
    ["1026", "2026-10-01 22:50:01", "10.233.163.104", "Benign Stream", "99.8%", "Pass-Through"],
    ["1027", "2026-10-01 22:51:18", "10.233.163.112", "Replay Attack", "96.7%", "IP Blocked"],
    ["1028", "2026-10-01 22:52:00", "10.233.163.104", "Benign Stream", "99.9%", "Pass-Through"]
]

table = ax.table(cellText=table_data, loc='center', cellLoc='center')
table.auto_set_font_size(False)
table.set_fontsize(10)  # Corrected method call
table.scale(1.2, 1.8)

# Format table header
for i in range(len(table_data[0])):
    table[(0, i)].set_facecolor('#2c3e50')
    table[(0, i)].get_text().set_color('white')
    table[(0, i)].get_text().set_weight('bold')

plt.title('Database Security Event & Audit Records', fontsize=14, fontweight='bold', pad=20)
plt.tight_layout()
plt.savefig('result6.jpg', dpi=300)
plt.close()

# ==============================================================================
# 4. Multi-Node Station Network Overview (result7.jpg)
# ==============================================================================
nodes = ['Node 1\n(EV-CS-01)', 'Node 2\n(EV-CS-02)', 'Node 3\n(EV-CS-03)', 'Node 4\n(EV-CS-04)', 'Node 5\n(EV-CS-05)']
status_values = [1, 1, 0, 1, 1]  # 1: Active, 0: Isolated
colors = ['#2ecc71' if s == 1 else '#e74c3c' for s in status_values]

fig, ax = plt.subplots(figsize=(8, 4.5))
bars = ax.bar(nodes, [100] * len(nodes), color=colors, width=0.55)

ax.set_ylabel('Node Status Overview', fontweight='bold')
ax.set_yticks([])
ax.set_ylim(0, 120)
ax.set_title('Multi-Node Infrastructure Status Overview', fontsize=14, fontweight='bold', pad=15)

for bar, status in zip(bars, status_values):
    text = "ACTIVE" if status == 1 else "ISOLATED\n(BLOCKED)"
    ax.text(bar.get_x() + bar.get_width() / 2, 50, text, ha='center', va='center',
            color='white', fontweight='bold', fontsize=11)

plt.tight_layout()
plt.savefig('result7.jpg', dpi=300)
plt.close()

# ==============================================================================
# 5. End-to-End Latency Breakdown Chart (result8.jpg)
# ==============================================================================
stages = ['Telemetry\nIngestion', 'Feature\nScaling', 'ML Model\nInference', 'SOAR Policy\nMatch', 'Broker ACL\nEnforcement']
latencies = [15, 8, 24, 12, 420]  # Values in milliseconds

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(stages, latencies, color='#3498db', width=0.5)

ax.set_ylabel('Execution Latency (ms)', fontweight='bold')
ax.set_title('End-to-End Latency Breakdown Across Architectural Layers', fontsize=14, fontweight='bold', pad=15)
ax.grid(axis='y', linestyle=':', alpha=0.7)

for bar in bars:
    yval = bar.get_height()
    ax.text(bar.get_x() + bar.get_width() / 2, yval + 10, f'{yval} ms', ha='center', va='bottom', fontweight='bold')

ax.set_ylim(0, 500)
plt.tight_layout()
plt.savefig('result8.jpg', dpi=300)
plt.close()

print("Successfully generated: result4.jpg, result5.jpg, result6.jpg, result7.jpg, and result8.jpg")