"""
ml/train_model.py
=================
Trains a RandomForestClassifier on threat_data.csv.
Features:
  connection_count   - how many times this IP appeared in the log window
  brute_force_hits   - hits on /login, /admin, /wp-login.php
  sensitive_path_hits - hits on /.env, /config, /backup, /phpinfo.php
  error_count        - 403/404/500 responses from this IP
  unusual_port       - connected on port 4444/6667/1337/31337 (0 or 1)
  off_hours          - connection between 01:00-05:00 (0 or 1)
  upload_attempt     - POST to /upload or /api/data (0 or 1)
  in_feed            - IP found in Abuse.ch threat feed (0 or 1)
  feed_count         - number of feeds it appeared in (0, 1, or 2)
  threat_type_score  - base score for threat type (0, 20, 25, 30, 40, 50)

Label:
  is_threat          - 1 = threat, 0 = benign

Run:  python3 ml/train_model.py
Saves: ml/model.pkl, ml/feature_names.pkl
"""

import os
import pickle
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score
)
from sklearn.preprocessing import StandardScaler

# ── Load data ─────────────────────────────────────────────────────────────────
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, 'threat_data.csv')

df = pd.read_csv(DATA_PATH)

FEATURES = [
    'connection_count',
    'brute_force_hits',
    'sensitive_path_hits',
    'error_count',
    'unusual_port',
    'off_hours',
    'upload_attempt',
    'in_feed',
    'feed_count',
    'threat_type_score',
]

X = df[FEATURES]
y = df['is_threat']

print(f"Dataset:  {len(df)} rows")
print(f"Threats:  {y.sum()} ({y.mean()*100:.1f}%)")
print(f"Benign:   {(~y.astype(bool)).sum()} ({(1-y.mean())*100:.1f}%)")
print()

# ── Train / test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Train model ───────────────────────────────────────────────────────────────
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=8,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight='balanced',   # handles class imbalance
    random_state=42,
    n_jobs=-1,
)
model.fit(X_train, y_train)

# ── Evaluate ──────────────────────────────────────────────────────────────────
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)*100:.1f}%")
print()
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'Threat']))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))
print()

# Feature importances
importances = pd.Series(model.feature_importances_, index=FEATURES)
importances = importances.sort_values(ascending=False)
print("Feature Importances:")
for feat, imp in importances.items():
    bar = '█' * int(imp * 40)
    print(f"  {feat:<25} {imp:.3f}  {bar}")

# ── Save model ────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(HERE, 'model.pkl')
NAMES_PATH = os.path.join(HERE, 'feature_names.pkl')

with open(MODEL_PATH, 'wb') as f:
    pickle.dump(model, f)

with open(NAMES_PATH, 'wb') as f:
    pickle.dump(FEATURES, f)

print(f"\nModel saved → {MODEL_PATH}")
print(f"Feature names saved → {NAMES_PATH}")
