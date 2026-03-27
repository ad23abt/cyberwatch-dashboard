"""
ml/classifier.py
================
Loads the trained RandomForest model and provides classify() and
batch_classify() for use by app.py.

Usage:
    from ml.classifier import ThreatClassifier
    clf = ThreatClassifier()
    result = clf.classify(connection_features_dict)
"""

import os
import pickle
import numpy as np
from dataclasses import dataclass, field
from typing import List, Dict, Any

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(HERE, 'model.pkl')
NAMES_PATH  = os.path.join(HERE, 'feature_names.pkl')


@dataclass
class ClassificationResult:
    is_threat: bool             # True = YES threat, False = NO threat
    verdict: str                # "THREAT" or "BENIGN"
    confidence: float           # 0.0 – 1.0
    confidence_pct: int         # 0 – 100
    top_features: List[Dict]    # which features drove the decision
    feature_values: Dict        # raw input features
    model_used: str = "RandomForestClassifier"


class ThreatClassifier:
    """Loads the trained model once; reused across requests."""

    FEATURE_NAMES = [
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

    def __init__(self, auto_train: bool = True):
        self._model = None
        self._load_or_train(auto_train)

    # ── Private ──────────────────────────────────────────────────────────────

    def _load_or_train(self, auto_train: bool):
        if os.path.exists(MODEL_PATH):
            with open(MODEL_PATH, 'rb') as f:
                self._model = pickle.load(f)
        elif auto_train:
            print("[ThreatClassifier] No model.pkl found — training now...")
            self._train()
        else:
            raise FileNotFoundError(
                "model.pkl not found. Run: python3 ml/train_model.py"
            )

    def _train(self):
        """Train model inline if pkl doesn't exist (e.g. first run)."""
        import pandas as pd
        from sklearn.ensemble import RandomForestClassifier

        data_path = os.path.join(HERE, 'threat_data.csv')
        df = pd.read_csv(data_path)

        X = df[self.FEATURE_NAMES]
        y = df['is_threat']

        self._model = RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_split=4,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X, y)

        with open(MODEL_PATH, 'wb') as f:
            pickle.dump(self._model, f)
        print("[ThreatClassifier] Model trained and saved.")

    def _build_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Build numpy row from a feature dict, defaulting missing values to 0."""
        row = [float(features.get(name, 0)) for name in self.FEATURE_NAMES]
        import pandas as pd
        return pd.DataFrame([dict(zip(self.FEATURE_NAMES, row))])

    # ── Public ───────────────────────────────────────────────────────────────

    def classify(self, features: Dict[str, Any]) -> ClassificationResult:
        """
        Classify a single connection's feature set.

        Parameters
        ----------
        features : dict with any subset of FEATURE_NAMES as keys.

        Returns
        -------
        ClassificationResult
        """
        X = self._build_feature_vector(features)
        prediction   = int(self._model.predict(X)[0])
        proba        = self._model.predict_proba(X)[0]
        # proba[0] = P(benign), proba[1] = P(threat)
        confidence   = float(proba[1]) if prediction == 1 else float(proba[0])

        # Build top features explanation from importances
        importances  = self._model.feature_importances_
        feat_contrib = []
        for name, imp in zip(self.FEATURE_NAMES, importances):
            val = float(features.get(name, 0))
            if val > 0:
                feat_contrib.append({
                    'feature':     name,
                    'value':       val,
                    'importance':  round(float(imp), 3),
                })
        feat_contrib.sort(key=lambda x: x['importance'], reverse=True)

        return ClassificationResult(
            is_threat       = bool(prediction),
            verdict         = "THREAT" if prediction else "BENIGN",
            confidence      = round(confidence, 4),
            confidence_pct  = round(confidence * 100),
            top_features    = feat_contrib[:5],
            feature_values  = {k: features.get(k, 0) for k in self.FEATURE_NAMES},
        )

    def batch_classify(self, feature_list: List[Dict]) -> List[ClassificationResult]:
        """Classify a list of feature dicts."""
        return [self.classify(f) for f in feature_list]

    def is_loaded(self) -> bool:
        return self._model is not None
