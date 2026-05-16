# Файл: ml/analysis.py
import hashlib
import re
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.ensemble import GradientBoostingClassifier

class RiskEvaluator:
    """Математична модель оцінки ризиків (CRQ) та ML"""
    
    def __init__(self):
        self.gbdt = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1)
        self.dbscan = DBSCAN(eps=0.5, min_samples=3)

    def calculate_cyber_risk(self, vulnerabilities: list, I_i: float, W_i: float, F_ml: float) -> float:
        sum_p = 0.0
        for vuln in vulnerabilities:
            likelihood = vuln.get('likelihood', 0.1)
            tef = vuln.get('threat_event_frequency', 1.0)
            sum_p += (likelihood * tef)
            
        R_i = sum_p * I_i * W_i * F_ml
        return R_i

    def calculate_privacy_risk(self, threat_char: float, privacy_impact: float) -> float:
        return (threat_char + 2 * privacy_impact) / 3.0

    def detect_shadow_it(self, network_features: np.ndarray) -> np.ndarray:
        clusters = self.dbscan.fit_predict(network_features)
        anomaly_indices = np.where(clusters == -1)[0]
        return anomaly_indices
