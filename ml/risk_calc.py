import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.cluster import DBSCAN

class CyberRiskQuantification:
    def __init__(self):
        # Алгоритм Ансамблевого Градієнтного Бустингу (GBDT)
        self.gbdt_model = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1)
        # Просторова кластеризація для виявлення "тіньового IT"
        self.dbscan_model = DBSCAN(eps=0.5, min_samples=5)

    def calculate_asset_risk(self, vulnerabilities: list, I_i: float, W_i: float, F_ml: float) -> float:
        """
        Формула: R_i = (Sum P(v_ik, t_ik)) * I_i * W_i * F_ml
        """
        sum_p = 0.0
        for vuln in vulnerabilities:
            # P(v, t) - загальна ймовірність успішної експлуатації
            p_v_t = vuln['likelihood'] * vuln['threat_event_frequency']
            sum_p += p_v_t
            
        R_i = sum_p * I_i * W_i * F_ml
        return R_i

    def calculate_privacy_risk(self, threat_char: float, privacy_impact: float) -> float:
        """
        Спеціалізована зважена формула для витоків конфіденційності
        Privacy_Risk = (Threat_Characterisation + 2 * Privacy_Impact) / 3
        """
        return (threat_char + 2 * privacy_impact) / 3.0

    def detect_shadow_it(self, network_features: np.ndarray):
        """Виявлення аномалій (Shadow IT) за допомогою DBSCAN"""
        clusters = self.dbscan_model.fit_predict(network_features)
        # -1 означає шум (аномалію)
        anomalies = network_features[clusters == -1]
        return anomalies