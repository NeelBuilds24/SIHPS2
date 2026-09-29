import numpy as np
import pandas as pd
from typing import Tuple, List, Dict
from sklearn.preprocessing import StandardScaler, LabelEncoder
from ml.feature_extraction import FEATURE_COLUMNS, extract_features_df

CLASSES = sorted([
    "BENIGN",
    "SYN_FLOOD",
    "UDP_FLOOD",
    "SLOWLORIS",
    "DNS_TUNNEL",
    "DGA",
    "C2_BEACON"
])

class Preprocessor:
    """Handles feature scaling, label encoding, and missing value cleaning."""
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.label_encoder.fit(CLASSES)
        self.is_fitted = False

    @property
    def classes(self) -> List[str]:
        return list(self.label_encoder.classes_)

    def clean_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace inf, -inf, NaN with valid float defaults."""
        df_clean = df.copy()
        for col in FEATURE_COLUMNS:
            if col not in df_clean.columns:
                df_clean[col] = 0.0
        
        df_clean = df_clean[FEATURE_COLUMNS]
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
        df_clean = df_clean.fillna(0.0)
        return df_clean

    def fit_transform(self, df: pd.DataFrame, labels: List[str] = None) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features, clean, scale, and encode labels."""
        X_df = extract_features_df(df)
        X_clean = self.clean_features(X_df)
        X_scaled = self.scaler.fit_transform(X_clean)
        self.is_fitted = True
        
        y_encoded = None
        if labels is not None:
            clean_labels = [l if l in self.classes else "BENIGN" for l in labels]
            y_encoded = self.label_encoder.transform(clean_labels)
            
        return X_scaled, y_encoded

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """Transform features using fitted scaler."""
        X_df = extract_features_df(df)
        X_clean = self.clean_features(X_df)
        if self.is_fitted:
            return self.scaler.transform(X_clean)
        return X_clean.values

    def decode_labels(self, encoded_labels: np.ndarray) -> List[str]:
        """Convert integer predictions back to class names."""
        return list(self.label_encoder.inverse_transform(encoded_labels))
