import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import json
import os
from datetime import datetime
from modules.utils.logger import get_logger
from models.database import Finding

logger = get_logger(__name__)

class MLAnalyzer:
    def __init__(self, db_session):
        self.db_session = db_session
        self.models_dir = "data/ml_models"
        self.ensure_models_directory()
        self.vectorizer = None
        self.classifier = None
        self.load_latest_model()

    def ensure_models_directory(self):
        """Ensure the ML models directory exists"""
        if not os.path.exists(self.models_dir):
            os.makedirs(self.models_dir)

    def load_latest_model(self):
        """Load the latest trained model"""
        try:
            model_files = [f for f in os.listdir(self.models_dir) if f.endswith('.joblib')]
            if not model_files:
                return False

            latest_model = max(model_files)
            model_path = os.path.join(self.models_dir, latest_model)
            model_data = joblib.load(model_path)

            self.vectorizer = model_data['vectorizer']
            self.classifier = model_data['classifier']
            logger.info(f"Loaded ML model: {latest_model}")
            return True

        except Exception as e:
            logger.error(f"Error loading ML model: {str(e)}")
            return False

    def train_model(self, min_samples=1000):
        """Train a new model using historical findings"""
        try:
            # Fetch training data
            findings = self.db_session.query(Finding).all()
            if len(findings) < min_samples:
                logger.warning(f"Insufficient training data: {len(findings)} samples")
                return False

            # Prepare training data
            X = []  # Features
            y = []  # Labels (false positive or not)

            for finding in findings:
                # Combine relevant features
                feature_text = f"{finding.title} {finding.description}"
                if finding.evidence:
                    feature_text += f" {finding.evidence}"
                if finding.detection_pattern:
                    pattern_data = json.loads(finding.detection_pattern)
                    feature_text += f" {json.dumps(pattern_data)}"

                X.append(feature_text)
                y.append(1 if finding.false_positive else 0)

            # Split dataset
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Feature extraction
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words='english'
            )
            X_train_vectorized = self.vectorizer.fit_transform(X_train)
            X_test_vectorized = self.vectorizer.transform(X_test)

            # Train classifier
            self.classifier = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.classifier.fit(X_train_vectorized, y_train)

            # Evaluate model
            y_pred = self.classifier.predict(X_test_vectorized)
            report = classification_report(y_test, y_pred)
            logger.info(f"Model Performance:\n{report}")

            # Save model
            model_path = os.path.join(
                self.models_dir,
                f"model_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.joblib"
            )
            joblib.dump({
                'vectorizer': self.vectorizer,
                'classifier': self.classifier
            }, model_path)

            logger.info(f"Trained and saved new ML model: {model_path}")
            return True

        except Exception as e:
            logger.error(f"Error training ML model: {str(e)}")
            return False

    def predict_false_positive(self, finding):
        """Predict if a finding is a false positive"""
        try:
            if not self.vectorizer or not self.classifier:
                logger.error("ML model not loaded")
                return None

            # Prepare feature text
            feature_text = f"{finding.title} {finding.description}"
            if finding.evidence:
                feature_text += f" {finding.evidence}"
            if finding.detection_pattern:
                pattern_data = json.loads(finding.detection_pattern)
                feature_text += f" {json.dumps(pattern_data)}"

            # Vectorize and predict
            X = self.vectorizer.transform([feature_text])
            prediction = self.classifier.predict(X)[0]
            probability = self.classifier.predict_proba(X)[0]

            return {
                'is_false_positive': bool(prediction),
                'confidence': float(max(probability)),
                'probabilities': {
                    'true_positive': float(probability[0]),
                    'false_positive': float(probability[1])
                }
            }

        except Exception as e:
            logger.error(f"Error predicting false positive: {str(e)}")
            return None

    def get_feature_importance(self, top_n=20):
        """Get the most important features for classification"""
        try:
            if not self.vectorizer or not self.classifier:
                logger.error("ML model not loaded")
                return None

            feature_names = np.array(self.vectorizer.get_feature_names_out())
            importances = self.classifier.feature_importances_
            indices = np.argsort(importances)[::-1][:top_n]

            return [{
                'feature': feature_names[i],
                'importance': float(importances[i])
            } for i in indices]

        except Exception as e:
            logger.error(f"Error getting feature importance: {str(e)}")
            return None

    def analyze_finding_batch(self, findings):
        """Analyze a batch of findings for false positives"""
        results = []
        for finding in findings:
            prediction = self.predict_false_positive(finding)
            if prediction:
                results.append({
                    'finding_id': finding.id,
                    'prediction': prediction
                })
        return results
