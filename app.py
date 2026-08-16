from __future__ import annotations

from pathlib import Path
from typing import Any
import logging

import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, render_template, request

from feature_extractor import FEATURE_NAMES, extract_features


BASE_DIR = Path(__file__).resolve().parent
MODELS_DIR = BASE_DIR / "models"
MODEL_PATH = MODELS_DIR / "phishing_rf_model.joblib"
FEATURE_COLUMNS_PATH = MODELS_DIR / "feature_columns.joblib"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024
app.logger.setLevel(logging.INFO)


def load_artifacts() -> tuple[Any, list[str]]:
    """Load the classifier and the exact column order used during training."""
    if not MODEL_PATH.exists() or not FEATURE_COLUMNS_PATH.exists():
        raise FileNotFoundError(
            "Model files are missing. Run the final training cell in "
            "'Phishing Website detection.ipynb' first."
        )

    model = joblib.load(MODEL_PATH)
    feature_columns = list(joblib.load(FEATURE_COLUMNS_PATH))
    if not feature_columns:
        raise ValueError("The saved feature list is empty.")
    if tuple(feature_columns) != FEATURE_NAMES:
        raise ValueError(
            "Saved model feature order does not match the extractor. Retrain or restore matching artifacts."
        )
    return model, feature_columns


def build_explanation(features: dict[str, int | str], prediction: int) -> list[str]:
    """Return small, human-readable reasons based only on observed feature values."""
    suspicious = [
        ("having_IP_Address", "The URL uses an IP address instead of a domain name."),
        ("URL_Length", "The URL is unusually long."),
        ("Shortining_Service", "A URL-shortening service is being used."),
        ("having_At_Symbol", "The URL contains an @ symbol."),
        ("Prefix_Suffix", "The domain name contains a hyphen."),
        ("having_Sub_Domain", "The URL has multiple subdomains."),
        ("SSLfinal_State", "The final URL is not using HTTPS."),
        ("HTTPS_token", "The hostname contains the word 'https'."),
        ("Submitting_to_email", "The page contains an email-submission pattern."),
        ("Iframe", "The page contains an iframe."),
        ("Statistical_report", "The URL contains a known suspicious pattern."),
    ]
    reasons = [message for name, message in suspicious if features.get(name) == -1]
    if prediction == 1 and not reasons:
        reasons.append("No strong URL-level phishing indicators were detected.")
    return reasons[:4]


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response


@app.get("/")
def index():
    from pathlib import Path

    print("Template folder:", app.template_folder)
    print("Absolute template path:", (BASE_DIR / app.template_folder / "index.html").resolve())

    try:
        load_artifacts()
        return render_template("index.html", model_ready=True)
    except (FileNotFoundError, ValueError) as error:
        return render_template("index.html", model_ready=False, error=str(error))


@app.post("/predict")
def predict():
    try:
        payload = request.get_json(silent=True)
        if payload is None:
            payload = request.form.to_dict()
        if not isinstance(payload, dict):
            raise ValueError("Send a JSON object or form field containing 'url'.")

        model, feature_columns = load_artifacts()
        extracted = extract_features(str(payload.get("url", "")))
        missing = [feature for feature in feature_columns if feature not in extracted]
        if missing:
            raise ValueError(f"The model requires unsupported features: {', '.join(missing)}")
        sample = pd.DataFrame(
            np.asarray([[extracted[feature] for feature in feature_columns]], dtype=float),
            columns=feature_columns,
        )
        prediction = int(model.predict(sample)[0])
        probabilities = model.predict_proba(sample)[0]
        classes = list(model.classes_)
        predicted_index = classes.index(prediction)
        confidence = float(probabilities[predicted_index] * 100)
        explanation = build_explanation(extracted, prediction)
        app.logger.info(
            "\n%s\nInput URL: %s\nExtracted Features: %s\nPrediction: %s\nConfidence: %.2f%%\n%s",
            "=" * 40, payload.get("url", ""),
            {name: extracted[name] for name in feature_columns},
            "Legitimate" if prediction == 1 else "Phishing", confidence, "=" * 40,
        )

        return jsonify({
            "prediction": "Legitimate" if prediction == 1 else "Phishing",
            "prediction_value": prediction,
            "confidence": round(confidence, 2),
            "url": payload.get("url", ""),
            "warning": extracted.get("__analysis_warning"),
            "explanation": explanation,
            "uncertain": confidence < 70 or bool(extracted.get("__analysis_warning")),
        })
    except (FileNotFoundError, ValueError) as error:
        app.logger.warning("Prediction request rejected: %s", error)
        return jsonify({"error": str(error)}), 400
    except Exception:
        app.logger.exception("Unexpected error while processing prediction request")
        return jsonify({"error": "Unable to analyse this website right now. Please try again."}), 500


if __name__ == "__main__":
    app.run(debug=False)
