# Phishing Website Detection using Machine Learning

This MCA final-year project classifies a user-supplied URL as **Phishing** or **Legitimate**. The workflow is preserved: URL input → feature extraction → Random Forest prediction → prediction, confidence and indicators.

## Installation and run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` and submit a complete `http://` or `https://` URL.

## Project structure

- `app.py` — Flask routes, model loading, prediction, security headers and developer logging.
- `feature_extractor.py` — URL and safely fetched page-content feature extraction.
- `models/` — Random Forest model and its exact saved feature order.
- `templates/index.html` — single-URL user interface.
- `Phishing Website detection.ipynb` — training and artifact export notebook.

## Model and confidence

The Random Forest was trained on the 30-feature UCI Phishing Websites Dataset. `feature_columns.joblib` is checked against the extractor before predictions are accepted, preventing an accidental feature-order mismatch. Confidence is the probability returned by `model.predict_proba()` for the selected class.

Scores below 70%, or predictions made without fetching the page, are marked **uncertain**. A model probability is not a guarantee of website safety.

## Important limitations

The UCI dataset includes historical features such as domain age, domain registration length, PageRank, Google indexing, traffic and backlinks. These cannot be correctly recovered from a URL alone without reliable external services. The application reports neutral values for unavailable signals, so live predictions are not directly comparable to the dataset's offline accuracy.

For a production-quality model, retrain with features available at inference time, or add trusted WHOIS, reputation, Safe Browsing and traffic providers with caching and API keys. Never visit a site solely because this demo labels it legitimate.

## Security and robustness

The application accepts only HTTP(S) URLs, blocks local/private network targets, limits redirects and request size, uses request timeouts, hides internal exceptions from users, and sends basic browser security headers. Network failures fall back to URL-only analysis and are shown as a user-friendly warning.
