# Project Audit Report

## Bugs found and fixed

1. **Manual-feature interface:** the original page required users to enter all 30 ML features. It now accepts one URL and extracts the vector automatically.
2. **Export-cell dependency:** the notebook export cell assumed `X` and `y` existed. It now creates the training matrix and saves both model and feature-order artifacts.
3. **Unreachable URLs stopped prediction:** DNS/HTTP failures now result in URL-only analysis with a clear warning, not a Python error in the browser.
4. **Feature-order risk:** the app now rejects artifacts whose saved order differs from the extractor's 30 UCI feature names.
5. **Unnamed model input:** the Random Forest was trained with named columns but received an unnamed array. Predictions now use a named pandas DataFrame in the saved order.
6. **Misleading outgoing-link feature:** outgoing anchors were incorrectly used as a backlink count. That unavailable feature is now neutral rather than falsely inferred.
7. **Model-version drift:** the artifact was trained with scikit-learn 1.7.2 while the environment had 1.9.0. Requirements now pin 1.7.2.
8. **Unsafe development configuration:** Flask debug mode was enabled. It is now disabled.
9. **User-facing exception risk:** unexpected errors are logged server-side and replaced by a generic browser-safe message.
10. **Presentation ambiguity:** low-confidence/fallback predictions now show an uncertainty notice, confidence bar, reasons, and correct class colouring.

## Improvements made

- Added URL validation, redirect cap, request timeout, local/private-address blocking, response-size limit, and security headers.
- Added terminal logging for URL, feature vector, prediction, and confidence.
- Added an explanation list based on observed suspicious signals.
- Added README, this audit, and `TECHNICAL_GUIDE.md` for installation and viva preparation.
- Installed the declared dependencies in the project virtual environment and verified the Flask routes with its test client.

## Verification completed

- Saved model: 200-tree `RandomForestClassifier`, 30 inputs, classes `0` and `1`.
- Feature-order comparison: exact match between model artifact and extractor constant.
- `/`: HTTP 200 and security headers present.
- `/predict` with empty URL: friendly HTTP 400 error.
- `/predict` without protocol: friendly HTTP 400 error.
- `/predict` with unreachable URL: HTTP 200 URL-only fallback, explanation, uncertainty status, and no internal exception leakage.

## Remaining limitations and accuracy risks

The UCI data contains historical reputation features that are unavailable from live URL/page inspection: domain age, registration period, real traffic, PageRank, Google index, and backlinks. Neutral fallback values preserve the input shape but are not substitutes for those data sources. Consequently, a live prediction can differ materially from the dataset accuracy reported in the notebook. An unreachable URL is especially uncertain because page-content features cannot be observed.

The model itself was not retrained during this review. Retraining it without an updated, labelled dataset and a held-out evaluation would be an unjustified change. The recommended next step is to retrain on features that can all be measured at prediction time, or integrate trusted external providers and evaluate the resulting system.

## Suggested future enhancements

- Add rate limiting and CSRF protection before public deployment.
- Use cached WHOIS/domain-age, Safe Browsing, VirusTotal, reputation and traffic APIs with documented consent and API-key management.
- Add a current labelled test set, unit tests for each feature, and integration tests using mocked HTTP pages.
- Calibrate model probabilities and select a threshold from validation data rather than treating every 50%+ result as decisive.
- Add SHAP/LIME explanations, Docker deployment, and a structured application log.
