# Technical Guide and Viva Notes

## End-to-end prediction pipeline

1. The browser sends one complete HTTP(S) URL to `POST /predict`.
2. `feature_extractor.py` validates it, rejects private/local addresses, and safely follows at most five redirects with an eight-second timeout per request.
3. It creates the 30 values expected by the UCI-trained Random Forest.
4. `app.py` verifies the saved feature order, constructs a numeric vector in that exact order, and calls `predict()` and `predict_proba()`.
5. The response shows the chosen class, its probability, URL/page indicators, and an uncertainty warning when appropriate.

## UCI feature groups

| Group | Features | Purpose |
|---|---|---|
| URL structure | IP address, length, shortener, `@`, double slash, prefix/suffix, subdomain, port, HTTPS token | Detect deceptive URL patterns. |
| HTTPS/domain | SSL state, registration length, domain age, DNS record | Estimate domain and transport trust. |
| Page resources | favicon, request URL, anchor URL, links in tags, iframe | Detect resource loading or links that point away from the claimed site. |
| Forms/scripts | SFH, email submission, abnormal URL, redirect, mouse-over, right-click, popup | Detect suspicious page behavior. |
| Reputation | traffic, PageRank, Google index, backlinks, statistical report | Add external popularity/reputation evidence. |

Values follow the source dataset convention: `1` generally represents a legitimate signal, `-1` a suspicious signal, and `0` an intermediate/unknown value.

### Feature reference

- **having_IP_Address** — whether a raw IP address is used instead of a domain.
- **URL_Length** — short, medium or unusually long URL length.
- **Shortining_Service** — whether a recognised URL shortener is used.
- **having_At_Symbol** — whether `@` appears in the URL.
- **double_slash_redirecting** — whether an extra `//` appears after the protocol.
- **Prefix_Suffix** — whether the hostname contains a hyphen.
- **having_Sub_Domain** — number of subdomain levels.
- **SSLfinal_State** — whether the final URL uses HTTPS.
- **Domain_registeration_length** — WHOIS registration lifetime; unavailable without a WHOIS provider.
- **Favicon** — whether the favicon is hosted away from the website domain.
- **port** — whether a non-standard port is used.
- **HTTPS_token** — whether the hostname itself contains `https`.
- **Request_URL** — proportion of page resources loaded from other domains.
- **URL_of_Anchor** — proportion of empty, JavaScript, or external anchors.
- **Links_in_tags** — external links in meta/script/link tags.
- **SFH** — whether a form submits to blank or external destinations.
- **Submitting_to_email** — email-submission patterns in page content.
- **Abnormal_URL** — mismatch between the entered and final URL domain.
- **Redirect** — number of HTTP redirects.
- **on_mouseover** — mouse-over script patterns in page source.
- **RightClick** — context-menu/right-click blocking patterns.
- **popUpWidnow** — JavaScript popup patterns.
- **Iframe** — whether an iframe is present.
- **age_of_domain** — domain age; requires WHOIS data.
- **DNSRecord** — DNS availability; a lookup failure is suspicious, while other unavailable DNS details are neutral.
- **web_traffic** — external web-traffic rank; unavailable without a provider.
- **Page_Rank** — external page reputation/ranking; unavailable without a provider.
- **Google_Index** — search-engine indexing status; unavailable without a provider.
- **Links_pointing_to_page** — external backlink count; unavailable without a backlink provider.
- **Statistical_report** — URL patterns associated with known suspicious cases.

## Random Forest

A Random Forest trains many decision trees on different samples and feature subsets. Each tree votes for a class. The final classification is the majority vote. `predict_proba()` returns the fraction of trees supporting each class; for example, 0.72 means 72% of trees voted for that class. This is a model score, not proof that a site is safe.

The saved model has 200 trees and 30 input columns. Its most influential saved features are SSL state and URL-of-anchor, followed by web traffic and subdomain count. Because feature order affects every tree split, the application compares the saved order to the extractor's `FEATURE_NAMES` before prediction.

## Why results may be uncertain

Some UCI features were gathered from historical third-party sources. A live URL-only checker cannot know its past traffic, PageRank, backlinks, WHOIS registration duration, or Google indexing without external services. The project therefore uses neutral values when those signals are unavailable and labels network-fallback or sub-70% results as uncertain. This prevents a low-confidence result from being presented as a strong security decision.

## Design choices

- Requests are made with a timeout and a redirect cap to avoid hanging the web server.
- Private, loopback and reserved IP addresses are blocked to reduce server-side request forgery risk.
- Internal errors are logged in the terminal but not returned to the browser.
- The frontend uses DOM `textContent` for dynamic explanations, preventing injected URL text from becoming HTML.
- Basic response security headers reduce clickjacking and MIME-sniffing risks.

## Recommended future work

Retrain a model on features that can be consistently collected at prediction time, then evaluate it on a held-out contemporary dataset. Add safe, cached integrations for WHOIS, Google Safe Browsing, VirusTotal, reputation feeds, and domain-age data only after obtaining API keys and observing their usage policies. SHAP explanations, unit tests, Docker deployment and a rate limiter would further strengthen a production deployment.
