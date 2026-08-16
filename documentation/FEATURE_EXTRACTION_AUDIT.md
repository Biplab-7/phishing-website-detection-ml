# Feature Extraction Audit — UCI Phishing Websites Dataset (ID 327)

**Scope:** read-only audit of `feature_extractor.py`, `models/feature_columns.joblib`, the local `Training Dataset.arff`, and the local UCI feature-definition document. No model or extractor code was changed.

## Baseline verification

- The local ARFF has 30 input attributes plus `Result`; the saved model has 30 inputs.
- `FEATURE_NAMES`, the saved `feature_columns.joblib`, and ARFF input-column order are an **exact positional match**: positions 1–30 are correct.
- Dataset encoding is feature-specific, not universally ternary. In particular, several attributes are binary and **do not permit `0`**, while `Redirect` permits only `0` and `1`.
- The application currently emits neutral `0` for unavailable signals. That is structurally convenient but is out-of-distribution for binary attributes and does not mean “unknown” to this trained model.

Status key: **Correct** = same intended rule and allowed encoding; **Partial** = broadly related but incomplete or materially different; **Incorrect** = wrong rule/threshold/encoding; **Unavailable** = cannot be correctly calculated from a URL/page without a current external source.

| # | UCI feature | Position | Current audit | Dataset encoding vs current output | Live computability and best handling |
|---:|---|---:|---|---|---|
| 1 | `having_IP_Address` | 1 | **Partial.** Detects normal IPv4/IPv6 literals, but not legacy hexadecimal/IP-obfuscation forms described by UCI. | Correct `-1` / `1`. | URL-only. Add robust URL-host normalisation before deciding. |
| 2 | `URL_Length` | 2 | **Correct.** Uses `<54 → 1`, `54–75 → 0`, `>75 → -1`. | Correct `1` / `0` / `-1`. | URL-only. |
| 3 | `Shortining_Service` | 3 | **Partial.** Uses a limited, exact-host shortener list; UCI used a broader pattern/list. | Correct `1` / `-1`. | URL-only. Maintain a versioned shortener list and match normalized subdomains safely. |
| 4 | `having_At_Symbol` | 4 | **Correct.** Tests for `@` in URL. | Correct `1` / `-1`. | URL-only. |
| 5 | `double_slash_redirecting` | 5 | **Partial.** Any `//` after the scheme is flagged; UCI uses its position/rule, so path syntax can cause false positives. | Correct `1` / `-1`. | URL-only. Implement the UCI position rule exactly. |
| 6 | `Prefix_Suffix` | 6 | **Correct.** Hyphen in hostname is the intended signal. | Correct `1` / `-1`. | URL-only. |
| 7 | `having_Sub_Domain` | 7 | **Partial.** Dot-level mapping is broadly correct, but naïve label counting mishandles public suffixes such as `co.uk`. | Correct `1` / `0` / `-1`. | URL-only with a public-suffix parser. |
| 8 | `SSLfinal_State` | 8 | **Incorrect.** HTTPS alone is marked legitimate. UCI also uses certificate issuer trust and certificate age, with `0` as intermediate. | Output values allowed, but semantics are wrong and `0` is never produced. | Requires a live TLS handshake and certificate validation/metadata; otherwise mark unavailable, not `1`. |
| 9 | `Domain_registeration_length` | 9 | **Incorrect.** Always emits `0`. | ARFF permits only `-1` / `1`; current `0` is invalid. | Requires WHOIS/RDAP expiry data. Use cached RDAP or remove/retrain; do not invent `0`. |
| 10 | `Favicon` | 10 | **Partial.** Checks only `rel` containing `favicon`; common `rel=icon` is missed. | Correct `1` / `-1`. | Requires fetchable page HTML. Resolve icon URL and compare registrable domains. |
| 11 | `port` | 11 | **Partial.** Uses only visible non-standard URL port; UCI rule concerns service/port behavior. | Correct `1` / `-1`. | Partly URL-only; a real port/service check needs network probing and should be optional. |
| 12 | `HTTPS_token` | 12 | **Correct.** Flags `https` in the hostname. | Correct `1` / `-1`. | URL-only. |
| 13 | `Request_URL` | 13 | **Partial.** Thresholds match UCI (`<22`, `22–61`, `>61`), but resource tag set differs and omits iframe. | Correct `1` / `0` / `-1`. | Requires page HTML; return unavailable on fetch failure. |
| 14 | `URL_of_Anchor` | 14 | **Incorrect.** Uses 22%/61% thresholds; UCI uses `<31%`, `31–67%`, `>67%`. | Allowed values, wrong mapping. | Requires page HTML. Apply original thresholds. |
| 15 | `Links_in_tags` | 15 | **Incorrect.** Uses 22%/61%; UCI uses `<17%`, `17–81%`, `>81%`. | Allowed values, wrong mapping. | Requires page HTML. Apply original thresholds. |
| 16 | `SFH` | 16 | **Partial.** Blank/about:blank and external actions are mapped correctly; no-form and URL-normalisation cases need an explicit policy. | Correct `-1` / `0` / `1`. | Requires page HTML. |
| 17 | `Submitting_to_email` | 17 | **Partial.** Detects `mailto:` and broad `mail(` text; UCI is specifically email submission. | Correct `1` / `-1`. | Requires page HTML; inspect form actions and JavaScript patterns more precisely. |
| 18 | `Abnormal_URL` | 18 | **Incorrect.** Redirect-host comparison is not UCI’s WHOIS/domain consistency test. | Correct `1` / `-1`, wrong semantics. | Requires WHOIS/RDAP registrant/domain data; otherwise unavailable. |
| 19 | `Redirect` | 19 | **Incorrect.** Emits `-1` for many redirects. | ARFF permits only `0` / `1`; current `-1` is invalid. | Requires live HTTP redirects. Implement the source dataset’s binary forwarding rule exactly. |
| 20 | `on_mouseover` | 20 | **Partial.** Presence of `onmouseover` is too broad; UCI targets status-bar manipulation. | Correct `1` / `-1`. | Requires page HTML/JavaScript. Detect the relevant status-changing patterns. |
| 21 | `RightClick` | 21 | **Partial.** Checks only limited string patterns and misses whitespace/handler variations. | Correct `1` / `-1`. | Requires page HTML/JavaScript. |
| 22 | `popUpWidnow` | 22 | **Partial.** `window.open` is relevant, but `alert()` alone creates false positives. | Correct `1` / `-1`. | Requires page HTML/JavaScript. |
| 23 | `Iframe` | 23 | **Correct.** Detects iframe presence. | Correct `1` / `-1`. | Requires page HTML. |
| 24 | `age_of_domain` | 24 | **Incorrect.** Always emits `0`. | ARFF permits only `-1` / `1`; current `0` is invalid. | Requires WHOIS/RDAP creation date. Use cached provider data or retrain without it. |
| 25 | `DNSRecord` | 25 | **Incorrect.** Fetch failure is treated as missing DNS, although DNS may have resolved and HTTP/TLS failed. | ARFF permits only `-1` / `1`; current `0` on normal fetch is invalid. | DNS lookup itself is live-computable. Set from DNS resolution independently of page fetch. |
| 26 | `web_traffic` | 26 | **Unavailable.** Always `0`; no traffic source queried. | `0` is allowed, but is not evidence of intermediate traffic. | Requires a maintained traffic-ranking provider; otherwise remove/retrain or explicitly impute after validation. |
| 27 | `Page_Rank` | 27 | **Incorrect/Unavailable.** Always `0`. | ARFF permits only `-1` / `1`; current `0` is invalid. | Requires a comparable reputation/rank source; legacy Google PageRank is unavailable. Retraining is preferred. |
| 28 | `Google_Index` | 28 | **Incorrect/Unavailable.** Always `0`. | ARFF permits only `1` / `-1`; current `0` is invalid. | Requires an authorised search/index API; do not infer from a page fetch. |
| 29 | `Links_pointing_to_page` | 29 | **Unavailable.** Neutral `0` is deliberately used, not measured. | `0` is allowed but does not mean unknown in UCI. | Requires a backlink index/provider. Do not derive it from outgoing page links. |
| 30 | `Statistical_report` | 30 | **Incorrect.** Uses keywords/IP; UCI checks hosts against dated PhishTank/StopBadware top-domain/IP reports. | Correct `1` / `-1`, wrong semantics. | Requires an up-to-date reputation feed. Replace only with a documented current feed and retrain/evaluate. |

## Summary

**Order:** 30/30 correct. **Encoding:** 24 features use only ARFF-allowed values; 6 features currently output an explicitly invalid value for their attribute (`Domain_registeration_length`, `Redirect`, `age_of_domain`, `DNSRecord`, `Page_Rank`, `Google_Index`). **Implementation:** 5 features are substantially correct, 12 are partial, 11 are incorrect (including unavailable legacy/reputation rules), and 2 are explicitly unavailable as implemented.

## High-priority findings before any future model work

1. Do not treat `0` as an unknown value for binary UCI attributes; it is out-of-distribution for the trained forest.
2. Fix the hard threshold/encoding defects first: `URL_of_Anchor`, `Links_in_tags`, `Redirect`, `DNSRecord`.
3. Separate URL-only, HTML-dependent, DNS/TLS-dependent, WHOIS/RDAP-dependent, and reputation-provider-dependent features.
4. A fully faithful live implementation requires third-party/temporal sources that differ from those used by the 2012 dataset. The statistically honest long-term solution is a new labelled dataset and retraining with features available at inference time.
