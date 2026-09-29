import pickle
import re
from urllib.parse import urlparse

from features import extract_features


# =========================
# LOAD ML MODEL
# =========================

with open("phishing_model.pkl", "rb") as file:
    model = pickle.load(file)


# =========================
# STRONG URL VALIDATION
# =========================

def validate_url(url):

    errors = []

    # Empty URL
    if not url or not url.strip():
        return ["URL cannot be empty."]

    url = url.strip()

    # Spaces
    if " " in url:
        errors.append("URL contains spaces.")

    # Basic length check
    if len(url) > 2048:
        errors.append("URL is too long.")

    # HTTP / HTTPS required
    if not re.match(r"^https?://", url, re.IGNORECASE):
        errors.append("URL must start with http:// or https://.")

    # Parse URL
    parsed = urlparse(url)

    # Scheme check
    if parsed.scheme.lower() not in ["http", "https"]:
        errors.append("Invalid URL protocol.")

    # Domain check
    if not parsed.netloc:
        errors.append("URL does not contain a valid domain.")

    # Hostname check
    hostname = parsed.hostname

    if not hostname:
        errors.append("Domain name could not be detected.")
        return errors

    # Invalid hostname characters
    if any(char in hostname for char in ["<", ">", '"', "'", "\\"]):
        errors.append("Domain contains invalid characters.")

    # Domain must contain something meaningful
    if hostname.startswith(".") or hostname.endswith("."):
        errors.append("Domain format is invalid.")

    # Consecutive dots
    if ".." in hostname:
        errors.append("Domain contains consecutive dots.")

    # Invalid port
    try:
        parsed.port
    except ValueError:
        errors.append("URL contains an invalid port.")

    return errors


# =========================
# URL SECURITY ANALYSIS
# =========================

def analyze_url(url):

    reasons = []

    parsed = urlparse(url)

    hostname = parsed.hostname

    if not hostname:
        return ["Domain name could not be detected."]

    hostname_lower = hostname.lower()

    # =========================
    # IP ADDRESS
    # =========================

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, hostname_lower):

        reasons.append(
            "URL uses an IP address instead of a domain name."
        )

    # =========================
    # HTTP WITHOUT HTTPS
    # =========================

    if parsed.scheme.lower() == "http":

        reasons.append(
            "URL does not use HTTPS."
        )

    # =========================
    # @ SYMBOL
    # =========================

    if "@" in url:

        reasons.append(
            "URL contains an @ symbol."
        )

    # =========================
    # SUSPICIOUS KEYWORDS
    # =========================

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "confirm",
        "banking",
        "signin",
        "authenticate",
        "wallet",
        "payment"
    ]

    found_words = []

    for word in suspicious_words:

        if word in url.lower():

            found_words.append(word)

    if found_words:

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_words)
        )

    # =========================
    # TOO MANY SUBDOMAINS
    # =========================

    domain_parts = hostname_lower.split(".")

    if len(domain_parts) > 4:

        reasons.append(
            "URL contains an unusually large number of subdomains."
        )

    # =========================
    # VERY LONG URL
    # =========================

    if len(url) > 150:

        reasons.append(
            "URL is unusually long."
        )

    # =========================
    # MANY HYPHENS
    # =========================

    if hostname_lower.count("-") >= 3:

        reasons.append(
            "Domain contains multiple hyphens."
        )

    return reasons


# =========================
# PHISHING DETECTION
# =========================

def detect_phishing(url):

    # =========================
    # STEP 1: URL VALIDATION
    # =========================

    validation_errors = validate_url(url)

    if validation_errors:

        return {
            "status": "INVALID",
            "message": "Please enter a valid URL.",
            "risk": 0,
            "safe_probability": 0,
            "domain": "",
            "protocol": "",
            "length": len(url),
            "reasons": validation_errors,
            "ml_prediction": "NOT_CHECKED",
            "rule_score": 0
        }

    # =========================
    # STEP 2: ML DETECTION
    # =========================

    features = extract_features(url)

    prediction = model.predict([features])[0]

    probabilities = model.predict_proba([features])[0]

    phishing_probability = probabilities[1] * 100

    safe_probability = probabilities[0] * 100

    if prediction == 1:
        ml_prediction = "PHISHING"
    else:
        ml_prediction = "SAFE"

    # =========================
    # STEP 3: SECURITY RULES
    # =========================

    parsed = urlparse(url)

    domain = parsed.netloc

    protocol = parsed.scheme

    reasons = analyze_url(url)

    # Each suspicious indicator adds rule points
    rule_score = min(len(reasons) * 15, 60)

    # =========================
    # STEP 4: HYBRID RISK
    # =========================

    hybrid_risk = (
        (phishing_probability * 0.70)
        + (rule_score * 0.30)
    )

    hybrid_risk = round(
        min(max(hybrid_risk, 0), 100),
        2
    )

    # =========================
    # STEP 5: FINAL DECISION
    # =========================

    if hybrid_risk >= 70:

        status = "PHISHING"

        message = (
            "High-risk URL detected by ML and security analysis."
        )

    elif hybrid_risk >= 40:

        status = "SUSPICIOUS"

        message = (
            "The URL contains suspicious security indicators."
        )

    else:

        status = "SAFE"

        message = (
            "No major phishing indicators were detected."
        )

    # =========================
    # STEP 6: EXTRA ML OVERRIDE
    # =========================

    # If ML strongly identifies phishing,
    # keep the result as phishing.

    if phishing_probability >= 85:

        status = "PHISHING"

        message = (
            "ML model detected a high probability of phishing."
        )

    # =========================
    # FINAL RESULT
    # =========================

    return {

        "status": status,

        "message": message,

        "risk": hybrid_risk,

        "safe_probability": round(
            safe_probability,
            2
        ),

        "domain": domain,

        "protocol": protocol,

        "length": len(url),

        "reasons": reasons,

        "ml_prediction": ml_prediction,

        "rule_score": rule_score
    }