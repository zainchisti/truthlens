import re
from typing import Dict, List
from urllib.parse import urlparse

KNOWN_SCAM_DOMAINS = [
    "fake-bank-login.com",
    "secure-verify-account.net",
    "prize-notification.org",
    "urgent-action-required.com",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".work", ".click", ".link", ".buzz"]

TRUSTED_DOMAINS = [
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
]


def check_url_reputation(url: str) -> Dict:
    result = {
        "tool": "check_url_reputation",
        "url": url,
        "risk_level": "low",
        "message": ""
    }

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        if not domain:
            result["risk_level"] = "medium"
            result["message"] = "Invalid URL format"
            return result

        for scam_domain in KNOWN_SCAM_DOMAINS:
            if scam_domain in domain:
                result["risk_level"] = "high"
                result["message"] = f"URL matches known scam domain: {scam_domain}"
                return result

        if domain.startswith("bit.ly") or domain.startswith("tinyurl.com") or domain.startswith("goo.gl"):
            result["risk_level"] = "medium"
            result["message"] = "Shortened URL detected - destination unknown"
            return result

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result["risk_level"] = "medium"
                result["message"] = f"Uncommon TLD ({tld}) detected"
                break

        for trusted in TRUSTED_DOMAINS:
            if trusted in domain:
                result["risk_level"] = "low"
                result["message"] = "URL appears to be from a trusted domain"
                return result

        if not result["message"]:
            result["risk_level"] = "low"
            result["message"] = "No obvious red flags detected"

    except Exception as e:
        result["risk_level"] = "medium"
        result["message"] = f"Error analyzing URL: {str(e)}"

    return result


def verify_company(name: str) -> Dict:
    result = {
        "tool": "verify_company",
        "company_name": name,
        "risk_level": "low",
        "message": ""
    }

    name_lower = name.lower()

    known_companies = [
        "google", "microsoft", "apple", "amazon", "paypal", "facebook",
        "twitter", "linkedin", "netflix", "spotify", "uber", "airbnb",
        "bank of america", "chase", "wells fargo", "citi"
    ]

    for company in known_companies:
        if company in name_lower:
            result["risk_level"] = "low"
            result["message"] = f"Company '{name}' appears to be verified"
            return result

    scam_indicators = ["inc", "llc", "corp", "holdings", "group"]
    fake_company_patterns = ["winner", "prize", "lottery", "million", "winner"]

    if any(indicator in name_lower for indicator in scam_indicators):
        if any(pattern in name_lower for pattern in fake_company_patterns):
            result["risk_level"] = "high"
            result["message"] = "Company name pattern matches known scam organizations"
            return result

    suspicious_words = ["online", "secure", "verify", "confirm", "support"]
    if any(word in name_lower for word in suspicious_words):
        result["risk_level"] = "medium"
        result["message"] = "Company name contains suspicious keywords"
    else:
        result["message"] = "Company name not found in verified database"

    return result


def check_scam_database(text: str) -> Dict:
    result = {
        "tool": "check_scam_database",
        "risk_level": "low",
        "message": ""
    }

    text_lower = text.lower()

    known_scam_phrases = [
        "you have won",
        "congratulations winner",
        "claim your prize",
        "act now",
        "limited time offer",
        "urgent security alert",
        "account will be suspended",
        "verify your account now",
        "confirm your identity",
        "click the link below",
        "call immediately",
        "money gram",
        "western union",
        "gift card",
    ]

    matches = []
    for phrase in known_scam_phrases:
        if phrase in text_lower:
            matches.append(phrase)

    if len(matches) >= 3:
        result["risk_level"] = "high"
        result["message"] = f"Content matches {len(matches)} known scam patterns: {', '.join(matches[:3])}"
    elif len(matches) >= 1:
        result["risk_level"] = "medium"
        result["message"] = f"Content contains suspicious phrase: '{matches[0]}'"
    else:
        result["risk_level"] = "low"
        result["message"] = "No matches found in scam database"

    return result


def run_mcp_tools(text: str, urls: List[str]) -> List[Dict]:
    results = []

    if urls:
        for url in urls:
            url_result = check_url_reputation(url)
            results.append(url_result)

    words = text.split()
    if len(words) >= 3:
        potential_company = ' '.join(words[:min(5, len(words))])
        company_result = verify_company(potential_company)
        results.append(company_result)

    scam_db_result = check_scam_database(text)
    results.append(scam_db_result)

    return results


def combine_mcp_score(mcp_results: List[Dict]) -> int:
    score = 0
    for result in mcp_results:
        risk = result.get("risk_level", "low")
        if risk == "high":
            score += 30
        elif risk == "medium":
            score += 15

    return min(score, 40)
