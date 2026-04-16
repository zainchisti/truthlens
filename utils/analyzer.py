import re
from typing import Dict, List, Tuple


def safe_print(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode('ascii', 'replace').decode('ascii'))


def normalize_text(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'\s+', ' ', text)

    text = text.replace('0', 'o')
    text = text.replace('1', 'l')
    text = text.replace('5', 's')
    text = text.replace('3', 'e')
    text = text.replace('4', 'a')

    text = re.sub(r'[^\w\s\.\-\:\/\?\&\=\%\@\$\+\£\€\₹]', ' ', text)

    text = re.sub(r'[|Il]', 'l', text)
    text = re.sub(r'[0Oo]', 'o', text)
    text = re.sub(r'[1Il]', 'l', text)

    text = re.sub(r'\s+', ' ', text)
    return text.strip()


CRITICAL_KEYWORDS = [
    "urgent", "act now", "limited time offer", "expires today", "immediately required",
    "winner", "you won", "congratulations", "prize", "lottery",
    "click here", "click now", "call now", "act immediately",
    "account blocked", "account suspended", "account locked", "verify account",
    "confirm identity", "confirm your account", "payment required",
    "bank details", "credit card", "debit card", "ssn", "social security",
    "bitcoin", "cryptocurrency", "money transfer", "western union",
    "gift card", "itunes card", "free money", "make money fast",
]

HIGH_RISK_KEYWORDS = [
    "suspended", "locked", "verify your identity", "password reset",
    "security alert", "unauthorized access", "suspicious activity",
    "fraud", "scam", "fake", "inheritance", "million dollars",
    "work from home", "double your money", "guaranteed", "no risk",
    "investment opportunity", "limited offer", "exclusive deal",
]

MEDIUM_RISK_KEYWORDS = [
    "confirm", "update", "verify", "secure", "account",
    "banking", "customer", "support", "help",
]

SUSPICIOUS_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "short.link", "cutt.ly", "rb.gy",
]

HIGH_RISK_TLDS = [".xyz", ".top", ".work", ".click", ".link", ".buzz", ".tk", ".ml", ".ga"]

PHISHING_KEYWORDS = [
    "login", "signin", "account", "verify", "secure", "update",
    "banking", "password", "credential", "authentication",
]


def fuzzy_match(keyword, text):
    keyword_lower = keyword.lower()
    text_normalized = normalize_text(text)

    if keyword_lower in text_normalized:
        return True

    for i in range(len(keyword_lower) - 2):
        segment = keyword_lower[i:i+3]
        if segment in text_normalized:
            return True

    return False


def detect_critical_keywords(text: str) -> Tuple[int, List[str]]:
    text_normalized = normalize_text(text)
    found = []
    score = 0

    for keyword in CRITICAL_KEYWORDS:
        if fuzzy_match(keyword, text_normalized):
            found.append(f"Critical keyword: '{keyword}'")
            score += 20

    return score, found


def detect_high_risk_keywords(text: str) -> Tuple[int, List[str]]:
    text_normalized = normalize_text(text)
    found = []
    score = 0

    for keyword in HIGH_RISK_KEYWORDS:
        if fuzzy_match(keyword, text_normalized):
            found.append(f"High-risk keyword: '{keyword}'")
            score += 15

    return score, found


def detect_medium_risk_keywords(text: str) -> Tuple[int, List[str]]:
    text_normalized = normalize_text(text)
    found = []
    score = 0

    for keyword in MEDIUM_RISK_KEYWORDS:
        if fuzzy_match(keyword, text_normalized):
            found.append(f"Suspicious keyword: '{keyword}'")
            score += 8

    return score, found


def detect_all_keywords(text: str) -> Tuple[int, List[str], Dict[str, bool]]:
    keyword_score, keyword_reasons = detect_critical_keywords(text)
    hr_score, hr_reasons = detect_high_risk_keywords(text)
    mr_score, mr_reasons = detect_medium_risk_keywords(text)

    total_score = keyword_score + hr_score + mr_score
    all_reasons = keyword_reasons + hr_reasons + mr_reasons

    text_normalized = normalize_text(text)
    indicators = {
        "has_critical": len(keyword_reasons) > 0,
        "has_high_risk": len(hr_reasons) > 0,
        "has_urgency": any(k in text_normalized for k in ["urgent", "immediately", "act now", "limited", "expires"]),
        "has_prize": any(k in text_normalized for k in ["winner", "won", "prize", "lottery", "congratulations"]),
        "has_money": any(k in text_normalized for k in ["money", "bank", "card", "payment", "transfer", "bitcoin", "rupee", "$", "₹"]),
        "has_otp": bool(re.search(r'\b\d{4,6}\b', text)),
    }

    return total_score, all_reasons, indicators


def detect_links(text: str) -> Tuple[int, List[str], bool, bool]:
    score = 0
    reasons = []
    has_shortened = False
    has_phishing_pattern = False

    text_normalized = normalize_text(text)

    url_pattern = re.compile(
        r'https?://[^\s]+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(text)

    if urls:
        reasons.append(f"URL detected ({len(urls)} found)")
        score += 25
        has_shortened = True

    for shortener in SUSPICIOUS_SHORTENERS:
        if shortener in text_normalized:
            reasons.append(f"Suspicious shortened URL: {shortener}")
            score += 30
            has_shortened = True
            break

    for tld in HIGH_RISK_TLDS:
        if tld in text_normalized:
            reasons.append(f"Suspicious domain extension: {tld}")
            score += 20
            break

    for kw in PHISHING_KEYWORDS:
        if f".com/{kw}" in text_normalized or f".net/{kw}" in text_normalized:
            reasons.append(f"Phishing URL pattern: {kw}")
            score += 30
            has_phishing_pattern = True
            break

    if "login" in text_normalized and ("verify" in text_normalized or "account" in text_normalized):
        reasons.append("Potential phishing login page")
        score += 25
        has_phishing_pattern = True

    return score, reasons, has_shortened, has_phishing_pattern


def detect_otp_patterns(text: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []

    otp_numbers = re.findall(r'\b\d{4,6}\b', text)
    if otp_numbers:
        reasons.append(f"Numeric code detected ({len(otp_numbers)} occurrences) - possible OTP")
        score += 25

    otp_keywords = ['otp', 'one time pass', 'verification code', 'security code']
    for kw in otp_keywords:
        if kw in text.lower():
            reasons.append(f"OTP/verification keyword: '{kw}'")
            score += 25
            break

    return score, reasons


def extract_urls(text: str) -> List[str]:
    url_pattern = re.compile(
        r'https?://[^\s]+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def analyze_text(text: str) -> Dict:
    safe_print(f"\n[ANALYZER] Processing text: {len(text)} chars")

    text_original = text
    text_normalized = normalize_text(text)

    safe_print(f"[ANALYZER] Original text: {text_original[:200]}...")
    safe_print(f"[ANALYZER] Normalized text: {text_normalized[:200]}...")

    total_score = 0
    all_reasons = []

    keyword_score, keyword_reasons, indicators = detect_all_keywords(text)
    total_score += keyword_score
    all_reasons.extend(keyword_reasons)
    safe_print(f"[ANALYZER] Keyword score: {keyword_score}, reasons: {len(keyword_reasons)}")

    link_score, link_reasons, has_shortened, has_phishing = detect_links(text)
    total_score += link_score
    all_reasons.extend(link_reasons)
    safe_print(f"[ANALYZER] Link score: {link_score}, reasons: {len(link_reasons)}")

    otp_score, otp_reasons = detect_otp_patterns(text)
    total_score += otp_score
    all_reasons.extend(otp_reasons)
    safe_print(f"[ANALYZER] OTP score: {otp_score}, reasons: {len(otp_reasons)}")

    combination_boost = 0
    if indicators["has_critical"] and (has_shortened or indicators["has_money"]):
        combination_boost = 25
        all_reasons.append("COMBINATION: Critical keywords with suspicious links - HIGH SCAM INDICATOR")
        safe_print(f"[ANALYZER] COMBINATION BOOST: +25")

    if indicators["has_prize"] and (has_shortened or indicators["has_money"]):
        combination_boost += 20
        all_reasons.append("COMBINATION: Prize/lottery with money request - LIKELY SCAM")
        safe_print(f"[ANALYZER] PRIZE+MONEY BOOST: +20")

    if indicators["has_urgency"] and indicators["has_otp"]:
        combination_boost += 15
        all_reasons.append("COMBINATION: Urgency with OTP request - PHISHING INDICATOR")
        safe_print(f"[ANALYZER] URGENCY+OTP BOOST: +15")

    total_score += combination_boost

    if indicators["has_critical"] and total_score < 50:
        bonus = 35
        total_score += bonus
        all_reasons.append(f"CRITICAL KEYWORD BONUS: +{bonus} (minimum score enforcement)")
        safe_print(f"[ANALYZER] CRITICAL BONUS: +35")

    if indicators["has_critical"] and indicators["has_prize"] and total_score < 80:
        bonus = 40
        total_score += bonus
        all_reasons.append(f"SCAM ENFORCEMENT: +{bonus} (obvious scam pattern)")
        safe_print(f"[ANALYZER] SCAM ENFORCEMENT: +40")

    total_score = min(total_score, 100)
    safe_print(f"[ANALYZER] FINAL SCORE: {total_score}")

    if total_score <= 40:
        classification = "Safe"
    elif total_score <= 70:
        classification = "Suspicious"
    else:
        classification = "Scam"

    safe_print(f"[ANALYZER] CLASSIFICATION: {classification}")

    return {
        "score": total_score,
        "classification": classification,
        "reasons": all_reasons,
        "urls_found": extract_urls(text),
        "indicators": indicators
    }


def generate_explanation(analysis_result: Dict, mcp_results: List[Dict]) -> str:
    classification = analysis_result["classification"]
    reasons = analysis_result["reasons"]
    indicators = analysis_result.get("indicators", {})

    explanations = []

    if classification == "Scam":
        explanations.append("This content shows clear signs of a scam. Multiple red flags detected.")

    if any("critical" in r.lower() for r in reasons):
        explanations.append("Contains critical scam keywords designed to create urgency and panic.")

    if any("prize" in r.lower() or "winner" in r.lower() for r in reasons):
        explanations.append("False prize/lottery claim - a classic scam tactic.")

    if any("shortened" in r.lower() or "phishing" in r.lower() for r in reasons):
        explanations.append("Contains suspicious links that could lead to phishing or malware sites.")

    if indicators.get("has_otp"):
        explanations.append("Requests sensitive one-time codes or verification numbers.")

    if indicators.get("has_money"):
        explanations.append("Involves money-related requests - a major scam indicator.")

    for mcp_result in mcp_results:
        if mcp_result.get("risk_level") == "high":
            explanations.append(mcp_result.get("message", ""))

    if not explanations:
        explanations.append("No obvious scam indicators were detected in this content.")

    return " ".join(explanations)


def get_suggested_action(classification: str) -> str:
    actions = {
        "Safe": "Looks safe. You may proceed with normal caution.",
        "Suspicious": "Verify before proceeding. Do additional research.",
        "Scam": "Do NOT click or share. Report this content immediately."
    }
    return actions.get(classification, "Proceed with caution.")
