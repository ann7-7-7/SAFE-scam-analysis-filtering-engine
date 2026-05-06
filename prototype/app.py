from __future__ import annotations

import html
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from flask import Flask, render_template, request

app = Flask(__name__)

# --- Constants used by link detection, scoring, highlighting, and category rules ---

# http(s) and www, plus a simple pattern for "bare" hostnames that look like domains (e.g. rm-redelivery-uk.info).
URL_WITH_SCHEME = re.compile(r"https?://[^\s<>\'\"]+", re.IGNORECASE)
URL_WWW = re.compile(r"www\.[^\s<>\'\"]+", re.IGNORECASE)
# Bare domain: at least one dot, common risky TLDs; avoids 1-word false positives.
BARE_DOMAIN = re.compile(
    r"(?<![@/])\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|uk|net|org|io|info|co\.uk|xyz|online|top|buzz|click)\b"
    r"(?![a-z0-9.-]*@)",
    re.IGNORECASE,
)
# If any of these are in the *host or path* of a link, the link is treated as more suspicious (+15 with link).
LINK_SNEAKY_KEYWORDS = (
    "secure",
    "verify",
    "refund",
    "claim",
    "support",
    "login",
    "tracking",
    "redelivery",
    "update",
    "confirm",
    "suspended",
)
SHORTENER_SUBSTR = ("bit.ly", "tinyurl", "t.co", "cutt.ly", "goo.gl", "ow.ly", "rebrand.ly")

# Phrases/words for each scoring block (see analyse_message; points are per block, not per word).
URGENCY_PATTERNS = [
    r"\burgent\b",
    "urgently",
    r"\bimmediately\b",
    r"act now",
    r"limited time",
    r"within 24 hours",
    r"final warning",
    r"last chance",
    r"account suspended",
    r"account locked",
    r"legal action",
    r"\bnow\b",  # word-bounded; avoid matching inside other words
]
OTP_PATTERNS = [
    r"\botp\b",
    r"one time password",
    r"one-time password",
    r"verification code",
    r"security code",
    r"login code",
    r"\bpassword\b",
    r"passcode",
    r"verify your account",
    r"confirm your identity",
    r"\bverify\s+identity\b",
    r"\bbank login\b",
    r"\bseed phrase\b",
]
MONEY_PATTERNS = [
    "payment",
    r"\bpay\b",
    r"\bfee\b",
    "refund",
    "compensation",
    r"\blend\b",
    r"\bborrow\b",
    "pay you back",
    r"\btransfer\b",
    "bank transfer",
    "send money",
    r"\bdeposit\b",
    "investment",
    "crypto",
    "bitcoin",
    r"\bprofit\b",
    r"\bearn\b",
    r"\breward\b",
    r"\bclaim\b",
    "tax refund",
    r"\bbill\b",
    r"£\s*\d+(?:\.\d+)?",  # money amount
    r"£\d+(?:\.\d+)?",
    r"\$\d+(?:\.\d+)?",
    "usdt",
    "wallet",
    "security fee",
    "release fee",
]
# Money-request side of the emotional+money combo (peer-to-peer pleas, not only merchant “payment”).
COMBO_MONEY_REQUEST_PATTERNS = [
    r"\blend\b",
    r"\bborrow\b",
    "pay you back",
    "send money",
    "bank transfer",
    r"\bpay\b",
    r"£\s*\d+(?:\.\d+)?",
    r"£\d+(?:\.\d+)?",
    r"£",
    "payment",
    r"\bfee\b",
    r"\btransfer\b",
    r"\bbill\b",
]
# Trusted names often abused in scams. Use word boundaries for short/generic tokens like "bank".
IMPERSONATION_PHRASES = [
    "hmrc",
    "barclays",
    "lloyds",
    "hsbc",
    "natwest",
    "santander",
    "royal mail",
    "evri",
    "dpd",
    "amazon",
    "netflix",
    "paypal",
    "police",
    "nhs",
    "gov.uk",
    "microsoft",
]
# Do not treat “bank transfer” alone as impersonation (rental/marketplace use it legitimately in scams).
IMPERSONATION_EXTRA = re.compile(
    r"\bbank\b\s*(?:account|online|security|alert|statement|app)|"
    r"\b(?:hsbc|barclays|lloyds|natwest|santander)\b",
    re.IGNORECASE,
)
EMOTIONAL_PATTERNS = [
    "accident",
    "hospital",
    r"\btrouble\b",
    "emergency",
    "lost my phone",
    "new number",
    "cannot talk",
    "can't talk",
    "please help",
    r"\bhelp\b",
    r"\bstuck\b",
    r"\bbroke\b",
    r"\bmum\b",
    r"\bmom\b",
    r"\bdad\b",
    r"\bson\b",
    r"\bdaughter\b",
    "short of money",
    r"\bflight\b",
]
# Used only for the combined “emotional pressure + money request” rule (social engineering / family-style pleas).
COMBO_PRESSURE_PATTERNS = [
    r"\btrouble\b",
    r"\bhelp\b",
    r"\burgent",
    "urgently",
    "emergency",
    r"\bbroke\b",
    "lost my phone",
    "new number",
    "hospital",
    "accident",
    r"\bstuck\b",
    "cannot talk",
    "can't talk",
    "please help",
    r"\bmum\b",
    r"\bmom\b",
    r"\bdad\b",
    r"\bson\b",
    r"\bdaughter\b",
    "short of money",
    r"can you send",
]
UNREALISTIC_PATTERNS = [
    r"earn £",
    "earn money",
    "guaranteed profit",
    "no experience needed",
    "work from home",
    "selected for a job",
    "exclusive opportunity",
    "double your money",
    "daily profit",
    r"guaranteed return",
    "inner circle",
    "insider",
    "selected for inner circle",
    "guaranteed rise",
    r"double by",
]
DEVICE_COMPROMISE_PATTERNS = [
    r"\bhacked\b",
    r"phone is hacked",
    r"device is hacked",
    r"\bcompromised\b",
    r"\binfected\b",
    r"\bvirus\b",
    r"\bmalware\b",
    r"\bspyware\b",
    r"your device",
    r"save your device",
    r"camera hacked",
    r"account hacked",
]
MALWARE_DOWNLOAD_PATTERNS = [
    r"download this",
    r"install this",
    r"open this file",
    r"security update",
    r"clean your device",
    r"remove virus",
    r"download app",
    r"\bapk\b",
    r"\battachment\b",
]
FEAR_THREAT_PATTERNS = [
    r"\blocked\b",
    r"\bblocked\b",
    r"\bdeleted\b",
    r"\bexposed\b",
    r"\bleaked\b",
    r"\bwarning\b",
    r"final notice",
    r"account closed",
    r"device blocked",
    r"act now",
    r"\bimmediately\b",
    r"\burgent\b",
    r"save your device",
]

# (category name, list of (pattern, weight))
CATEGORY_DEFS: List[Tuple[str, List[Tuple[str, int]]]] = [
    (
        "Bank / Account Verification Phishing Scam",
        [
            (r"\baccount\b", 2),
            (r"\bbank\b", 2),
            (r"\bbanking\b", 2),
            (r"\blogin\b", 2),
            (r"\bverify\b", 2),
            (r"\bverification\b", 2),
            (r"\bidentity\b", 2),
            (r"unusual activity", 3),
            (r"\bsuspended\b", 3),
            (r"\blocked\b", 2),
            (r"\bclosure\b", 2),
            (r"security team", 3),
            (r"restore access", 3),
            (r"confirm details", 2),
            (r"secure-account", 3),
            (r"account verification", 3),
            (r"\botp\b", 2),
            (r"one-time code", 2),
            (r"one time code", 2),
            (r"\bpassword\b", 2),
            (r"\bpin\b", 2),
        ],
    ),
    (
        "Device Compromise / Extortion Scam",
        [
            (r"\bhacked\b", 3),
            (r"device is hacked", 3),
            (r"phone is hacked", 3),
            (r"\bcompromised\b", 2),
            (r"\binfected\b", 2),
            (r"\bvirus\b", 2),
            (r"\bmalware\b", 2),
            (r"save your device", 3),
            (r"camera hacked", 2),
            (r"account hacked", 2),
        ],
    ),
    (
        "Malware / Download Scam",
        [
            (r"download this", 3),
            (r"install this", 3),
            (r"open this file", 3),
            (r"download app", 2),
            (r"\bapk\b", 2),
            (r"\battachment\b", 2),
            (r"security update", 2),
            (r"remove virus", 2),
            (r"clean your device", 2),
        ],
    ),
    (
        "Fake Job Scam",
        [
            (r"\bjob\b", 1),
            ("remote job", 2),
            ("vacancy", 2),
            ("hiring", 2),
            ("salary", 2),
            ("work from home", 2),
            ("no experience needed", 2),
            ("no resume needed", 2),
            ("training fee", 2),
            (r"\btask\b", 1),
            ("telegram group", 2),
            ("registration fee", 2),
            ("like and subscribe", 2),
            ("youtube task", 2),
            ("tiktok task", 2),
            ("earn daily", 2),
            ("hr selected", 2),
            ("salary setup", 1),
            ("paid likes", 2),
            ("app link", 2),
            ("refundable", 1),
            (r"\bincome\b", 2),
            (r"per hour", 2),
        ],
    ),
    (
        "Bank/OTP Scam",
        [
            ("account locked", 2),
            ("suspicious activity", 2),
            (r"\botp\b", 2),
            ("verification code", 2),
            (r"\bpassword\b", 1),
            ("login code", 2),
            (r"\b(?:hsbc|barclays|lloyds|natwest|santander)\b", 1),
            (r"\bbank\b\s*(?:account|security|online|alert)", 2),
        ],
    ),
    (
        "Parcel Delivery Scam",
        [
            ("parcel", 1),
            ("delivery", 1),
            ("royal mail", 2),
            ("evri", 2),
            ("dpd", 1),
            ("redelivery", 2),
            ("tracking", 1),
            ("package", 1),
        ],
    ),
    (
        "HMRC/Tax Scam",
        [
            ("hmrc", 2),
            ("tax refund", 2),
            ("unpaid tax", 2),
            ("legal action", 1),
            ("gov.uk", 1),
        ],
    ),
    (
        "Investment/Crypto Scam",
        [
            ("bitcoin", 2),
            ("crypto", 1),
            ("investment", 1),
            ("trading", 1),
            ("exchange", 1),
            (r"\btrade\b", 1),
            ("this platform", 2),
            ("guide every trade", 3),
            (r"start with £\s*\d+", 2),
            ("usdt", 2),
            ("wallet", 2),
            ("presale", 2),
            ("inner circle", 2),
            ("signal group", 2),
            ("mentor", 1),
            ("withdrawals are blocked", 2),
            ("security fee", 2),
            ("insider", 2),
            ("guaranteed profit", 2),
            ("double your money", 2),
            ("daily profit", 2),
        ],
    ),
    (
        "Family Emergency Scam",
        [
            (r"\bmum\b", 1),
            (r"\bdad\b", 1),
            ("lost my phone", 2),
            ("new number", 2),
            ("accident", 1),
            ("hospital", 1),
            ("emergency", 1),
            ("cannot talk", 1),
            (r"\blend\b", 1),
            (r"\bborrow\b", 1),
            ("pay you back", 2),
            (r"\btrouble\b", 1),
            (r"\bhelp\b", 1),
        ],
    ),
    (
        "Subscription/Billing Scam",
        [
            ("amazon", 1),
            ("netflix", 1),
            ("prime", 1),
            ("subscription", 1),
            ("renewal", 1),
            ("charged", 1),
            ("billing", 1),
            ("payment failed", 2),
        ],
    ),
    (
        "SIM Swap Scam",
        [
            (r"sim card", 2),
            (r"sim swap", 2),
            ("mobile service", 1),
            ("number transfer", 2),
            ("disconnected", 1),
            ("verify identity", 1),
        ],
    ),
    (
        "Wrong Number Scam",
        [
            # Deliberately strict: "are we still meeting" alone is common in legitimate messages (see viva test).
            ("wrong number", 3),
            ("sorry wrong number", 3),
            ("you seem nice", 2),
            (r"have the wrong (?:number|person)", 2),
        ],
    ),
    (
        "Compensation Scam",
        [
            ("compensation", 2),
            (r"\bclaim\b", 1),
            ("mis-selling", 2),
            ("processing fee", 2),
        ],
    ),
]

WARNING_LABELS = {
    "link": "Suspicious link detected",
    "urgency": "Urgency or pressure language detected",
    "otp": "OTP/password/code request detected",
    "money": "Money/payment request detected",
    "impersonation": "Possible trusted organisation impersonation detected",
    "emotional": "Emotional pressure or emergency language detected",
    "unrealistic": "Unrealistic income/profit offer detected",
    "combo_emotional_money": "Urgency or emotional pressure combined with money request detected",
    "task_fake_job": "Task-based fake job offer detected",
    "unrealistic_job_high_earn": "Unrealistic job offer with high earnings detected",
    "unrealistic_simple_online": "Unrealistic earnings for simple online actions detected",
    "transfer_over_50": "Request to transfer more than £50 detected",
    "strong_pattern": "Strong scam pattern detected",
    "deposit_before": "Deposit/payment before viewing or verification detected",
    "authority_bec": "Authority impersonation or business payment request detected",
    "link_org": "Suspicious link combined with trusted organisation name",
    "urgency_money": "Urgency combined with a money request",
    "otp_link": "OTP/password/code request combined with a link",
    "pay_before_item": "Payment requested before viewing, collection, or handover",
    "unreal_easy": "Unrealistic reward/earning combined with ‘no experience’ or easy-task wording",
    "device_compromise": "Device compromise claim detected",
    "download_instruction": "Download instruction detected",
    "fear_pressure": "Fear pressure detected",
    "money_demand": "Money demand detected",
    "extortion_combo": "Attempts to pressure the user into quick action",
    "account_suspension_claim": "Account suspension claim detected",
    "verification_request": "Verification request detected",
    "generic_security_sender": "Generic security sender detected",
    "urgency_pressure": "Urgency pressure detected",
    "remote_work_offer": "Remote work/job opportunity detected",
    "weekly_pay_language": "Weekly pay or income language detected",
    "unverified_job_offer": "Unverified job offer detected",
}

# When lend/borrow + distress cues appear together, use this instead of generic band text.
SAFETY_ADVICE_COMBO_EMOTIONAL_MONEY = (
    "Do not send money. Contact the person using their old trusted number or "
    "another verified method before taking action."
)

SAFETY_BY_BAND = {
    "Low": "Low risk detected. Still be careful and only use official websites or apps.",
    "Medium": "Be cautious. Do not click links or share personal details unless you can verify the sender through an official source.",
    "High": "This message shows strong scam indicators. Do not click links, do not send money, and do not share personal or banking details.",
    "Critical": "This message is highly likely to be a scam. Do not click any links, do not send money, do not share codes or passwords, and contact the organisation directly using an official phone number or app.",
}
SAFETY_ADVICE_DEVICE_EXTORTION = (
    "Do not send money. Do not download unknown files or apps. Do not click suspicious links. "
    "Run a trusted antivirus/security scan if concerned, and contact the official device/account provider through official channels."
)

# --- Scoring pipeline (see analyse_message) ---
# 1) Base indicators — _base_indicator_score: independent buckets (link tiers, urgency, OTP, money,
#    impersonation, emotional, unrealistic). These are the same signals used for warning flags.
# 2) Category-specific boosts — _strong_category_hits + STRONG_BOOST: one AND-style strong pattern
#    per category; only the single highest-priority winner (CATEGORY_PRIORITY) adds its points.
# 3) Combination boosts — _global_combination_boosts: cross-signal rules (e.g. link + trusted name,
#    urgency + money) applied after the base score; all matching rules stack until the 100 cap.
# 4) Category label — winning strong pattern if any; else keyword fallbacks / Family combo /
#    Unknown/Suspicious; Likely Safe when score and major flags are all low (safe protection).
# --- Category priority (most specific first). Used when several “strong pattern” detectors fire. ---
CATEGORY_PRIORITY: List[str] = [
    "Bank / Account Verification Phishing Scam",
    "Bank/OTP Scam",
    "Parcel Delivery Scam",
    "HMRC/Tax Scam",
    "Rental Scam / Advance Fee Fraud",
    "Device Compromise / Extortion Scam",
    "Fake Job Scam",
    "Malware / Download Scam",
    "Investment/Crypto Scam",
    "Family Emergency Scam",
    "Romance Scam",
    "Marketplace Scam",
    "Subscription/Billing Scam",
    "SIM Swap Scam",
    "Compensation Scam",
    "CEO / Business Email Compromise Scam",
    "Tech Support Scam",
    "Wrong Number Scam",
]

# Dedicated phishing context for bank/account verification scams
_BANK_ACCOUNT_VERIFY_CONTEXT = re.compile(
    r"\b(account|bank|banking|login|verify|verification|identity|unusual activity|suspended|locked|closure|restore access|confirm details|secure-account|account verification|otp|one[- ]time code|password|pin|security team)\b",
    re.I,
)
_ACCOUNT_SUSPENSION_CLAIM = re.compile(
    r"(account\s+(?:has\s+been\s+)?(?:temporarily\s+)?suspended|account\s+locked|account\s+closure|permanent account closure|restore access)",
    re.I,
)
_VERIFICATION_REQUEST = re.compile(
    r"(verify(?:\s+your)?\s+(?:information|account|identity|details)?|verify\s+(?:immediately|now)|verification\s+(?:required|request)|confirm\s+details)",
    re.I,
)
_GENERIC_SECURITY_SENDER = re.compile(
    r"(security team|account team|support team|dear customer)",
    re.I,
)


def _detect_bank_account_verification_phishing_strong(lowered: str) -> bool:
    """High-confidence bank/account verification phishing."""
    has_link = _has_link(lowered)
    has_verify_context = bool(_BANK_ACCOUNT_VERIFY_CONTEXT.search(lowered))
    has_suspend = bool(_ACCOUNT_SUSPENSION_CLAIM.search(lowered))
    has_verify_request = bool(_VERIFICATION_REQUEST.search(lowered))
    has_urgency = _match_any(lowered, URGENCY_PATTERNS)
    # fallback requested by user: link + urgency + account/verification/suspended wording
    fallback_combo = has_link and has_urgency and (
        bool(re.search(r"\b(account|verification|verify|suspended|locked|closure)\b", lowered, re.I))
    )
    return bool((has_link and has_verify_context and (has_suspend or has_verify_request)) or fallback_combo)


def _has_link(lowered: str) -> bool:
    return bool(_collect_url_strings(lowered)) or bool(URL_WITH_SCHEME.search(lowered)) or bool(URL_WWW.search(lowered))


# --- UK amount extraction (for transfer and hourly fake-job rules) ---
def _collect_gbp_amounts(lowered: str) -> List[float]:
    """Extract numeric GBP values from common UK money spellings."""
    amounts: List[float] = []
    for m in re.finditer(r"£\s*(\d+(?:\.\d+)?)", lowered, re.I):
        amounts.append(float(m.group(1)))
    for m in re.finditer(r"£\s*(\d+)\s*-\s*£\s*(\d+)", lowered, re.I):
        amounts.extend([float(m.group(1)), float(m.group(2))])
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s*to\s*(\d+(?:\.\d+)?)\s*pounds?", lowered, re.I):
        amounts.extend([float(m.group(1)), float(m.group(2))])
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s+pounds?", lowered, re.I):
        amounts.append(float(m.group(1)))
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s+pound\b", lowered, re.I):
        amounts.append(float(m.group(1)))
    return amounts


def _max_gbp_amount(lowered: str) -> float:
    vals = _collect_gbp_amounts(lowered)
    return max(vals) if vals else 0.0


def _max_hourly_gbp_rate(lowered: str) -> float:
    """Largest £/hour (or pounds per hour) rate mentioned; 0 if none."""
    rates: List[float] = []
    for m in re.finditer(
        r"(\d+(?:\.\d+)?)\s*to\s*(\d+(?:\.\d+)?)\s*pounds?\s*per\s*(?:hour|hrs?|hr)\b",
        lowered,
        re.I,
    ):
        rates.append(float(m.group(1)))
        rates.append(float(m.group(2)))
    for m in re.finditer(r"£\s*(\d+(?:\.\d+)?)\s*(?:/|per)\s*(?:hour|hrs?|hr)\b", lowered, re.I):
        rates.append(float(m.group(1)))
    for m in re.finditer(r"£\s*(\d+)\s+per\s*(?:hour|hrs?|hr)\b", lowered, re.I):
        rates.append(float(m.group(1)))
    for m in re.finditer(r"(\d+(?:\.\d+)?)\s*pounds?\s*per\s*(?:hour|hrs?|hr)\b", lowered, re.I):
        rates.append(float(m.group(1)))
    for m in re.finditer(r"(?:earn|pay)\s+£\s*(\d+)\s*per\s*(?:hour|hrs?|hr)\b", lowered, re.I):
        rates.append(float(m.group(1)))
    return max(rates) if rates else 0.0


_TASK_ACTIVITY = re.compile(
    r"\blike\s+videos?|like(?:ing)?\s+videos?|liking\s+videos?|\bliking\b.*\b(?:video|youtube)\b|"
    r"\bclicks?\b|"
    r"\bsubscribe\b|\bshare\b|\bfollow\b|"
    r"rate\s+products?|rating\s+products?|\breviews?\b|"
    r"complete\s+tasks?|simple\s+tasks?|\byoutube\b",
    re.I,
)
_EARN_OR_WAGE = re.compile(
    r"\bearn\b|\bper\s+hour\b|\bper\s+hrs?\b|\bhourly\b|\bdaily\b|£\s*\d|\d+\s*pounds?|\bpay\b",
    re.I,
)
_EASY_OR_REMOTE_JOB = re.compile(r"no experience|easy job|work from home|remote job", re.I)
_MEDIUM_JOB_INDICATORS = re.compile(
    r"(remote work|remote job|work opportunity|job opportunity|flexible hours|weekly pay|message us if interested|part-?time opportunity|online job|job offer)",
    re.I,
)
_JOB_PAYMENT_PRESSURE = re.compile(
    r"(registration fee|training fee|deposit|telegram group|whatsapp group|join our (?:telegram|whatsapp)|pay\s*(?:£|\d)|payment required|bank transfer|send money|upfront fee)",
    re.I,
)
_TRANSFER_VERB = re.compile(
    r"\bsend\s+me\b|\btransfer\b|bank\s+transfer|\blend\s+me\b|\bborrow\b|pay\s+me\b|pay\s+a\s+bill|\bdeposit\b|"
    r"send\s+money|can\s+you\s+send|can\s+you\s+transfer|please\s+send|\bsend\s+now\b",
    re.I,
)
_TRANSFER_PRESSURE = re.compile(
    r"urgent|urgently|\bnow\b|today|trouble|emergency|hospital|accident|broke|lost my phone|new number|"
    r"cannot talk|can't talk|stuck|\bhelp\b",
    re.I,
)
_FAMILY_CONTEXT = re.compile(
    r"\bmum\b|\bmom\b|\bdad\b|\bson\b|\bdaughter\b|lost my phone|new number",
    re.I,
)


def _detect_rental_strong(lowered: str) -> bool:
    """K. Deposit / viewing / property rental fraud."""
    prop = re.search(
        r"\b(room|rent|rental|deposit|property|viewing|keys|contract|furnished|landlord)\b",
        lowered,
        re.I,
    )
    money = re.search(
        r"(bank transfer|send (?:a )?deposit|\bdeposit\b|payment|pay\b|£\s*\d)",
        lowered,
        re.I,
    )
    pressure = re.search(
        r"(before viewing|secure the room|high demand|must send|to secure)",
        lowered,
        re.I,
    )
    return bool(prop and money and pressure)


def _detect_ceo_bec_strong(lowered: str) -> bool:
    """N. Business email compromise style."""
    biz = re.search(r"\b(supplier|invoice|transfer|payment|wire)\b", lowered, re.I)
    auth = re.search(
        r"(in a meeting|urgently|please do it now|confirm once|asap|need you to|ceo|director|executive)",
        lowered,
        re.I,
    )
    return bool(biz and auth)


def _detect_romance_strong(lowered: str) -> bool:
    """L. Relationship trust + money."""
    rel = re.search(
        r"(enjoy talking|talking to you|want to visit|i promise|short of money|miss you|love you)",
        lowered,
        re.I,
    )
    money = re.search(
        r"(send £|£\s*\d|£\d|can you send|money for|flight|lend|borrow|pay you back)",
        lowered,
        re.I,
    )
    return bool(rel and money)


def _detect_marketplace_strong(lowered: str) -> bool:
    """M. Marketplace payment-before-collection."""
    item = re.search(
        r"\b(item|reserve|reserved|still available|collection|delivery|buyer)\b",
        lowered,
        re.I,
    )
    pay = re.search(r"(bank transfer|payment first|send payment|pay first|many people are interested|high demand)", lowered, re.I)
    return bool(item and pay)


def _detect_fake_job_strong(lowered: str) -> bool:
    """A. Task / earn-at-home style (must include job/task indicators)."""
    job = re.search(
        r"\b(job|remote job|vacancy|hiring|salary|income|work from home|part-?time|\btasks?\b|simple task|like and subscribe|youtube task|tiktok task|telegram group|registration fee|no experience required|no experience needed)\b",
        lowered,
        re.I,
    ) or _TASK_ACTIVITY.search(lowered)
    lure = re.search(
        r"(earn|per hour|per hr|per hrs|daily|youtube|tiktok|task|registration fee|salary|income|work from home)",
        lowered,
        re.I,
    )
    return bool(job and lure)


def _detect_fake_job_medium(lowered: str) -> bool:
    """
    Medium-strength fake-job/task cues that should not be treated as Likely Safe.
    This path is for early-stage job lures without direct upfront payment pressure.
    """
    has_job_cues = bool(_MEDIUM_JOB_INDICATORS.search(lowered))
    has_income_language = bool(re.search(r"(weekly pay|income|salary|earn)", lowered, re.I))
    has_payment_pressure = bool(_JOB_PAYMENT_PRESSURE.search(lowered))
    unrealistic_high_pay = bool(_max_hourly_gbp_rate(lowered) > 15)
    return bool(has_job_cues and has_income_language and not has_payment_pressure and not unrealistic_high_pay)


def _detect_bank_otp_strong(lowered: str) -> bool:
    """B. Requires bank/security context — not ‘bank transfer’ alone."""
    sec = re.search(
        r"(account locked|suspicious activity|security alert|unusual login|verify your identity|"
        r"confirm your identity|online banking|banking app|otp|password|verification code|login code)",
        lowered,
        re.I,
    )
    # Named institutions or true “banking” context — not the phrase “bank transfer” on its own.
    bankish = re.search(
        r"\b(hsbc|barclays|lloyds|natwest|santander|paypal)\b",
        lowered,
        re.I,
    ) or re.search(
        r"\bbank\b\s*(?:account|security|online|alert|statement|app|details)",
        lowered,
        re.I,
    )
    if not sec:
        return False
    if bankish:
        return True
    return bool(re.search(r"https?://", lowered))


def _detect_parcel_strong(lowered: str) -> bool:
    """C."""
    carrier = re.search(r"(parcel|delivery|redelivery|royal mail|\bevri\b|\bdpd\b|package|tracking)", lowered, re.I)
    pay = re.search(r"(pay|fee|payment|£\s*\d|£\d|http)", lowered, re.I)
    return bool(carrier and pay)


def _detect_hmrc_strong(lowered: str) -> bool:
    """D."""
    tax = re.search(r"(hmrc|unpaid tax|tax refund|gov\.uk|legal action)", lowered, re.I)
    hook = re.search(r"(refund|pay|payment|http|urgent|within 24|hours)", lowered, re.I)
    return bool(tax and hook)


def _detect_investment_strong(lowered: str) -> bool:
    """E."""
    inv = re.search(r"(crypto|bitcoin|trading|investment|forex|exchange|\btrade\b|\bplatform\b)", lowered, re.I)
    hype = re.search(r"(guaranteed profit|double your money|high return|limited slot|daily profit|guaranteed)", lowered, re.I)
    guided_trade_pitch = re.search(
        r"(start with £\s*\d+|start with \d+\s*pounds?|guide every trade|i will guide every trade|mentor you)",
        lowered,
        re.I,
    )
    return bool((inv and hype) or (inv and guided_trade_pitch and re.search(r"£\s*\d+|\d+\s*pounds?", lowered, re.I)))


def _detect_investment_social_grooming_strong(lowered: str) -> bool:
    """E2. Investment grooming with social persuasion + money intent."""
    inv_ctx = re.search(r"(crypto|bitcoin|trading|investment|trade|platform|wallet|usdt|presale|signal group|inner circle|exchange)", lowered, re.I)
    social_pitch = re.search(
        r"(trust me|i care about your future|mentor|guide every trade|insider|selected for inner circle|don't tell family|don’t tell family|share your screen|before market opens|guaranteed rise)",
        lowered,
        re.I,
    )
    money = re.search(
        r"(£\s*\d+|\d+\s*pounds?|\b\d+\b|start with \d+|send|transfer|deposit|fund this wallet|security fee|release fee)",
        lowered,
        re.I,
    )
    return bool(inv_ctx and (social_pitch or money))


def _detect_family_emergency_strong(lowered: str) -> bool:
    """F. Named-family or classic emergency cues plus a concrete money movement request."""
    fam = re.search(
        r"(\bmum\b|\bmom\b|\bdad\b|\bson\b|\bdaughter\b|lost my phone|new number|hospital|accident|emergency|cannot talk|can't talk)",
        lowered,
        re.I,
    )
    money = re.search(
        r"(£\s*\d|£\d|transfer|send money|payment|\bpay\b|lend|borrow|send now|please send|can you send|can you transfer)",
        lowered,
        re.I,
    )
    return bool(fam and money)


def _detect_subscription_strong(lowered: str) -> bool:
    """G."""
    brand = re.search(
        r"(amazon|netflix|\bprime\b|subscription|billing|payment failed|renewal|charged)",
        lowered,
        re.I,
    )
    hook = re.search(r"(http|urgent|within 24|suspended|locked|update billing)", lowered, re.I)
    return bool(brand and hook)


def _detect_sim_swap_strong(lowered: str) -> bool:
    """H."""
    sim = re.search(r"(sim card|sim swap|new sim|number transfer|disconnected|verify identity|mobile service)", lowered, re.I)
    hook = re.search(r"(urgent|urgently|http|immediately|verify here)", lowered, re.I)
    return bool(sim and hook)


def _detect_wrong_number_strong(lowered: str) -> bool:
    """I."""
    return bool(
        re.search(
            r"(wrong number|you seem nice|are you single|chat on whatsapp|sorry wrong number)",
            lowered,
            re.I,
        )
    )


def _detect_compensation_strong(lowered: str) -> bool:
    """J."""
    comp = re.search(r"(compensation|ppi|mis-?selling|you are owed|owed you|refund owed)", lowered, re.I)
    fee = re.search(r"(processing fee|release your claim|pay a|pay the|http|£\s*\d)", lowered, re.I)
    return bool(comp and fee)


def _detect_tech_support_strong(lowered: str) -> bool:
    """O."""
    tech = re.search(
        r"(microsoft|apple|security alert|your computer|virus|malware|infected|tech support|data loss)",
        lowered,
        re.I,
    )
    fear = re.search(r"(call (?:our )?(?:support|team)|immediately|right now|prevent)", lowered, re.I)
    return bool(tech and fear)


def _detect_device_extortion_strong(lowered: str) -> bool:
    """P."""
    device = _match_any(lowered, DEVICE_COMPROMISE_PATTERNS)
    money = bool(
        re.search(
            r"(send money|send\s+\d+|send\s+£|\bpay\b|\bpayment\b|\btransfer\b|bank transfer|\bfee\b|\bdeposit\b|release fee|\b\d+\s*pounds?\b|\bpounds?\b)",
            lowered,
            re.I,
        )
    )
    return bool(device and money)


def _detect_malware_download_strong(lowered: str) -> bool:
    """Q."""
    download = _match_any(lowered, MALWARE_DOWNLOAD_PATTERNS)
    risky_context = _match_any(lowered, DEVICE_COMPROMISE_PATTERNS) or _match_any(lowered, FEAR_THREAT_PATTERNS)
    return bool(download and risky_context)


def _strong_category_hits(lowered: str) -> Dict[str, bool]:
    """Which category-specific ‘strong pattern’ detectors fired (for boost + label priority)."""
    return {
        "Bank / Account Verification Phishing Scam": _detect_bank_account_verification_phishing_strong(lowered),
        "Rental Scam / Advance Fee Fraud": _detect_rental_strong(lowered),
        "Device Compromise / Extortion Scam": _detect_device_extortion_strong(lowered),
        "Malware / Download Scam": _detect_malware_download_strong(lowered),
        "CEO / Business Email Compromise Scam": _detect_ceo_bec_strong(lowered),
        "Family Emergency Scam": _detect_family_emergency_strong(lowered),
        "Romance Scam": _detect_romance_strong(lowered),
        "Marketplace Scam": _detect_marketplace_strong(lowered),
        "Bank/OTP Scam": _detect_bank_otp_strong(lowered),
        "Parcel Delivery Scam": _detect_parcel_strong(lowered),
        "HMRC/Tax Scam": _detect_hmrc_strong(lowered),
        "Investment/Crypto Scam": _detect_investment_strong(lowered) or _detect_investment_social_grooming_strong(lowered),
        "Subscription/Billing Scam": _detect_subscription_strong(lowered),
        "SIM Swap Scam": _detect_sim_swap_strong(lowered),
        "Compensation Scam": _detect_compensation_strong(lowered),
        "Fake Job Scam": _detect_fake_job_strong(lowered),
        "Tech Support Scam": _detect_tech_support_strong(lowered),
        "Wrong Number Scam": _detect_wrong_number_strong(lowered),
    }


STRONG_BOOST: Dict[str, int] = {
    "Bank / Account Verification Phishing Scam": 45,
    "Rental Scam / Advance Fee Fraud": 45,
    "Device Compromise / Extortion Scam": 45,
    "Malware / Download Scam": 40,
    "CEO / Business Email Compromise Scam": 45,
    "Family Emergency Scam": 40,
    "Romance Scam": 40,
    "Marketplace Scam": 40,
    "Bank/OTP Scam": 40,
    "Parcel Delivery Scam": 40,
    "HMRC/Tax Scam": 40,
    "Investment/Crypto Scam": 45,
    "Subscription/Billing Scam": 40,
    "SIM Swap Scam": 40,
    "Compensation Scam": 40,
    "Fake Job Scam": 35,
    "Tech Support Scam": 35,
    # +25 alone sits on the Low/Medium boundary; +40 targets Medium for grooming-only texts.
    "Wrong Number Scam": 40,
}


def _pick_category_by_priority(strong_hits: Dict[str, bool]) -> str | None:
    """Return the single highest-priority category that has a strong hit."""
    for name in CATEGORY_PRIORITY:
        if strong_hits.get(name):
            return name
    return None


def _match_any(text_lower: str, patterns: List[str]) -> bool:
    for p in patterns:
        if re.search(p, text_lower, re.IGNORECASE):
            return True
    return False


def _words_in_link_parts(url: str) -> bool:
    u = url.lower()
    for w in LINK_SNEAKY_KEYWORDS:
        if w in u:
            return True
    return False


def _is_shortener(url: str) -> bool:
    u = url.lower()
    return any(s in u for s in SHORTENER_SUBSTR)


def _impersonation_match(lowered: str) -> bool:
    if IMPERSONATION_EXTRA.search(lowered):
        return True
    return any(p in lowered for p in IMPERSONATION_PHRASES)


def _collect_url_strings(text: str) -> List[str]:
    out: List[str] = []
    for rx in (URL_WITH_SCHEME, URL_WWW):
        out.extend(rx.findall(text))
    for m in BARE_DOMAIN.finditer(text):
        g = m.group(0)
        # skip if it looks like an email (handled by BARE_DOMAIN negative lookahead) or if already in http match
        if g and g not in " ".join(out):
            out.append(g)
    # dedupe keeping order
    seen: set[str] = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _score_block_flags(lowered: str) -> Dict[str, bool]:
    """Which warning buckets fired (used for labels and to spot 'major' red flags)."""
    flags = {
        "link": False,
        "link_sneaky": False,
        "link_shortener": False,
        "urgency": _match_any(lowered, URGENCY_PATTERNS),
        "otp": _match_any(lowered, OTP_PATTERNS),
        "money": _match_any(lowered, MONEY_PATTERNS),
        "money_demand": bool(
            re.search(
                r"(send money|send\s+\d+|send\s+£|pay\s*(?:£|\d)|\bpayment\b|\btransfer\b|bank transfer|\bfee\b|\bdeposit\b|registration fee|upfront fee|release fee)",
                lowered,
                re.I,
            )
        ),
        "impersonation": _impersonation_match(lowered),
        "emotional": _match_any(lowered, EMOTIONAL_PATTERNS),
        "unrealistic": _match_any(lowered, UNREALISTIC_PATTERNS),
        "device_compromise": _match_any(lowered, DEVICE_COMPROMISE_PATTERNS),
        "malware_download": _match_any(lowered, MALWARE_DOWNLOAD_PATTERNS),
        "fear_pressure": _match_any(lowered, FEAR_THREAT_PATTERNS),
        "account_suspension_claim": bool(_ACCOUNT_SUSPENSION_CLAIM.search(lowered)),
        "verification_request": bool(_VERIFICATION_REQUEST.search(lowered)),
        "generic_security_sender": bool(_GENERIC_SECURITY_SENDER.search(lowered)),
    }
    urls = _collect_url_strings(lowered)
    if urls:
        flags["link"] = True
    for u in urls:
        if _is_shortener(u):
            flags["link_shortener"] = True
        if _words_in_link_parts(u) or re.search(
            r"[\-]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", u
        ):
            flags["link_sneaky"] = True
    # If message has a URL, check message-level sneaky words near links (entire text already scanned in link path).
    for u in urls:
        if any(k in u for k in ("secure", "verify", "refund", "claim", "support", "login", "tracking", "redelivery")):
            flags["link_sneaky"] = True
    combo_press = _match_any(lowered, COMBO_PRESSURE_PATTERNS)
    combo_money = _match_any(lowered, COMBO_MONEY_REQUEST_PATTERNS)
    flags["combo_emotional_money"] = combo_press and combo_money
    # Extortion should represent direct payment pressure tied to compromise claims.
    flags["extortion_combo"] = flags["device_compromise"] and flags["money_demand"]
    return flags


def _any_major(flags: Dict[str, bool]) -> bool:
    """True if any standalone red-flag bucket fired (used for Likely Safe vs Unknown)."""
    return bool(
        flags.get("link")
        or flags.get("urgency")
        or flags.get("otp")
        or flags.get("money")
        or flags.get("impersonation")
        or flags.get("emotional")
        or flags.get("unrealistic")
        or flags.get("money_demand")
        or flags.get("device_compromise")
        or flags.get("malware_download")
        or flags.get("fear_pressure")
        or flags.get("combo_emotional_money")
    )


def _base_indicator_score(lowered: str, flags: Dict[str, bool], matched: List[str]) -> int:
    """
    Base score from independent red-flag buckets (links, urgency, OTP, money, etc.).
    Does not include category-specific strong-pattern boosts or cross-signal combination boosts
    (those are applied in _compute_total_score).
    """
    score = 0

    if flags["link"]:
        score += 25
        matched.append("links detected in the message (http, www, or web-like address)")
    if flags["link_sneaky"]:
        score += 15
        matched.append("link text/path suggests phishing-style wording (e.g. verify, redelivery, secure)")
    if flags["link_shortener"]:
        score += 20
        matched.append("shortened URL (bit.ly, tinyurl, t.co, cutt.ly, etc.)")

    if flags["urgency"]:
        score += 15
        matched.append("urgency/pressure phrasing")
    if flags["otp"]:
        score += 25
        matched.append("request for codes, password, or account verification")
    if flags["money"]:
        score += 20
        matched.append("money, payment, or investment language")
    if flags["money_demand"]:
        score += 30
        matched.append("direct money demand or payment pressure")
    if flags["impersonation"]:
        score += 20
        matched.append("reference to a commonly impersonated organisation or bank")
    if flags["emotional"]:
        score += 20
        matched.append("emotional or emergency story")
    if flags["unrealistic"]:
        score += 25
        matched.append("unrealistic earnings or 'guaranteed' offer")
    if flags["device_compromise"]:
        score += 35
        matched.append("device/account hacked or compromised claim")
    if flags["malware_download"]:
        score += 30
        matched.append("instruction to download/install/open risky file/app")
    if flags["fear_pressure"]:
        score += 20
        matched.append("fear/threat pressure language")

    return score


def _global_combination_boosts(lowered: str, flags: Dict[str, bool], matched: List[str]) -> Tuple[int, Set[str]]:
    """
    Global combination boosts: extra points when risky signals appear together.
    Applied after the base indicator score, in parallel with a single category strong-pattern boost.
    """
    add = 0
    keys: Set[str] = set()

    if flags.get("link") and flags.get("impersonation"):
        add += 20
        keys.add("link_org")
        matched.append("combination boost: suspicious link + trusted organisation name (+20)")

    if flags.get("urgency") and flags.get("money"):
        add += 20
        keys.add("urgency_money")
        matched.append("combination boost: urgency + money request (+20)")

    if flags.get("combo_emotional_money"):
        add += 25
        matched.append("combination boost: emotional pressure + money request (+25)")

    if flags.get("otp") and flags.get("link"):
        add += 25
        keys.add("otp_link")
        matched.append("combination boost: OTP/password/code request + link (+25)")

    if flags.get("money") and re.search(
        r"before viewing|secure the room|secure the item|deposit before|"
        r"pay(?:ment)? by bank transfer first|transfer first|"
        r"before you collect|pay before",
        lowered,
        re.I,
    ):
        add += 25
        keys.add("pay_before_item")
        matched.append("combination boost: payment + before viewing / deposit / secure item (+25)")

    earn_side = flags.get("unrealistic") or re.search(
        r"\b(earn|profit|reward|double your money|guaranteed|bitcoin|crypto)\b|£\s*\d|per week|per hour|per hr|\bdaily\b",
        lowered,
        re.I,
    )
    easy_side = re.search(r"no experience|easy task|simple task", lowered, re.I)
    if earn_side and easy_side:
        add += 25
        keys.add("unreal_easy")
        matched.append("combination boost: unrealistic reward/earning + easy-task wording (+25)")

    if flags.get("device_compromise") and flags.get("money_demand"):
        add += 30
        keys.add("extortion_combo")
        matched.append("combination boost: device hacked claim + money demand (+30)")
    if flags.get("device_compromise") and flags.get("malware_download"):
        add += 25
        keys.add("extortion_combo")
        matched.append("combination boost: device hacked claim + download instruction (+25)")

    if flags.get("money") and re.search(
        r"(this platform|guide every trade|i will guide every trade|\btrade\b|\btrading\b|\binvest(?:ment)?\b|signal group)",
        lowered,
        re.I,
    ):
        add += 45
        keys.add("investment_pitch")
        matched.append("combination boost: money request + guided investment/trading pitch (+45)")

    if flags.get("money") and re.search(
        r"(no resume needed|hr selected|salary setup|paid likes|app link|seed phrase|verification)",
        lowered,
        re.I,
    ):
        add += 35
        keys.add("fake_job_money_combo")
        matched.append("combination boost: fake-job wording + money/credential request (+35)")

    return add, keys


def _contextual_rule_layer(
    lowered: str, flags: Dict[str, bool], matched: List[str]
) -> Tuple[int, List[str], Dict[str, bool]]:
    """
    Extra explainable rules: task-based fake jobs, easy-job + high pay, large transfer requests,
    and combinations (see project brief). Points add to base + category + global boosts.
    """
    extra_warnings: List[str] = []
    extra = 0
    meta = {
        "fake_job_task_combo": False,
        "fake_job_easy_combo": False,
        "fake_job_force_critical": False,
        "transfer_ge_50": False,
        "transfer_ge_50_pressure": False,
    }

    task_hit = bool(_TASK_ACTIVITY.search(lowered) or re.search(r"\blike\s+videos?\b", lowered, re.I))
    earn1 = bool(_EARN_OR_WAGE.search(lowered))
    if task_hit and earn1:
        extra += 45
        matched.append("earn money for simple online actions (+45)")
        extra_warnings.append(WARNING_LABELS["task_fake_job"])
        meta["fake_job_task_combo"] = True

    easy_hit = bool(_EASY_OR_REMOTE_JOB.search(lowered))
    earn2 = bool(
        re.search(r"\bearn\b|£\s*\d|\d+\s*pounds?|per\s+hour|per\s+hrs?|\bdaily\b", lowered, re.I)
    )
    if easy_hit and earn2:
        extra += 30
        matched.append("unrealistic job offer with easy entry and high pay cues (+30)")
        extra_warnings.append(WARNING_LABELS["unrealistic_job_high_earn"])
        meta["fake_job_easy_combo"] = True

    hourly_max = _max_hourly_gbp_rate(lowered)
    simple_online = bool(
        task_hit
        or re.search(r"simple\s+online|easy\s+tasks?|like\s+videos?|subscribe|follow|rating", lowered, re.I)
    )
    if hourly_max > 15 and simple_online and (earn1 or earn2):
        meta["fake_job_force_critical"] = True
        extra_warnings.append(WARNING_LABELS["unrealistic_simple_online"])

    max_amt = _max_gbp_amount(lowered)
    tverb = bool(_TRANSFER_VERB.search(lowered))
    if tverb and max_amt >= 50:
        extra += 35
        matched.append("direct money transfer request (+35)")
        extra_warnings.append(WARNING_LABELS["transfer_over_50"])
        meta["transfer_ge_50"] = True
        pressure = bool(
            _TRANSFER_PRESSURE.search(lowered) or flags.get("urgency") or flags.get("emotional")
        )
        if pressure:
            extra += 35
            matched.append("money transfer request with urgency or emotional pressure (+35)")
            meta["transfer_ge_50_pressure"] = True
            if WARNING_LABELS["combo_emotional_money"] not in extra_warnings:
                extra_warnings.append(WARNING_LABELS["combo_emotional_money"])

    return extra, extra_warnings, meta


def _score_floors(
    lowered: str,
    flags: Dict[str, bool],
    strong_hits: Dict[str, bool],
    ctx_meta: Dict[str, bool],
) -> int:
    """Minimum total score when specific high-confidence scam contexts match."""
    floors: List[int] = [0]

    if ctx_meta.get("fake_job_task_combo") or ctx_meta.get("fake_job_force_critical"):
        floors.append(80)
    if ctx_meta.get("transfer_ge_50_pressure"):
        floors.append(80)
    elif ctx_meta.get("transfer_ge_50"):
        floors.append(65)

    if _detect_rental_strong(lowered):
        # Rental/marketplace prepayment requests are severe but not always Critical.
        floors.append(70)

    if strong_hits.get("Bank/OTP Scam") and flags.get("link") and (
        flags.get("link_sneaky") or flags.get("link_shortener") or flags.get("otp")
    ):
        floors.append(90)
    if strong_hits.get("Bank / Account Verification Phishing Scam") and flags.get("link") and (
        flags.get("urgency") or flags.get("account_suspension_claim") or flags.get("verification_request")
    ):
        floors.append(90)
    # Generic account phishing fallback: link + verification + urgency/threat should be at least Critical.
    if flags.get("link") and flags.get("verification_request") and (
        flags.get("urgency")
        or flags.get("account_suspension_claim")
        or bool(re.search(r"\b(delete|deleted|deletion|closure|closed|locked|suspended)\b", lowered, re.I))
    ):
        floors.append(80)

    if strong_hits.get("Parcel Delivery Scam") and flags.get("link") and flags.get("money"):
        floors.append(85)

    if strong_hits.get("HMRC/Tax Scam") and (
        flags.get("urgency") or flags.get("link") or flags.get("money")
    ):
        floors.append(85)

    if strong_hits.get("Investment/Crypto Scam") or (
        re.search(r"guaranteed profit", lowered, re.I)
        and re.search(r"crypto|bitcoin|trading|investment", lowered, re.I)
    ):
        floors.append(90)
    if re.search(
        r"(start with £\s*\d+|start with \d+\s*pounds?|guide every trade|i will guide every trade)",
        lowered,
        re.I,
    ) and re.search(r"\b(platform|trade|trading|investment)\b", lowered, re.I):
        floors.append(80)
    if re.search(
        r"(usdt|wallet|presale|inner circle|insider|security fee|fund this wallet)",
        lowered,
        re.I,
    ) and re.search(r"(£\s*\d+|\d+\s*pounds?|send|transfer|deposit|pay)", lowered, re.I):
        floors.append(80)
    if re.search(
        r"(no resume needed|hr selected|salary setup|paid likes|app link|seed phrase|verification)",
        lowered,
        re.I,
    ) and re.search(r"(£\s*\d+|\d+\s*pounds?|send|transfer|deposit|bank login)", lowered, re.I):
        floors.append(75)
    if re.search(r"(bank login|seed phrase)", lowered, re.I):
        floors.append(80)
    if re.search(r"(paid likes|simple clicks?|clicks?\s+per day|training token|before market opens)", lowered, re.I):
        floors.append(60)
    if re.search(r"(approved for a\s*[£]?\s*\d+[,\d]*\s*loan|loan\s+approved|release the funds|admin fee)", lowered, re.I) and re.search(
        r"(pay|fee|deposit|transfer|today|immediately)",
        lowered,
        re.I,
    ):
        floors.append(70)
    if re.search(r"(don't tell family|don’t tell family)", lowered, re.I) and re.search(
        r"(trade|trading|investment|platform|wallet|exchange|market)",
        lowered,
        re.I,
    ):
        floors.append(60)
    if re.search(r"(double by|guaranteed rise)", lowered, re.I) and re.search(
        r"(start with\s*[£]?\s*\d+|\d+\s*pounds?|exchange|trade|investment|market)",
        lowered,
        re.I,
    ):
        floors.append(60)
    if re.search(r"(don't tell family|don’t tell family)", lowered, re.I):
        floors.append(60)
    if flags.get("extortion_combo") or strong_hits.get("Device Compromise / Extortion Scam"):
        floors.append(85)
    if strong_hits.get("Malware / Download Scam") and flags.get("fear_pressure"):
        floors.append(70)
    if _detect_fake_job_medium(lowered):
        floors.append(35)
    if re.search(
        r"(congratulations.*eligible.*reward|eligible for a reward|reply\s+yes\s+to\s+learn\s+more)",
        lowered,
        re.I,
    ):
        floors.append(30)
    if re.search(
        r"(talk more on whatsapp|move to (?:whatsapp|telegram)|continue (?:on|in) (?:whatsapp|telegram)|contact me on whatsapp)",
        lowered,
        re.I,
    ):
        floors.append(35)
    if re.search(
        r"(account needs attention).*(log in).*(usual app|official app)",
        lowered,
        re.I,
    ):
        floors.append(35)

    return max(floors)


def _compute_total_score(
    lowered: str, flags: Dict[str, bool], matched: List[str]
) -> Tuple[int, str | None, Set[str], List[str]]:
    """
    Full score = base + category strong-pattern boost + global combination boosts + contextual rules;
    then at least score floors for certain scam types. Category priority after merging contextual hits.
    """
    strong_hits = _strong_category_hits(lowered)
    ctx_extra, ctx_warnings, ctx_meta = _contextual_rule_layer(lowered, flags, matched)

    if ctx_meta.get("fake_job_task_combo") or ctx_meta.get("fake_job_easy_combo") or ctx_meta.get(
        "fake_job_force_critical"
    ):
        strong_hits["Fake Job Scam"] = True
    if ctx_meta.get("transfer_ge_50_pressure") and _FAMILY_CONTEXT.search(lowered):
        strong_hits["Family Emergency Scam"] = True

    winning = _pick_category_by_priority(strong_hits)
    base = _base_indicator_score(lowered, flags, matched)
    cat_boost = STRONG_BOOST[winning] if winning else 0
    if winning:
        matched.append(f"category strong pattern: {winning} (+{cat_boost})")
    g_add, g_keys = _global_combination_boosts(lowered, flags, matched)
    total = max(0, min(100, base + cat_boost + g_add + ctx_extra))
    total = max(total, _score_floors(lowered, flags, strong_hits, ctx_meta))
    # Keep non-link prepayment marketplace/rental scams in High unless stronger scam signals exist.
    marketplace_prepay = bool(
        re.search(
            r"(reserve the item|many people are interested|bank transfer first|before you collect|secure the item)",
            lowered,
            re.I,
        )
    )
    if (_detect_rental_strong(lowered) or marketplace_prepay) and not (
        flags.get("link")
        or flags.get("otp")
        or flags.get("impersonation")
        or flags.get("device_compromise")
        or flags.get("malware_download")
        or strong_hits.get("Parcel Delivery Scam")
        or strong_hits.get("Bank / Account Verification Phishing Scam")
    ):
        total = min(total, 79)
    # Malware/update-pressure without direct money demand should usually stay High.
    if strong_hits.get("Malware / Download Scam") and not (
        flags.get("money")
        or flags.get("money_demand")
        or flags.get("extortion_combo")
    ):
        total = min(total, 79)
    return total, winning, g_keys, ctx_warnings


def _risk_band_from_score(score: int) -> str:
    """
    Risk bands (fixed for the project):
    0–29 Low, 30–59 Medium, 60–79 High, 80–100 Critical
    """
    if score <= 29:
        return "Low"
    if score <= 59:
        return "Medium"
    if score <= 79:
        return "High"
    return "Critical"


def _normalize_score_to_band(score: int, risk_band: str) -> int:
    """
    Clamp score to the configured band ranges so numeric score and displayed risk level
    always stay consistent:
    Low 0-29, Medium 30-59, High 60-79, Critical 80-100.
    """
    score = max(0, min(100, int(score)))
    if risk_band == "Low":
        return max(0, min(29, score))
    if risk_band == "Medium":
        return max(30, min(59, score))
    if risk_band == "High":
        return max(60, min(79, score))
    return max(80, min(100, score))


def _category_scores(lowered: str) -> Dict[str, int]:
    scores: Dict[str, int] = {}
    for name, patterns in CATEGORY_DEFS:
        total = 0
        for pat, w in patterns:
            if re.search(pat, lowered, re.IGNORECASE):
                total += w
        scores[name] = total
    return scores


def _winning_category_name(cat_s: Dict[str, int], best: int) -> str | None:
    """If several categories share the top score, the first in CATEGORY_DEFS order wins (deterministic)."""
    if best <= 0:
        return None
    for name, _ in CATEGORY_DEFS:
        if cat_s.get(name) == best:
            return name
    return None


def _resolve_scam_category(
    score: int,
    risk_band: str,
    lowered: str,
    flags: Dict[str, bool],
    winning_strong: str | None,
) -> str:
    """
    Final scam category label.

    Category priority (when multiple strong patterns match) is handled earlier via
    _pick_category_by_priority on strong_hits; winning_strong is that single winner.

    Fallbacks use keyword weights; Likely Safe is protected when the score and all major
    buckets stay low (see _any_major).
    """
    cat_s = _category_scores(lowered)
    best = max(cat_s.values()) if cat_s else 0
    best_name = _winning_category_name(cat_s, best)
    fe_name = "Family Emergency Scam"
    combo = bool(flags.get("combo_emotional_money"))
    major = _any_major(flags)

    if winning_strong:
        if winning_strong == "Fake Job Scam":
            return "Fake Job / Task Scam"
        return winning_strong

    # Requested fallback: suspicious link + urgency + account/verification/suspended wording.
    if flags.get("link") and flags.get("urgency") and (
        flags.get("account_suspension_claim")
        or flags.get("verification_request")
        or bool(re.search(r"\b(account|verification|verify|suspended|locked|closure)\b", lowered, re.I))
    ):
        return "Bank / Account Verification Phishing Scam"

    # Medium fake-job lure path: prevent "Likely Safe" for remote-work + weekly-pay bait.
    if _detect_fake_job_medium(lowered):
        return "Fake Job / Task Scam"

    # Safe message protection: no strong pattern, no major buckets, low score → Likely Safe.
    if score <= 25 and not major:
        return "Likely Safe"

    # Emotional plea + money request: family-style if family cues exist; else a sharper label or Unknown.
    if combo:
        if _FAMILY_CONTEXT.search(lowered):
            clear_other = best_name is not None and best >= 5 and best_name != fe_name
            if clear_other:
                return best_name
            return fe_name
        clear_other = best_name is not None and best >= 5
        if clear_other:
            return best_name
        return "Unknown/Suspicious"

    if best > 0 and best_name:
        if best_name == "Fake Job Scam":
            return "Fake Job / Task Scam"
        return best_name
    if risk_band in ("High", "Critical") or score > 50:
        return "Unknown/Suspicious"
    return "Likely Safe"


def _build_warning_signs(
    flags: Dict[str, bool],
    winning_strong: str | None,
    lowered: str,
    g_keys: Set[str],
    extra_warnings: List[str] | None = None,
) -> List[str]:
    """Human-readable warnings from flags, global combination keys, and strong category context."""
    out: List[str] = []
    seen: Set[str] = set()

    def add(label: str) -> None:
        if label and label not in seen:
            seen.add(label)
            out.append(label)

    for w in extra_warnings or []:
        add(w)

    bank_phish_like = bool(
        winning_strong == "Bank / Account Verification Phishing Scam"
        or (
            flags.get("link")
            and flags.get("urgency")
            and (flags.get("account_suspension_claim") or flags.get("verification_request"))
        )
    )
    medium_fake_job = _detect_fake_job_medium(lowered)

    if winning_strong:
        add(WARNING_LABELS["strong_pattern"])
    if flags.get("link") or flags.get("link_sneaky") or flags.get("link_shortener"):
        add(WARNING_LABELS["link"])
    if "link_org" in g_keys:
        add(WARNING_LABELS["link_org"])
    if flags.get("urgency"):
        add(WARNING_LABELS["urgency_pressure"] if bank_phish_like else WARNING_LABELS["urgency"])
    if flags.get("money") and not medium_fake_job:
        add(WARNING_LABELS["money"])
    if flags.get("money_demand") and not medium_fake_job:
        add(WARNING_LABELS["money_demand"])
    if medium_fake_job:
        add(WARNING_LABELS["remote_work_offer"])
        add(WARNING_LABELS["weekly_pay_language"])
        add(WARNING_LABELS["unverified_job_offer"])
    if flags.get("emotional"):
        add(WARNING_LABELS["emotional"])
    if flags.get("fear_pressure"):
        add(WARNING_LABELS["fear_pressure"])
    if flags.get("otp"):
        add(WARNING_LABELS["otp"])
    if flags.get("device_compromise"):
        add(WARNING_LABELS["device_compromise"])
    if flags.get("malware_download"):
        add(WARNING_LABELS["download_instruction"])
    if flags.get("combo_emotional_money"):
        add(WARNING_LABELS["combo_emotional_money"])
    if flags.get("extortion_combo"):
        add(WARNING_LABELS["extortion_combo"])
    if "otp_link" in g_keys:
        add(WARNING_LABELS["otp_link"])
    if "urgency_money" in g_keys:
        add(WARNING_LABELS["urgency_money"])
    if "pay_before_item" in g_keys or _detect_rental_strong(lowered):
        add(WARNING_LABELS["deposit_before"])
    if flags.get("unrealistic") or "unreal_easy" in g_keys:
        add(WARNING_LABELS["unrealistic"])
    if flags.get("impersonation"):
        add(WARNING_LABELS["impersonation"])
    if flags.get("account_suspension_claim"):
        add(WARNING_LABELS["account_suspension_claim"])
    if flags.get("verification_request"):
        add(WARNING_LABELS["verification_request"])
    if flags.get("generic_security_sender"):
        add(WARNING_LABELS["generic_security_sender"])
    if winning_strong == "CEO / Business Email Compromise Scam" or _detect_ceo_bec_strong(lowered):
        add(WARNING_LABELS["authority_bec"])
    return out


def build_highlighted_message(message: str) -> str:
    """
    How highlighting works (for the viva):
    1) We collect text slices that our rules also use for scoring (urgency words,
       URLs, bank names, etc.) using the same regular expressions.
    2) We build one big "alternation" pattern (longer phrases first) and walk the
       string left-to-right, wrapping each match in
       <span class="highlight">...</span> and html.escape-escaping *both* the
       surrounding text and the match so angle brackets in the user message
       cannot become live HTML or scripts.
    """
    if not message:
        return ""
    # Non-overlapping span merge
    terms_set: Set[str] = set()
    for p in (
        URGENCY_PATTERNS
        + OTP_PATTERNS
        + MONEY_PATTERNS
        + EMOTIONAL_PATTERNS
        + UNREALISTIC_PATTERNS
        + DEVICE_COMPROMISE_PATTERNS
        + MALWARE_DOWNLOAD_PATTERNS
        + FEAR_THREAT_PATTERNS
        + COMBO_PRESSURE_PATTERNS
        + COMBO_MONEY_REQUEST_PATTERNS
    ):
        for m in re.finditer(p, message, re.IGNORECASE):
            terms_set.add(m.group(0))
    for u in _collect_url_strings(message):
        terms_set.add(u)
    for ph in IMPERSONATION_PHRASES:
        for m in re.finditer(re.escape(ph), message, re.IGNORECASE):
            terms_set.add(m.group(0))
    for m in IMPERSONATION_EXTRA.finditer(message):
        terms_set.add(m.group(0))
    if not terms_set:
        return html.escape(message, quote=True)

    # Longest token first: alternation is left‑to‑right, so longer phrases beat shorter substrings.
    parts = sorted(terms_set, key=len, reverse=True)
    try:
        pat = re.compile("(" + "|".join(re.escape(t) for t in parts) + ")", re.IGNORECASE)
    except re.error:
        return html.escape(message, quote=True)
    out_parts: List[str] = []
    last = 0
    for m in pat.finditer(message):
        if m.start() > last:
            out_parts.append(html.escape(message[last : m.start()], quote=True))
        out_parts.append(f'<span class="highlight">{html.escape(m.group(0), quote=True)}</span>')
        last = m.end()
    if last < len(message):
        out_parts.append(html.escape(message[last:], quote=True))
    return "".join(out_parts)


def analyse_message(message: str) -> Dict[str, Any]:
    """
    Main entry: rule-based scam analysis for S.A.F.E. Returns a dict with score, band, labels,
    evidence lists, and HTML-safe highlights.

    - Scoring: base indicator buckets + one winning category-specific strong-pattern boost +
      global combination boosts; total clamped 0–100.
    - Category: highest-priority strong pattern (CATEGORY_PRIORITY) else keyword weights / safe corridor.
    - Risk band: derived only from the numeric risk_score using fixed ranges.
    """
    text = message or ""
    lowered = text.lower()
    flags = _score_block_flags(lowered)
    matched: List[str] = []
    risk_score, winning_strong, g_keys, ctx_warnings = _compute_total_score(lowered, flags, matched)
    risk_band = _risk_band_from_score(risk_score)
    risk_score = _normalize_score_to_band(risk_score, risk_band)
    # Safety re-check in case future logic changes band assignment order.
    risk_band = _risk_band_from_score(risk_score)
    scam_category = _resolve_scam_category(risk_score, risk_band, lowered, flags, winning_strong)
    warning_signs = _build_warning_signs(flags, winning_strong, lowered, g_keys, ctx_warnings)
    safety_advice = SAFETY_BY_BAND[risk_band]
    if flags.get("combo_emotional_money"):
        safety_advice = SAFETY_ADVICE_COMBO_EMOTIONAL_MONEY
    if flags.get("device_compromise") or flags.get("malware_download") or flags.get("extortion_combo"):
        safety_advice = SAFETY_ADVICE_DEVICE_EXTORTION
    highlighted_message = build_highlighted_message(text)
    matched_indicators = matched
    if not matched_indicators and risk_score == 0:
        matched_indicators = []

    return {
        "risk_score": risk_score,
        "risk_band": risk_band,
        "scam_category": scam_category,
        "warning_signs": warning_signs,
        "safety_advice": safety_advice,
        "highlighted_message": highlighted_message,
        "matched_indicators": matched_indicators,
    }


EVAL_CASES: List[Dict[str, str]] = [
    # Internal smoke examples for category accuracy:
    # 1) "Dear Customer, unusual activity detected. Your account has been suspended. Verify immediately at
    #    http://secure-account-verification-login-update.com or your account will be closed within 24 hours."
    #    -> Bank / Account Verification Phishing Scam
    # 2) "Earn £50 per hour by liking YouTube videos. Join our Telegram group and pay £30 registration fee."
    #    -> Fake Job Scam
    # 3) "Hi, are we still meeting at 3pm tomorrow?"
    #    -> Likely Safe
    {
        "name": "Bank OTP Phish",
        "message": "HSBC Security: Unusual login detected. Your account is locked. Confirm identity and enter OTP here: https://hsbc-secure-verify.net/login",
        "expected_band": "Critical",
        "expected_category": "Bank/OTP Scam",
    },
    {
        "name": "Parcel Redelivery",
        "message": "Royal Mail: Your parcel could not be delivered. Pay £1.99 to reschedule: http://rm-redelivery-uk.info",
        "expected_band": "Critical",
        "expected_category": "Parcel Delivery Scam",
    },
    {
        "name": "Family Emergency Request",
        "message": "Mum, I lost my phone. This is my new number. I need £500 urgently in hospital after an accident, please send now.",
        "expected_band": "Critical",
        "expected_category": "Family Emergency Scam",
    },
    {
        "name": "Normal Appointment",
        "message": "Reminder: Dental check-up tomorrow at 10:15am at Green Street Surgery. Reply YES to confirm.",
        "expected_band": "Low",
        "expected_category": "Likely Safe",
    },
    {
        "name": "Normal Family Chat",
        "message": "Hi, I'll be ten minutes late for dinner. See you soon.",
        "expected_band": "Low",
        "expected_category": "Likely Safe",
    },
]


def _evaluate_engine() -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    band_hits = 0
    category_hits = 0
    for case in EVAL_CASES:
        res = analyse_message(case["message"])
        band_ok = res["risk_band"] == case["expected_band"]
        cat_ok = res["scam_category"] == case["expected_category"]
        band_hits += 1 if band_ok else 0
        category_hits += 1 if cat_ok else 0
        rows.append(
            {
                "name": case["name"],
                "expected_band": case["expected_band"],
                "actual_band": res["risk_band"],
                "expected_category": case["expected_category"],
                "actual_category": res["scam_category"],
                "score": res["risk_score"],
                "pass": band_ok and cat_ok,
            }
        )
    total = len(EVAL_CASES)
    strict_hits = sum(1 for r in rows if r["pass"])
    return {
        "rows": rows,
        "total": total,
        "strict_accuracy": round((strict_hits / total) * 100, 1) if total else 0.0,
        "band_accuracy": round((band_hits / total) * 100, 1) if total else 0.0,
        "category_accuracy": round((category_hits / total) * 100, 1) if total else 0.0,
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/dataset", methods=["GET"])
def dataset():
    """Educational page: scam/safe examples, patterns, and real-vs-fake comparisons."""
    return render_template("dataset.html")


@app.route("/about", methods=["GET"])
def about():
    """Project overview, limitations, and future-work ideas (not implemented)."""
    return render_template("about.html")


@app.route("/contact", methods=["GET"])
def contact():
    """Public contact and support page for S.A.F.E."""
    return render_template("contact.html")


@app.route("/policies", methods=["GET"])
def policies():
    """Central policies page for privacy, terms, cookies, AI statement, and disclaimer."""
    return render_template("policies.html")


@app.route("/evaluation", methods=["GET"])
def evaluation():
    """Quick measurable quality report for the built-in test set."""
    return render_template("evaluation.html", eval_report=_evaluate_engine())


@app.route("/checker", methods=["GET"])
def checker():
    """Primary S.A.F.E checker page with input tabs and empty state."""
    return render_template(
        "checker.html",
        has_result=False,
        active_tab="text",
        selected_channel="sms",
        message="",
        original_message="",
        highlighted_message="",
        risk_score=0,
        risk_band="Low",
        scam_category="",
        warning_signs=[],
        matched_indicators=[],
        safety_advice=SAFETY_BY_BAND["Low"],
    )


@app.route("/analyse", methods=["POST"])
def analyse():
    start = time.perf_counter()
    message = request.form.get("message", "").strip()
    channel = request.form.get("channel", "unknown")

    if not message:
        elapsed_ms = int((time.perf_counter() - start) * 1000)
        timestamp = datetime.now(timezone.utc).isoformat()
        print(f"[SAFE] timestamp={timestamp} latency_ms={elapsed_ms} risk_band=Low channel={channel}")
        return render_template(
            "checker.html",
            has_result=False,
            active_tab="text",
            selected_channel=channel,
            message="",
            original_message="",
            highlighted_message="",
            risk_score=0,
            risk_band="Low",
            scam_category="",
            warning_signs=["You submitted an empty message."],
            safety_advice=SAFETY_BY_BAND["Low"],
            matched_indicators=[],
        )

    result = analyse_message(message)
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    timestamp = datetime.now(timezone.utc).isoformat()
    print(f"[SAFE] timestamp={timestamp} latency_ms={elapsed_ms} risk_band={result['risk_band']} channel={channel}")

    warning_signs = result["warning_signs"]
    if not warning_signs:
        warning_signs = ["No strong scam patterns were detected, but stay cautious."]

    return render_template(
        "checker.html",
        has_result=True,
        active_tab="text",
        selected_channel=channel,
        message=message,
        original_message=message,
        highlighted_message=result["highlighted_message"],
        risk_score=result["risk_score"],
        risk_band=result["risk_band"],
        scam_category=result["scam_category"],
        warning_signs=warning_signs,
        safety_advice=result["safety_advice"],
        matched_indicators=result["matched_indicators"],
    )


if __name__ == "__main__":
    app.run(debug=True)
