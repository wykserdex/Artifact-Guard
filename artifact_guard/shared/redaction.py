"""PII redaction utilities."""

import re


PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?7|8)[\s()-]*"
    r"(\d{3})[\s()-]*(\d{3})[\s-]*(\d{2})[\s-]*(\d{2})(?!\d)"
)

EMAIL_RE = re.compile(
    r"\b([A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]*"
    r"(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b"
)

# Simple patterns for common PII types
CREDIT_CARD_RE = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
)

PASSPORT_RU_RE = re.compile(
    r"\b\d{4}\s?\d{6}\b"
)

SNILS_RE = re.compile(
    r"\b\d{3}-\d{3}-\d{3}\s?\d{2}\b"
)

INN_RE = re.compile(
    r"\b\d{10}(?:\d{2})?\b"
)


def redact_phone(text: str) -> str:
    """Redact phone numbers, keeping last 2 digits."""
    return PHONE_RE.sub(r"+7 *** ***-**-\4", text)


def redact_email(text: str) -> str:
    """Redact email addresses, keeping first char and domain."""
    return EMAIL_RE.sub(r"\1***\2", text)


def redact_credit_card(text: str) -> str:
    """Redact credit card numbers, keeping last 4 digits."""
    def replace_cc(match):
        cc = match.group(0).replace(" ", "").replace("-", "")
        return f"****-****-****-{cc[-4:]}"
    return CREDIT_CARD_RE.sub(replace_cc, text)


def redact_passport(text: str) -> str:
    """Redact Russian passport numbers."""
    return PASSPORT_RU_RE.sub("**** ******", text)


def redact_snils(text: str) -> str:
    """Redact SNILS (Russian pension insurance number)."""
    return SNILS_RE.sub("***-***-*** **", text)


def redact_inn(text: str) -> str:
    """Redact INN (Russian tax ID)."""
    def replace_inn(match):
        inn = match.group(0)
        if len(inn) == 10:
            return f"**********{inn[-2:]}"
        elif len(inn) == 12:
            return f"************{inn[-2:]}"
        return inn
    return INN_RE.sub(replace_inn, text)


def redact_text(text: str) -> str:
    """
    Apply all redaction rules to text.
    
    Order matters: apply more specific patterns first.
    """
    text = redact_credit_card(text)
    text = redact_passport(text)
    text = redact_snils(text)
    text = redact_inn(text)
    text = redact_phone(text)
    text = redact_email(text)
    return text


def contains_pii(text: str) -> bool:
    """Check if text potentially contains PII."""
    patterns = [
        PHONE_RE,
        EMAIL_RE,
        CREDIT_CARD_RE,
        PASSPORT_RU_RE,
        SNILS_RE,
        INN_RE,
    ]
    return any(pattern.search(text) for pattern in patterns)
