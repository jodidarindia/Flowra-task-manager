import re


def normalize_phone(raw):
    """Normalize a 10-digit Indian mobile into E.164 form (+91XXXXXXXXXX).

    Accepts (examples):
      +91 9712345684, 9715463287, +918245678941,
      09123456784, 00919712345684

    Rule: exactly 10 digits, starting with 9, 8, 6 or 7.
    The +91 / 91 / 0 country/trunk prefix is optional and stripped.
    Returns the normalized number, or None if input is not valid.
    """
    raw = (raw or "").strip()
    if not raw:
        return None

    digits = re.sub(r"\D", "", raw)

    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]

    if len(digits) != 10:
        return None

    if digits[0] not in "9867":
        return None

    return "+91" + digits


def is_valid_phone(raw):
    """True only when the number matches the 10-digit 9/8/6/7 rule."""
    return normalize_phone(raw) is not None