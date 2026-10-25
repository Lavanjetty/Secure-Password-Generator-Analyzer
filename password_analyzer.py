"""
Secure Password Generator & Analyzer
Educational CLI project. Uses only local computation.
Python 3.10+
"""
from __future__ import annotations

import math
import re
import secrets
import string
from dataclasses import dataclass, asdict
from typing import Iterable

try:
    from zxcvbn import zxcvbn
except ImportError:
    zxcvbn = None

AMBIGUOUS = set("O0Il1|`'\"")
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}:,.?/"

COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "qwerty",
    "admin", "letmein", "welcome", "iloveyou", "abc123",
    "password1", "changeme", "monkey", "dragon", "football",
}
SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)


@dataclass
class Analysis:
    length: int
    character_classes: list[str]
    estimated_pool_size: int
    theoretical_entropy_bits: float
    score_0_to_4: int
    rating: str
    findings: list[str]
    recommendations: list[str]
    zxcvbn_available: bool
    zxcvbn_score: int | None = None
    zxcvbn_crack_time: str | None = None

    def to_dict(self):
        return asdict(self)


def _secure_choice(chars: str) -> str:
    return secrets.choice(chars)


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """Generate with secrets, guaranteeing at least one from each selected class."""
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length must be an integer")
    if length < 8 or length > 128:
        raise ValueError("length must be between 8 and 128")
    pools = []
    if use_lower:
        pools.append(LOWER)
    if use_upper:
        pools.append(UPPER)
    if use_digits:
        pools.append(DIGITS)
    if use_symbols:
        pools.append(SYMBOLS)
    if not pools:
        raise ValueError("Select at least one character type")
    if len(pools) > length:
        raise ValueError("Password length is too short for selected character types")

    if avoid_ambiguous:
        pools = ["".join(ch for ch in pool if ch not in AMBIGUOUS) for pool in pools]
    if any(not p for p in pools):
        raise ValueError("A selected character set is empty after removing ambiguous characters")

    all_chars = "".join(pools)
    # Guarantee class inclusion, then use CSPRNG to shuffle the completed list.
    chars = [_secure_choice(pool) for pool in pools]
    chars.extend(_secure_choice(all_chars) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def _classes(password: str) -> list[str]:
    result = []
    if any(c.islower() for c in password): result.append("lowercase")
    if any(c.isupper() for c in password): result.append("uppercase")
    if any(c.isdigit() for c in password): result.append("digits")
    if any(not c.isalnum() and not c.isspace() for c in password): result.append("symbols")
    if any(c.isspace() for c in password): result.append("whitespace")
    return result


def _pattern_findings(password: str) -> list[str]:
    findings = []
    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        findings.append("Matches a common-password example.")
    if re.search(r"(.)\1{2,}", password):
        findings.append("Contains a character repeated at least three times consecutively.")
    if re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|asdf)", lower):
        findings.append("Contains a predictable sequence or keyboard pattern.")
    if password.isalpha() or password.isdigit():
        findings.append("Uses only one broad character category.")
    if len(password) < 12:
        findings.append("Shorter than the recommended 15-character minimum for a single-factor password.")
    if password.lower() in {"password123", "welcome123", "admin123", "qwerty123"}:
        findings.append("Uses a highly predictable word-plus-number pattern.")
    return findings


def analyze_password(password: str, use_zxcvbn: bool = True) -> Analysis:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        return Analysis(0, [], 0, 0.0, 0, "Very weak",
                        ["Password is empty."],
                        ["Use a long, unique password or passphrase."],
                        bool(zxcvbn and use_zxcvbn))
    classes = _classes(password)
    # This pool-size estimate assumes characters are independently and uniformly
    # selected from the inferred pool; that assumption is usually false for human passwords.
    pool = 0
    if any(c.islower() for c in password): pool += 26
    if any(c.isupper() for c in password): pool += 26
    if any(c.isdigit() for c in password): pool += 10
    if any(not c.isalnum() and not c.isspace() for c in password): pool += len(SYMBOLS)
    if any(c.isspace() for c in password): pool += 1
    entropy = len(password) * math.log2(pool) if pool > 1 else 0.0

    findings = _pattern_findings(password)
    recommendations = []
    if len(password) < 15:
        recommendations.append("Prefer at least 15 characters for a password protecting an important account.")
    if len(classes) < 3:
        recommendations.append("Consider a longer passphrase or a password generated from a broad character set.")
    if any(f.startswith("Matches") or "predictable sequence" in f or "word-plus-number" in f for f in findings):
        recommendations.append("Avoid common words, familiar sequences, and predictable substitutions.")
    if re.search(r"(.)\1{2,}", password):
        recommendations.append("Avoid long runs of repeated characters.")
    if not recommendations:
        recommendations.append("Use it for one account only and store it in a reputable password manager.")
    # This is an explainable heuristic, not a cryptographic guarantee.
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if len(password) >= 15: score += 1
    if len(classes) >= 3: score += 1
    if findings: score = max(0, score - min(2, len(findings)))
    score = max(0, min(4, score))
    ratings = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]

    z_score = None
    z_time = None
    z_available = bool(zxcvbn and use_zxcvbn)
    if z_available:
        try:
            result = zxcvbn(password)
            z_score = int(result["score"])
            z_time = str(result["crack_times_display"].get("offline_slow_hashing_1e4_per_second", "unknown"))
        except Exception:
            z_available = False

    return Analysis(
        length=len(password),
        character_classes=classes,
        estimated_pool_size=pool,
        theoretical_entropy_bits=round(entropy, 2),
        score_0_to_4=score,
        rating=ratings[score],
        findings=findings or ["No basic pattern warning was detected."],
        recommendations=recommendations,
        zxcvbn_available=z_available,
        zxcvbn_score=z_score,
        zxcvbn_crack_time=z_time,
    )


def format_analysis(result: Analysis) -> str:
    lines = [
        "\nPASSWORD ANALYSIS",
        "=" * 56,
        f"Length:                    {result.length}",
        f"Character classes:         {', '.join(result.character_classes) or 'none'}",
        f"Estimated character pool:  {result.estimated_pool_size}",
        f"Theoretical entropy:       {result.theoretical_entropy_bits:.2f} bits (assumption-based)",
        f"Rule-based rating:         {result.rating} ({result.score_0_to_4}/4)",
        "",
        "Findings:",
    ]
    lines.extend(f"  - {item}" for item in result.findings)
    lines.append("Recommendations:")
    lines.extend(f"  - {item}" for item in result.recommendations)
    if result.zxcvbn_available:
        lines.extend([
            "",
            f"zxcvbn score:               {result.zxcvbn_score}/4",
            f"Illustrative offline slow-hash estimate: {result.zxcvbn_crack_time}",
        ])
    else:
        lines.extend(["", "zxcvbn: not installed or unavailable (optional dependency)."])
    lines.extend([
        "",
        "Important: scores and entropy estimates are not guarantees. Do not reuse passwords.",
        "This app analyzes locally and does not save or transmit the entered password.",
    ])
    return "\n".join(lines)
