"""Password strength and entropy evaluation."""

from __future__ import annotations

import math
from typing import NamedTuple

LABELS: list[str] = ["Very weak", "Weak", "Fair", "Good", "Strong"]

COMMON_PASSWORDS: frozenset[str] = frozenset({
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "welcome",
    "ninja",
    "admin",
    "master",
    "monkey",
    "letmein",
    "abc123",
    "password1",
    "password123",
    "iloveyou",
    "football",
    "secret",
    "pass1234",
    "trustno1",
    "sunshine",
    "princess",
})


class StrengthResult(NamedTuple):
    """Result of password strength analysis."""

    score: int
    label: str
    entropy_bits: float


def calculate_strength(password: str) -> StrengthResult:
    """Estimate password strength in bits and map to score (0-4) and label.

    Considers length, character variety (lowercase, uppercase, digits, symbols),
    penalizes character repetitions, sequential runs, and common password lists.

    Args:
        password: The candidate password string.

    Returns:
        StrengthResult with score (0-4), label, and estimated entropy bits.
    """
    if not password:
        return StrengthResult(score=0, label=LABELS[0], entropy_bits=0.0)

    length = len(password)
    cleaned = password.lower().strip()

    if cleaned in COMMON_PASSWORDS:
        return StrengthResult(score=0, label=LABELS[0], entropy_bits=0.0)

    pool_size = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() for c in password)

    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 32

    if pool_size == 0:
        return StrengthResult(score=0, label=LABELS[0], entropy_bits=0.0)

    # Base Shannon entropy
    raw_entropy = length * math.log2(pool_size)
    penalty = 0.0

    # Penalize low uniqueness ratio
    unique_ratio = len(set(password)) / length
    if unique_ratio < 0.6:
        penalty += (1.0 - unique_ratio) * 20.0

    # Penalize consecutive repeated characters
    repeat_count = 0
    for i in range(1, length):
        if password[i] == password[i - 1]:
            repeat_count += 1
    penalty += repeat_count * 4.0

    # Penalize sequential ascii runs (e.g., 'abc', '123')
    sequence_count = 0
    for i in range(2, length):
        c1, c2, c3 = ord(password[i - 2]), ord(password[i - 1]), ord(password[i])
        if (c2 == c1 + 1 and c3 == c2 + 1) or (c2 == c1 - 1 and c3 == c2 - 1):
            sequence_count += 1
    penalty += sequence_count * 5.0

    effective_entropy = max(0.0, raw_entropy - penalty)

    # Score mapping based on effective entropy
    if effective_entropy < 28.0:
        score = 0
    elif effective_entropy < 45.0:
        score = 1
    elif effective_entropy < 60.0:
        score = 2
    elif effective_entropy < 75.0:
        score = 3
    else:
        score = 4

    # Length-based ceilings to avoid false confidence in short passwords
    if length < 8:
        score = min(score, 1)
    elif length < 12:
        score = min(score, 2)

    return StrengthResult(
        score=score,
        label=LABELS[score],
        entropy_bits=round(effective_entropy, 1),
    )
