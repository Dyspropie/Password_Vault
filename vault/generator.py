"""Cryptographically secure password generator."""

from __future__ import annotations

import math
import secrets

from vault.errors import GeneratorError

LOWERCASE: str = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE: str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS: str = "0123456789"
SYMBOLS: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"

LOOKALIKE_CHARS: frozenset[str] = frozenset({"0", "O", "o", "1", "l", "I"})


def entropy_bits(length: int, pool_size: int) -> float:
    """Calculate theoretical Shannon entropy in bits for a given length and pool size.

    Args:
        length: Password length.
        pool_size: Number of unique characters in the candidate pool.

    Returns:
        Entropy in bits, rounded to 2 decimal places.
    """
    if length <= 0 or pool_size <= 0:
        return 0.0
    return round(length * math.log2(pool_size), 2)


def generate_password(
    length: int = 20,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_lookalikes: bool = False,
) -> str:
    """Generate a cryptographically secure random password.

    Ensures at least one character from each selected character set is present,
    and shuffles the resulting characters using secrets.SystemRandom.

    Args:
        length: Password length (must be between 8 and 64).
        use_lower: Include lowercase letters (a-z).
        use_upper: Include uppercase letters (A-Z).
        use_digits: Include digits (0-9).
        use_symbols: Include symbols (!@#$%^&*()_+-=[]{}|;:,.<>?).
        exclude_lookalikes: Exclude confusing characters (0, O, o, 1, l, I).

    Returns:
        Generated password string.

    Raises:
        GeneratorError: If length is invalid or no character sets are selected.
    """
    if not (8 <= length <= 64):
        raise GeneratorError(f"Password length must be between 8 and 64 characters, received {length}.")

    active_sets: list[str] = []

    def filter_set(chars: str) -> str:
        if exclude_lookalikes:
            return "".join(c for c in chars if c not in LOOKALIKE_CHARS)
        return chars

    if use_lower:
        filtered = filter_set(LOWERCASE)
        if filtered:
            active_sets.append(filtered)
    if use_upper:
        filtered = filter_set(UPPERCASE)
        if filtered:
            active_sets.append(filtered)
    if use_digits:
        filtered = filter_set(DIGITS)
        if filtered:
            active_sets.append(filtered)
    if use_symbols:
        filtered = filter_set(SYMBOLS)
        if filtered:
            active_sets.append(filtered)

    if not active_sets:
        raise GeneratorError("At least one character set must be selected.")

    # Guarantee at least one character from each selected set
    result_chars: list[str] = [secrets.choice(char_set) for char_set in active_sets]

    # Combine all active sets into a single pool for the remaining characters
    combined_pool = "".join(active_sets)
    remaining_length = length - len(result_chars)

    for _ in range(remaining_length):
        result_chars.append(secrets.choice(combined_pool))

    # Cryptographically secure in-place shuffle
    rng = secrets.SystemRandom()
    rng.shuffle(result_chars)

    return "".join(result_chars)
