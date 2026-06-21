"""A/D auto-patch regex synthesis + zero-benign-match safety gate.

Given the CONSTANT tokens shared by an attack cluster, synthesize a minimal
regex (bytes) that matches the attack traffic but matches NONE of the benign /
checker samples. firegex DROPs matches, so a false match on the SLA checker
zeroes our SLA: the gate is mandatory and conservative -- refuse (return None)
rather than emit an SLA-killing rule.
"""

import re


def candidate_anchors(const_tokens: list[bytes], min_len: int = 4) -> list[bytes]:
    """Distinctive constant tokens usable as regex anchors.

    Keep tokens with length >= min_len, drop pure-whitespace ones, de-duplicate
    (preserving first occurrence), and sort by length descending so the most
    specific anchor is tried first.
    """
    seen: set[bytes] = set()
    anchors: list[bytes] = []
    for tok in const_tokens:
        if len(tok) < min_len:
            continue
        if not tok.strip():  # pure whitespace / empty
            continue
        if tok in seen:
            continue
        seen.add(tok)
        anchors.append(tok)
    anchors.sort(key=len, reverse=True)
    return anchors


def gate_zero_benign(regex: bytes, benign_samples: list[bytes]) -> bool:
    """True iff the compiled regex matches NONE of the benign samples."""
    pattern = re.compile(regex)
    return not any(pattern.search(sample) for sample in benign_samples)


def synthesize_regex(
    const_tokens: list[bytes],
    benign_samples: list[bytes],
    min_len: int = 4,
) -> bytes | None:
    """Most-specific anchor absent from every benign sample, re.escape'd.

    Returns None if every candidate anchor also appears in some benign sample
    (the zero-benign-match gate). The returned regex is guaranteed to pass
    gate_zero_benign against the same benign_samples.
    """
    for anchor in candidate_anchors(const_tokens, min_len):
        regex = re.escape(anchor)
        if gate_zero_benign(regex, benign_samples):
            return regex
    return None
