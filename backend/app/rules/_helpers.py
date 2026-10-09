"""Shared helpers for rule functions."""

import re

_NEGATION_RE = re.compile(
    r"\b(no|not|never|without|don't|do not|doesn't|does not|zero|free of)\b[^.\n]{0,25}$",
    re.IGNORECASE,
)
_SENTENCE_END = ".!?\n"
MAX_EVIDENCE = 160


def is_negated(text: str, start: int) -> bool:
    """True if the match at `start` is preceded by a negation in the same clause.

    Catches disclaimers such as "We never charge any registration fee".
    """
    return bool(_NEGATION_RE.search(text[max(0, start - 40) : start]))


def sentence_around(text: str, start: int, end: int) -> str:
    """The sentence containing text[start:end], trimmed for use as evidence."""
    left = max(text.rfind(c, 0, start) for c in _SENTENCE_END) + 1
    rights = [i for c in _SENTENCE_END if (i := text.find(c, end)) != -1]
    right = min(rights) + 1 if rights else len(text)
    sentence = " ".join(text[left:right].split())
    if len(sentence) <= MAX_EVIDENCE:
        return sentence
    # Centre the window on the match.
    match = " ".join(text[start:end].split())
    pos = max(0, sentence.find(match) - (MAX_EVIDENCE - len(match)) // 2)
    return ("…" if pos else "") + sentence[pos : pos + MAX_EVIDENCE].strip() + "…"


_LIST_JOIN_RE = re.compile(r"\s*(?:,|/|or|and|&)\s*", re.IGNORECASE)


def first_unnegated(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    prev: re.Match[str] | None = None
    prev_negated = False
    for m in pattern.finditer(text):
        # "never ... WhatsApp or Telegram": a list item inherits the previous item's negation.
        joined = prev is not None and _LIST_JOIN_RE.fullmatch(text[prev.end() : m.start()])
        negated = prev_negated if joined else is_negated(text, m.start())
        if not negated:
            return m
        prev, prev_negated = m, negated
    return None
