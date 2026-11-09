"""Text matching shared by search, filters and highlights (Python and SQL sides)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

# A minus sign only belongs to the number if it does not join two values ("1-5").
_NUMBER_RE = re.compile(r"(?:(?<![0-9A-Za-z])-)?[0-9]+(?:\.[0-9]+)?")
NUMBER_REGEX = r"-?\d+(?:\.\d+)?"
# Grouping key for numbers in SQL; a private-use character cannot collide with a literal "#".
NUMBER_KEY = "\ue000"
_REGEX_SPECIAL = set("\\.^$*+?{}[]|()")
_REGEX_CONTROL = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}

_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _escape_literal(text: str) -> str:
    """Readable ``re.escape``: only characters with meaning outside ``[]`` are escaped."""
    return "".join(_REGEX_CONTROL.get(char) or ("\\" + char if char in _REGEX_SPECIAL else char)
                   for char in text)


def message_regex(message: str) -> str:
    """Anchored regex matching ``message`` with every number replaced by a number pattern."""
    return "^" + NUMBER_REGEX.join(_escape_literal(part) for part in number_split(message)) + "$"


def number_split(message: str) -> list[str]:
    """The literal parts of ``message`` between the numbers that :func:`message_regex` replaces."""
    return _NUMBER_RE.split(message)


def number_template(message: str | None, placeholder: str = "#") -> str:
    """``message`` with every number (as :func:`message_regex` sees it) replaced by ``placeholder``."""
    return placeholder.join(number_split(message or ""))


@lru_cache(maxsize=32)
def _compiled_regex(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


def regex_matches(pattern: str, message: str | None) -> bool:
    """Python ``re.search`` semantics; anchor with ``^``/``$`` for whole messages."""
    return message is not None and _compiled_regex(pattern).search(message) is not None


def register_functions(conn) -> None:
    """SQL functions required by :func:`match_sql` and the query layer."""
    conn.create_function("regex_matches", 2, regex_matches, deterministic=True)
    conn.create_function("number_template", 1, lambda message: number_template(message, NUMBER_KEY),
                         deterministic=True)


@dataclass(frozen=True, slots=True)
class MatchOptions:
    """VS Code-style text matching: Match Case, Match Whole Word, Use Regular Expression."""
    case_sensitive: bool = False
    whole_word: bool = False
    regex: bool = False

    def __post_init__(self) -> None:
        if not all(isinstance(value, bool) for value in (self.case_sensitive, self.whole_word, self.regex)):
            raise ValueError("Invalid match options")

    @property
    def needs_regex(self) -> bool:
        return self.regex or self.whole_word


PLAIN_MATCH = MatchOptions()


def match_regex(text: str, options: MatchOptions, *, full: bool = False) -> str:
    """Python regex for ``text`` under ``options``; ``full`` matches the whole value."""
    pattern = text if options.regex else re.escape(text)
    if full:
        pattern = f"^(?:{pattern})\\Z"
    elif options.whole_word:
        pattern = f"(?<!\\w)(?:{pattern})(?!\\w)"
    return pattern if options.case_sensitive else f"(?i){pattern}"


def match_error(text: str, options: MatchOptions) -> str | None:
    """Error message if ``text`` is not a valid pattern under ``options``, else ``None``."""
    if not options.regex or not text.strip():
        return None
    try:
        _compiled_regex(match_regex(text.strip(), options))
    except re.error as error:
        return str(error)
    return None


def text_matches(value: str | None, text: str, options: MatchOptions = PLAIN_MATCH) -> bool:
    """Python counterpart of :func:`match_sql` for a ``contains`` comparison."""
    value = value or ""
    if options.needs_regex:
        return _compiled_regex(match_regex(text, options)).search(value) is not None
    if options.case_sensitive:
        return text in value
    return text.translate(_ASCII_LOWER) in value.translate(_ASCII_LOWER)


def match_sql(columns: tuple[str, ...], text: str, options: MatchOptions = PLAIN_MATCH,
              *, equals: bool = False) -> tuple[str, list[str]]:
    """SQL expression true if any column contains (or equals) ``text``.

    Plain options keep the index-free but fast ``LIKE``; whole word and regex
    use the Python ``regex_matches`` function registered on the connection.
    """
    if options.regex or (options.whole_word and not equals):
        template = "regex_matches(?, COALESCE({column}, ''))"
        value = match_regex(text, options, full=equals)
    elif equals:
        collation = "BINARY" if options.case_sensitive else "NOCASE"
        template, value = f"COALESCE({{column}}, '') = ? COLLATE {collation}", text
    elif options.case_sensitive:
        template, value = "instr(COALESCE({column}, ''), ?) > 0", text
    else:
        template, value = "COALESCE({column}, '') LIKE ? ESCAPE '\\'", like_pattern(text)
    sql = " OR ".join(template.format(column=column) for column in columns)
    return (f"({sql})" if len(columns) > 1 else sql), [value] * len(columns)


def like_pattern(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"
