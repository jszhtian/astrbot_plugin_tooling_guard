"""Central redaction contract for all outgoing or persisted content.

Requirement: Sanitized Persistence.

Every persisted text, administrator notification, and model-facing excerpt of
this plugin passes through the Anonymizer class. The module is pure: no file or
network I/O, no third-party dependency, no exception ever escapes, and no other
module of this package is imported.

Redaction runs synchronously on the event loop, so the module carries two
explicit bounds: MAX_REDACT_SCAN caps how much text one call scans, and
MAX_SECRET_PATTERN_LENGTH plus validate_secret_pattern keep an operator-supplied
expression from turning into a backtracking bomb.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

CUSTOM_PLACEHOLDER = "<SECRET:custom>"
"""Placeholder used for an operator-supplied pattern."""

_UNPRINTABLE = "<unprintable>"
"""Last-resort text for a value that can be neither printed nor represented."""

_PLACEHOLDER_RE = re.compile(r"<SECRET:([^<>]*)>")

MAX_REDACT_SCAN = 262_144
"""Characters one redact call scans; longer input is cut first, then redacted.

Requirement: Sanitized Persistence. A tool argument is attacker-controlled and
can be megabytes long, so the pass runs on a bounded prefix: the text is
truncated to this many characters BEFORE any rule touches it, never after, and
truncating first is what bounds the work. Redacting first and truncating
afterwards would still pay the full cost on every audit row, every administrator
notification, and every outbound deep-review prompt. The bound is a full 256 KiB
so an ordinary 200 KB argument is still redacted whole.
"""

_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def _placeholder(name: str) -> str:
    """Return the spec placeholder token of one secret class.

    Args:
        name: Secret class name, for example "api_key".

    Returns:
        The '<SECRET:name>' token required by the spec.
    """
    return f"<SECRET:{name}>"


def _stringify(value: Any) -> str:
    """Return a printable form of a value without ever raising.

    Args:
        value: Arbitrary object, including one whose __str__ fails.

    Returns:
        The str() form when available, else the repr() form, else a fixed
        marker.
    """
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - a hostile __str__ must not break redaction
        try:
            return repr(value)
        except Exception:  # noqa: BLE001 - unrepresentable value
            return _UNPRINTABLE


MAX_SECRET_PATTERN_LENGTH = 512
"""Longest operator-supplied expression that is accepted.

Requirement: Sanitized Persistence. An accepted pattern still runs synchronously
inside every redact call, so this cap - together with MAX_REDACT_SCAN - keeps the
scan itself bounded; the subset check below is what removes every expression whose
run time could grow faster than the text it reads.
"""

MAX_SECRET_PATTERN_REPEAT = 64
"""Largest repetition bound an accepted expression may state.

Requirement: Sanitized Persistence. "{0,1000000}" is refused: a bound is a
counter, and keeping every bound small is also what makes the product of one
alternative's widths - MAX_SECRET_PATTERN_AMBIGUITY - a small constant.
"""

MAX_SECRET_PATTERN_AMBIGUITY = 64
"""Largest product of repetition widths that one alternative may hold.

Requirement: Sanitized Persistence. The product is how many ways a single start
position can be retried, and it is measured rather than guessed: with a 64-wide
repetition, "[a-z]{0,64}[a-z]{0,64}x" needs 0.14 s for a 16384-character argument
and grows with the square of its length, which no scan cap can rescue before a
whole MAX_REDACT_SCAN pass has run on the event loop.
"""

PATTERN_TOO_LONG = "pattern_too_long"
"""Reason code: the expression exceeds MAX_SECRET_PATTERN_LENGTH."""

PATTERN_NESTED_QUANTIFIER = "pattern_nested_quantifier"
"""Reason code: a group is quantified, so its body is re-entered per prefix."""

PATTERN_NESTED_ALTERNATION = "pattern_nested_alternation"
"""Reason code: an alternation appears inside a group."""

PATTERN_REPEAT_TOO_LARGE = "pattern_repeat_too_large"
"""Reason code: a repetition bound exceeds MAX_SECRET_PATTERN_REPEAT."""

PATTERN_AMBIGUOUS_REPEAT = "pattern_ambiguous_repeat"
"""Reason code: one alternative retries a start position too many ways."""

PATTERN_UNSAFE_CONSTRUCT = "pattern_unsafe_construct"
"""Reason code: lookaround, backreference, conditional, atomic or possessive."""

PATTERN_UNBOUNDED_WILDCARD = "pattern_unbounded_wildcard"
"""Reason code: an atom of unknown extent is repeated without a bound."""

PATTERN_UNCOMPILABLE = "pattern_uncompilable"
"""Reason code: the expression is empty, not a string, or does not compile."""

_QUANTIFIER_START = frozenset("*+?{")
"""Characters that may open a repetition."""

_BOUND_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")
"""A stated repetition bound; anything else after "{" is a literal brace."""

_ESCAPED_CLASSES = frozenset("dDsSwW")
"""Escapes that consume exactly one character and may therefore repeat."""

_ESCAPED_ANCHORS = frozenset("bBAZz")
"""Escapes that consume nothing."""

_FLAG_LETTERS = frozenset("aiLmsux")
"""Inline flags the subset accepts, alone as "(?i)" or scoped as "(?i:...)"."""

_HEX_ESCAPE_DIGITS = {"x": 2, "u": 4, "U": 8}
"""Escape letter and the number of hex digits it must carry."""

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
"""Digits a hex escape may use."""

_SIMPLE_ESCAPE_CODES = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11}
"""Escapes that name one control character, by code point."""

_MAX_CLASS_CHARS = 256
"""Largest character set the scanner reasons about; anything wider stays unknown."""

_MAX_CLASS_SPAN = 256
"""Widest "a-z" range the scanner expands; anything wider stays unknown."""


class _Refused(Exception):
    """Early exit carrying one reason code out of the shape scanner."""

    def __init__(self, code: str) -> None:
        """Record the code this refusal answers with."""
        super().__init__(code)
        self.code = code


class _ShapeScanner:
    """Decide whether one operator expression stays inside the safe subset.

    Requirement: Sanitized Persistence. Only an operator-supplied pattern is
    judged here; the defaults in _DEFAULT_RULES are trusted constants and never
    pass through this check. The accepted subset is:

    - literals, character classes, and escapes that consume one character;
    - the zero-width anchors ^ $ \\b \\B \\A \\Z \\z, and a flag group such as
      "(?i)" or "(?i:...)", which consume nothing;
    - capturing, non-capturing, and named groups, used only as grouping, with
      alternation inside them as long as no repetition applies to the group;
    - a repetition - "*", "+", "?", "{n}", "{n,}", "{n,m}" - applied to exactly
      one character, one class, or one escape, with every stated bound at most
      MAX_SECRET_PATTERN_REPEAT;
    - alternation, at the top level or inside a plain group;
    - at most one unbounded repetition, as the last atom of its branch.

    Why the subset is what makes redaction cheap: no repetition applies to a
    group, so matching one alternative is a single left-to-right scan and its
    only replay points are its own repetitions. _finalize multiplies the widths
    of those repetitions - a width is 1 for "{n}", m-n+1 for "{n,m}", 2 for "?",
    and unbounded for "*", "+", "{n,}" - and refuses a product above
    MAX_SECRET_PATTERN_AMBIGUITY, so one alternative costs
    O(width * len(text)) with a width that is a constant of the pattern. k
    branches cost k times that, and _group_result multiplies k over the groups
    of the expression and refuses a product above the same constant, so
    branching cannot compound into an exponent. An atom whose characters are
    unknown - ".", "\\S", "\\D", "\\W", "\\w", "\\s", "\\d", or a negated class
    - answers PATTERN_UNBOUNDED_WILDCARD when it is repeated without a bound.

    An unbounded repetition is accepted in exactly one position: as the last
    atom of its branch, with nothing behind it at all - not another atom, not a
    zero-width assertion, not a flag group (see _finalize). Everywhere else it
    splits one run of input between itself and the rest of the branch, and that
    split is retried from every start position. Neither an anchoring "^" or
    "\\A" nor a trailing "$" or "\\b" is a proof of anything: the anchors only
    remove or shift whole start positions, and an assertion behind the
    repetition can fail, which is what hands the run back to it.

    Everything that would break that argument is refused with its own code: a
    quantified group re-enters its body once per prefix, an oversized bound
    turns one atom into a counter, a product of bounds or of branches acts like
    an exponent, an unbounded repetition in front of another consuming atom is
    refused as PATTERN_AMBIGUOUS_REPEAT (as PATTERN_UNBOUNDED_WILDCARD when the
    atom's own extent is unknown), and lookaround, backreferences, conditionals,
    atomic groups, and possessive quantifiers are outside the argument
    entirely.
    """

    def __init__(self, text: str) -> None:
        """Start a scan of one expression."""
        self._text = text
        self._index = 0
        self._repeats: list[tuple[int | None, bool]] = []
        self._paths = 1
        self._tail_open = False
        self._fold = False

    def scan(self) -> str | None:
        """Return the code of the first refused shape, or None when accepted."""
        try:
            while True:
                self._branch(top=True)
                self._finalize()
                if self._peek() != "|":
                    break
                self._index += 1
            if self._index < len(self._text):
                raise _Refused(PATTERN_UNCOMPILABLE)
        except _Refused as refused:
            return refused.code
        return None

    def _peek(self, offset: int = 0) -> str | None:
        """Return the character at the cursor without consuming it."""
        position = self._index + offset
        if position < len(self._text):
            return self._text[position]
        return None

    def _branch(self, *, top: bool) -> None:
        """Scan one alternative and record where its repetitions sit.

        Requirement: Sanitized Persistence. _tail_open answers one question for
        _finalize: is the last repetition of this branch its last atom too?
        Every atom that follows clears the flag, a zero-width one included: a
        trailing "$", "\\Z", "\\z", "\\b", "\\B" or a flag group can still fail
        behind the repetition, and that failure hands the run back to it. A "^"
        with nothing behind it cannot fail at all, yet it clears the flag as
        well - one question is worth more than the one shape it would keep
        ("a+^"), and a rule with an exception is a rule nobody can re-check.
        """
        if top:
            self._repeats = []
            self._paths = 1
            self._tail_open = False
        while True:
            char = self._peek()
            if char is None or char == "|" or char == ")":
                return
            kind, chars = self._atom()
            if kind == "zero":
                self._tail_open = False
                continue
            self._tail_open = self._repetition(kind=kind, chars=chars)

    def _atom(self) -> tuple[str, frozenset[int] | None]:
        """Scan one atom; report its kind and the characters it consumes.

        The kind is "one" for an atom that consumes a character, "zero" for an
        atom that consumes nothing - an anchor, or a flag group such as "(?i)" -
        and "group" for a group body. The second item is the character set an
        atom of kind "one" matches, or None when that set is unknown; nothing
        reads it for the other two kinds, because neither may be repeated.
        """
        char = self._peek()
        if char is None:
            raise _Refused(PATTERN_UNCOMPILABLE)
        self._index += 1
        if char == "\\":
            return self._escape()
        if char == "[":
            return ("one", self._character_class())
        if char == "(":
            return self._group()
        if char in _QUANTIFIER_START:
            raise _Refused(PATTERN_UNCOMPILABLE)
        if char in "^$":
            return ("zero", frozenset())
        if char == ".":
            return ("one", None)
        return ("one", self._expand_case({ord(char)}))

    def _escape(self) -> tuple[str, frozenset[int] | None]:
        """Scan one escape; report its kind and the characters it consumes."""
        char = self._peek()
        if char is None:
            raise _Refused(PATTERN_UNCOMPILABLE)
        self._index += 1
        if char in _ESCAPED_CLASSES:
            return ("one", None)
        if char in _ESCAPED_ANCHORS:
            return ("zero", frozenset())
        if char in "123456789" or char == "g":
            raise _Refused(PATTERN_UNSAFE_CONSTRUCT)
        code = self._escape_code(char)
        return ("one", None if code is None else self._expand_case({code}))

    def _escape_code(self, char: str) -> int | None:
        """Return the code point one escape names, or None when it is unknown."""
        simple = _SIMPLE_ESCAPE_CODES.get(char)
        if simple is not None:
            return simple
        digits = _HEX_ESCAPE_DIGITS.get(char)
        if digits is not None:
            chunk = self._text[self._index : self._index + digits]
            if len(chunk) != digits or any(item not in _HEX_DIGITS for item in chunk):
                raise _Refused(PATTERN_UNCOMPILABLE)
            self._index += digits
            return int(chunk, 16)
        if char == "N":
            close = self._text.find("}", self._index)
            if self._peek() != "{" or close <= self._index + 1:
                raise _Refused(PATTERN_UNCOMPILABLE)
            self._index = close + 1
            return None
        if char.isalnum():
            return None
        return ord(char)

    def _character_class(self) -> frozenset[int] | None:
        """Scan the rest of a class; report the characters it matches."""
        known = True
        chars: set[int] = set()
        if self._peek() == "^":
            self._index += 1
            known = False
        if self._peek() == "]":
            self._index += 1
            chars.add(ord("]"))
        while True:
            if self._peek() == "]":
                self._index += 1
                break
            low = self._class_atom()
            if low is None:
                known = False
                continue
            if self._peek() == "-" and self._peek(1) not in (None, "]"):
                self._index += 1
                high = self._class_atom()
                if high is None or high < low or high - low > _MAX_CLASS_SPAN:
                    known = False
                    continue
                chars.update(range(low, high + 1))
                continue
            chars.add(low)
            if len(chars) > _MAX_CLASS_CHARS:
                known = False
        if not known:
            return None
        return self._expand_case(chars)

    def _class_atom(self) -> int | None:
        """Return the code point one class member names, or None when unknown."""
        char = self._peek()
        if char is None:
            raise _Refused(PATTERN_UNCOMPILABLE)
        self._index += 1
        if char != "\\":
            return ord(char)
        escaped = self._peek()
        if escaped is None:
            raise _Refused(PATTERN_UNCOMPILABLE)
        self._index += 1
        return self._escape_code(escaped)

    def _expand_case(self, chars: set[int] | frozenset[int]) -> frozenset[int] | None:
        """Return the characters an atom matches under the flags seen so far."""
        if not self._fold:
            return frozenset(chars)
        expanded = set(chars)
        for code in chars:
            char = chr(code)
            for variant in (char.lower(), char.upper()):
                if len(variant) != 1:
                    return None
                expanded.add(ord(variant))
        if len(expanded) > _MAX_CLASS_CHARS:
            return None
        return frozenset(expanded)

    def _body(self) -> int:
        """Scan a group body; report how many branches it holds."""
        branches = 1
        self._branch(top=False)
        while self._peek() == "|":
            branches += 1
            self._index += 1
            self._branch(top=False)
        if self._peek() != ")":
            raise _Refused(PATTERN_UNCOMPILABLE)
        self._index += 1
        return branches

    def _group_result(self, *, branches: int) -> tuple[str, frozenset[int] | None]:
        """Reject a group the subset cannot accept, else report the group."""
        if self._quantified_ahead():
            raise _Refused(PATTERN_NESTED_QUANTIFIER)
        self._paths *= branches
        if self._paths > MAX_SECRET_PATTERN_AMBIGUITY:
            raise _Refused(PATTERN_NESTED_ALTERNATION)
        return ("group", None)

    def _quantified_ahead(self) -> bool:
        """Report whether the cursor sits on a repetition."""
        char = self._peek()
        if char is None:
            return False
        if char in "*+?":
            return True
        return char == "{" and _BOUND_RE.match(self._text, self._index) is not None

    def _group(self) -> tuple[str, frozenset[int] | None]:
        """Scan a group the caller has already opened."""
        if self._peek() == "?":
            self._index += 1
            return self._extended_group()
        return self._group_from_body()

    def _group_from_body(self) -> tuple[str, frozenset[int] | None]:
        """Scan a group body and report the group it forms."""
        return self._group_result(branches=self._body())

    def _extended_group(self) -> tuple[str, frozenset[int] | None]:
        """Scan the body of "(?...)" after its "?"."""
        marker = self._peek()
        if marker is None:
            raise _Refused(PATTERN_UNCOMPILABLE)
        if marker == ":":
            self._index += 1
            return self._group_from_body()
        if marker == "P":
            self._index += 1
            if self._peek() != "<":
                raise _Refused(PATTERN_UNSAFE_CONSTRUCT)
            close = self._text.find(">", self._index)
            if close <= self._index + 1:
                raise _Refused(PATTERN_UNCOMPILABLE)
            self._index = close + 1
            return self._group_from_body()
        if marker in "=!<>":
            raise _Refused(PATTERN_UNSAFE_CONSTRUCT)
        if marker in _FLAG_LETTERS:
            while self._peek() in _FLAG_LETTERS:
                if self._peek() == "i":
                    self._fold = True
                self._index += 1
            if self._peek() == "-":
                self._index += 1
                while self._peek() in _FLAG_LETTERS:
                    self._index += 1
            terminator = self._peek()
            if terminator == ")":
                self._index += 1
                return ("zero", frozenset())
            if terminator == ":":
                self._index += 1
                return self._group_from_body()
            raise _Refused(PATTERN_UNCOMPILABLE)
        raise _Refused(PATTERN_UNSAFE_CONSTRUCT)

    def _repetition(self, *, kind: str, chars: frozenset[int] | None) -> bool:
        """Scan the repetition that follows an atom; report whether it applied."""
        char = self._peek()
        if char is None:
            return False
        if char == "{":
            bound = _BOUND_RE.match(self._text, self._index)
            if bound is None:
                return False
            self._check(kind=kind)
            self._index = bound.end()
            low = int(bound.group(1))
            high_text = bound.group(2)
            if high_text is None:
                width: int | None = 1
                upper = low
            elif not high_text:
                width = None
                upper = low
            else:
                high = int(high_text)
                width = high - low + 1
                upper = high
            if low > MAX_SECRET_PATTERN_REPEAT or upper > MAX_SECRET_PATTERN_REPEAT:
                raise _Refused(PATTERN_REPEAT_TOO_LARGE)
            if width is not None and width < 1:
                raise _Refused(PATTERN_UNCOMPILABLE)
            self._lazy()
            self._repeats.append((width, chars is None))
            return True
        if char not in "*+?":
            return False
        self._check(kind=kind)
        self._index += 1
        self._lazy()
        self._repeats.append((2 if char == "?" else None, chars is None))
        return True

    def _lazy(self) -> None:
        """Scan an optional laziness marker and refuse a second quantifier."""
        if self._peek() == "?":
            self._index += 1
        char = self._peek()
        if char is None:
            return
        if char in "*+?":
            raise _Refused(PATTERN_UNSAFE_CONSTRUCT)
        if char == "{" and _BOUND_RE.match(self._text, self._index) is not None:
            raise _Refused(PATTERN_UNSAFE_CONSTRUCT)

    def _check(self, *, kind: str) -> None:
        """Refuse a repetition whose target cannot be repeated safely."""
        if kind == "one":
            return
        if kind == "group":
            raise _Refused(PATTERN_NESTED_QUANTIFIER)
        raise _Refused(PATTERN_UNCOMPILABLE)

    def _finalize(self) -> None:
        r"""Check the repetitions one alternative collected.

        Requirement: Sanitized Persistence. The rule is positional: one
        alternative may hold at most one unbounded repetition - "*", "+",
        "{n,}" - and it must be the alternative's last atom, with nothing behind
        it at all. Anything else splits one run of input between the
        repetition and the rest of the alternative, and that split is retried
        from every start position; an atom of unknown extent answers
        PATTERN_UNBOUNDED_WILDCARD, every other shape PATTERN_AMBIGUOUS_REPEAT.

        Why being the last atom is enough: nothing behind it can fail, so the
        alternative never hands the same run back to the repetition and the run
        it consumes is entered at most once per start position. Its failures
        happen in front of it, inside the finite prefix; the product of the
        widths there (refused above MAX_SECRET_PATTERN_AMBIGUITY = 64) bounds
        how many ways one start position may split the input among them, and
        MAX_SECRET_PATTERN_LENGTH = 512 bounds how long that prefix can be. Both
        are constants of the pattern, fixed before any text is read.

        The repetition is not free of failure, and an earlier version of this
        note was wrong to say it was: "+" and "{2,}" can only match the empty
        string when their lower bound is zero. A positive lower bound fails when
        fewer than that many characters fit, but the bound itself is at most
        MAX_SECRET_PATTERN_REPEAT = 64, so such a failure reads a constant number
        of characters and ends the branch at that start position; a repetition
        with a zero lower bound cannot fail at all. Charging per start position
        therefore gives O(constant) - on success the match ends and the forward
        read is charged once, on failure at most 64 characters were read - and a
        scan over the n start positions stays linear in the text, with a
        constant that does not grow with it.

        Why an anchor is not that proof: "^" and "\A" only remove start
        positions of the whole scan. They do not unshare the input that two
        repetitions of the same alternative hand to each other, so "^a*a*a*b"
        still splits one a-run three ways before it fails, and "^.*.*.*.*x"
        still partitions one run into four wildcard pieces. A literal in front
        that the repeated atom cannot match is no proof either: it fixes the
        offset of the repetition, not how often the run behind it is re-entered,
        and it is gone the moment the atom's own character set is unknown. Both
        used to be accepted here and both are refused now, which is the
        conservative cost of the rule.

        Why a zero-width atom behind it is refused as well: "$", "\Z", "\z",
        "\b", "\B" and a flag group consume nothing, so R11 kept them and
        accepted "^sk-[A-Za-z0-9]{16,}$" - but they can fail, and a failure
        behind the repetition makes the engine hand the run back to it and retry
        the whole share from the next start position. That walk grows with the
        square of the run: "a+$" and "[a-z]+$" needed 0.029 / 0.114 / 0.440 s
        and 0.035 / 0.139 / 0.552 s on 4000 / 8000 / 16000 characters before
        they were refused. Dropping the exception is what lets the argument
        above hold without a qualifier.
        """
        product = 1
        last = len(self._repeats) - 1
        for position, (width, unknown) in enumerate(self._repeats):
            if width is None:
                if position == last and self._tail_open:
                    continue
                raise _Refused(
                    PATTERN_UNBOUNDED_WILDCARD if unknown else PATTERN_AMBIGUOUS_REPEAT
                )
            product *= width
        if product > MAX_SECRET_PATTERN_AMBIGUITY:
            raise _Refused(PATTERN_AMBIGUOUS_REPEAT)


def validate_secret_pattern(pattern: Any) -> str | None:
    r"""Report why an operator-supplied pattern is outside the safe subset.

    Requirement: Sanitized Persistence. Only this module owns the rule set, so
    the helper is exported for the configuration slice to call before it stores,
    accepts, or logs a pattern, and for the policy snapshot before it compiles
    one. Nothing that answers with a code is ever compiled: the refusal happens
    here, in front of the snapshot, the Anonymizer and the TaintStore, so a
    refused expression cannot run inside a redact or deny scan at all. An
    accepted expression still executes synchronously inside every redact call,
    so MAX_SECRET_PATTERN_LENGTH, MAX_REDACT_SCAN and MAX_SECRET_PATTERN_AMBIGUITY
    are what bound that cost, never this check alone.

    The linearity this check proves, per top-level alternative (see _finalize
    for the full argument): at most one unbounded repetition, as the
    alternative's last atom, with nothing behind it. Nothing behind it can fail,
    so the run is never handed back to it, and every failure happens in front of
    it inside a finite prefix whose split count is bounded by the product of the
    widths (MAX_SECRET_PATTERN_AMBIGUITY = 64) and whose length is bounded by
    MAX_SECRET_PATTERN_LENGTH = 512 - both constants of the pattern. The
    repetition itself can still fail on a positive lower bound, but only after
    reading at most MAX_SECRET_PATTERN_REPEAT = 64 characters, and a repetition
    with a zero lower bound cannot fail at all. One start position therefore
    costs O(constant), and the scan over n start positions stays linear in the
    text.

    Neither an anchor nor a zero-width assertion is part of that proof: "^" and
    "\A" only remove start positions of the whole scan, they cannot unshare the
    input two repetitions of one alternative hand to each other, and "$", "\Z",
    "\z", "\b", "\B" and a flag group can fail behind the repetition, which
    makes the engine hand the run back and retry the share from the next start
    position. That is why "^a*a*a*b", "^.*.*.*.*x" and "a+$" are all refused.

    The cost of the rule is honest: a pattern that used to pass because it was
    anchored, because a literal in front of the repetition could not match the
    repeated atom, or because a zero-width assertion closed it, is refused from
    here on - "^.*x", "a.*x", "foo.*bar", "(?:^|a).*x", "(?ms:^.*x)",
    "(?i)password\s*[:=]", "^sk-[A-Za-z0-9]{16,}$" and the pre-R11 shipped
    default "(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----" among them. A refused
    pattern is dropped by every compiling consumer, so the operator sees an
    advisory instead of a rule that would have frozen the loop; the defaults
    this build ships use bounded widths ("[A-Z ]{0,63}", "[ ]{0,4}") and stay
    inside the subset.

    Args:
        pattern: Raw expression from configuration.

    Returns:
        None when the expression may be compiled and used, else a stable reason
        code (PATTERN_TOO_LONG, PATTERN_NESTED_QUANTIFIER,
        PATTERN_NESTED_ALTERNATION, PATTERN_REPEAT_TOO_LARGE,
        PATTERN_AMBIGUOUS_REPEAT, PATTERN_UNSAFE_CONSTRUCT,
        PATTERN_UNBOUNDED_WILDCARD, or PATTERN_UNCOMPILABLE) that a caller may
        log verbatim.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        return PATTERN_UNCOMPILABLE
    if len(pattern) > MAX_SECRET_PATTERN_LENGTH:
        return PATTERN_TOO_LONG
    refused = _ShapeScanner(pattern).scan()
    if refused is not None:
        return refused
    try:
        re.compile(pattern)
    except re.error:
        return PATTERN_UNCOMPILABLE
    return None


def _redact_pem_blocks(text: str) -> str:
    """Replace every complete PEM private-key block with its placeholder.

    Requirement: Sanitized Persistence. The scan is linear: the BEGIN and END
    markers are located once each and merged left to right, so a document full of
    unterminated headers costs one pass instead of one backtracking scan per
    header. The DOTALL pattern this replaces needed about 1.2 s for 4000
    unterminated headers and about 46 s for a 940 KB document, synchronously, on
    the loop.

    Args:
        text: Raw text, already truncated to MAX_REDACT_SCAN characters.

    Returns:
        The text with every BEGIN...END slice replaced by <SECRET:private_key>.
    """
    begins = list(_PEM_BEGIN_RE.finditer(text))
    ends = [match.end() for match in _PEM_END_RE.finditer(text)]
    if not begins or not ends:
        return text
    pieces: list[str] = []
    cursor = 0
    end_index = 0
    for begin in begins:
        if begin.start() < cursor:
            continue
        while end_index < len(ends) and ends[end_index] <= begin.end():
            end_index += 1
        if end_index >= len(ends):
            break
        pieces.append(text[cursor : begin.start()])
        pieces.append(_placeholder("private_key"))
        cursor = ends[end_index]
        end_index += 1
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


@dataclass(frozen=True)
class _Rule:
    """One redaction rule.

    Attributes:
        name: Secret class name used in the emitted placeholder.
        pattern: Compiled expression matched against the raw text.
        template: re.sub replacement, either a template string that may
            reference capture groups or a callable taking the match.
    """

    name: str
    pattern: re.Pattern[str]
    template: str | Callable[[re.Match[str]], str]


_URL_CREDENTIAL_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9+.\-]*://)([^\s/?#<>]*:[^\s/?#<>]*)@(?=[A-Za-z0-9\[\.])"
)

_URL_USER_RE = re.compile(r"[^:]+")


def _url_credential_template(match: re.Match[str]) -> str:
    """Keep the user name and redact the whole password of a URL credential.

    Requirement: Sanitized Persistence. The match already owns every character
    up to the last "@" that precedes the host, so a password that itself
    contains an "@" cannot leave a tail behind, and the empty-user form
    "redis://:secret@host" is covered as well.

    Args:
        match: Match of the scheme and the complete userinfo.

    Returns:
        The scheme, the user name when there is one, then the placeholder.
    """
    scheme = match.group(1)
    user = _URL_USER_RE.match(match.group(2))
    head = f"{scheme}{user.group(0)}:" if user else scheme
    return f"{head}{_placeholder('url_password')}@"


def _key_value_pattern(names: str, *, skip: str = "") -> re.Pattern[str]:
    """Return a key/value rule that redacts a value of any length.

    Requirement: Sanitized Persistence. The built-in binding rule this
    complements needs six characters, so "password=abc12" and "pwd=hunter2"
    survived it; here the value may be a single character. The lookahead after
    the separator refuses an already emitted placeholder, which is what makes
    redaction idempotent without weakening the rule.

    Args:
        names: Alternation of the key names the rule owns.
        skip: Alternation that a value may begin with and still stay readable,
            such as an authentication scheme whose credential follows it.

    Returns:
        The compiled expression.
    """
    guard = f"(?!{skip})" if skip else ""
    return re.compile(
        r"(?i)(?<![A-Za-z0-9<])"
        r"(" + names + r")"
        r"([\"']?\s*[:=]\s*)" + guard + r"(?:"
        r"(?P<q>[\"'])(?!<SECRET:)(?P<quoted>[^\n]*?)(?P=q)"
        r"|(?!<SECRET:)(?P<bare>[^\s,;&\"'<>=]+)"
        r")"
    )


_KEY_SEPARATOR = r"[_.\-\s]?"
"""Separator allowed between the words of a compound key name."""

_PASSWORD_KEY_ALIASES: tuple[tuple[str, ...], ...] = (
    ("password",),
    ("passphrase",),
    ("pass", "phrase"),
    ("passcode",),
    ("passwd",),
    ("pass",),
    ("pwd",),
)
"""Aliases of a key that binds a password.

Requirement: Sanitized Persistence. "passphrase" and "passcode" name the same
secret as "password" and were readable only because no alias reached them; the
compound form matches "pass_phrase", "pass-phrase", and "pass phrase" through
_KEY_SEPARATOR like every other compound alias.
"""

_ENV_PASSWORD_KEY_ALIASES: tuple[tuple[str, ...], ...] = (
    ("pg", "password"),
    ("pg", "pass"),
    ("mysql", "password"),
    ("mysql", "pass"),
    ("mysql", "pwd"),
)
"""Aliases of an environment variable that names a password in one glued word.

Requirement: Sanitized Persistence. A key rule refuses a match that starts
inside a word, which is what keeps "compass" and "bypass" readable; the same
guard is why an exported "PGPASSWORD=hunter2" survived every rule, because the
password spelling is glued to a program prefix with no separator to match on.
These aliases name that glued form pair by pair, so only a prefix an
environment really uses becomes a key.
"""

_TOKEN_KEY_ALIASES: tuple[tuple[str, ...], ...] = (
    ("secret", "access", "key"),
    ("client", "secret"),
    ("credentials",),
    ("session", "key"),
    ("private", "key"),
    ("credential",),
    ("secret", "key"),
    ("access", "key"),
    ("password",),
    ("passwd",),
    ("apikey",),
    ("api", "key"),
    ("secret",),
    ("token",),
)
"""Aliases of a key that binds a credential, longest name first.

Requirement: Sanitized Persistence. An alias is a complete key name followed by
the separator and ":" or "=", so "compass", "bypass", "tokenizer", and
"secretary" stay readable: the match is never a substring. Compound aliases
accept any one of "_", "-", "." and a space between words, which is what makes
"SecretAccessKey", "secret-access-key", and "secret access key" one key, and the
placeholder names the class through _normalise_key. "password_hint" is
deliberately not an alias: its value is text *about* a password, and a hint that
is itself a credential is already caught when it is stored under its own key.
"""


def _key_alias_regex(aliases: tuple[tuple[str, ...], ...]) -> str:
    """Build the alternation of key aliases for _key_value_pattern.

    Requirement: Sanitized Persistence. Every alias is emitted whole, so the
    pattern that uses it can only match a complete key name.

    Args:
        aliases: Word tuples, longest name first.

    Returns:
        A regex body, one alternative per alias.
    """
    return "|".join(_KEY_SEPARATOR.join(words) for words in aliases)


_PASSWORD_KEY_RE = _key_value_pattern(_key_alias_regex(_PASSWORD_KEY_ALIASES))
"""Key/value password binding with no minimum length on the value."""

_TOKEN_KEY_RE = _key_value_pattern(_key_alias_regex(_TOKEN_KEY_ALIASES))
"""Key/value token binding with no minimum length on the value."""

_ENV_PASSWORD_KEY_RE = _key_value_pattern(_key_alias_regex(_ENV_PASSWORD_KEY_ALIASES))
"""Key/value binding for an environment variable that glues "password" to a prefix."""

_HTTP_AUTH_SCHEMES = (
    "aws4-hmac-sha256|bearer|basic|digest|negotiate|ntlm|hawk|oauth|scram|vapid|gnap"
)
"""Authentication schemes that name how a credential follows, not the credential.

Requirement: Sanitized Persistence. "Authorization: Bearer <token>" keeps its
scheme word readable: the bearer and basic_auth rules own the credential that
follows, and redacting the scheme itself would both lose that context and stop
them from matching at all.
"""

_AUTHORIZATION_KEY_ALIASES: tuple[tuple[str, ...], ...] = (
    ("authorization",),
    ("auth",),
)
"""Aliases of a key that carries a credential unless its value names a scheme."""

_AUTHORIZATION_KEY_RE = _key_value_pattern(
    _key_alias_regex(_AUTHORIZATION_KEY_ALIASES), skip=_HTTP_AUTH_SCHEMES
)
"""Key/value authorization binding with no minimum length on the value."""


def _normalise_key(text: str) -> str:
    """Fold a key name to the form the placeholder shows.

    Requirement: Sanitized Persistence. Camel case is split before the fold, so
    "SecretAccessKey", "secret_access_key", and "SECRET-ACCESS-KEY" all become
    "secret_access_key" and one credential class gets one name in the audit row.

    Args:
        text: Key name exactly as it appeared in the text.

    Returns:
        The folded key name.
    """
    split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
    return re.sub(r"[^0-9A-Za-z]+", "_", split).strip("_").lower()


def _key_value_template(match: re.Match[str]) -> str:
    """Keep the quoting of a value and replace the value itself.

    Requirement: Sanitized Persistence. The placeholder repeats the key name, so
    the emitted text has the shape the older six-character binding rule produced;
    a quoted value keeps its quotes, which is what lets a JSON body stay
    readable. The value is never re-read on a second pass: the pattern refuses a
    value that already opens with "<SECRET:".

    Args:
        match: Match of the key, the separator, and the value.

    Returns:
        The key, its separator, and the placeholder.
    """
    placeholder = _placeholder(_normalise_key(match.group(1)))
    quote = match.group("q")
    if quote is None:
        return f"{match.group(1)}{match.group(2)}{placeholder}"
    return f"{match.group(1)}{match.group(2)}{quote}{placeholder}{quote}"


_HTTP_BASIC_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9<])(authorization|proxy-authorization)"
    r"([\"']?\s*[:=]\s*[\"']?)(basic)\s+([A-Za-z0-9+/=]{8,})"
)
"""An Authorization header whose Basic credential is base64 with no digit.

Requirement: Sanitized Persistence. The standalone basic_auth rule requires a
digit or a padding character in the value, which a short "user:password" pair
need not produce, and the authorization key rule deliberately skips a value that
opens with a scheme, so "Authorization: Basic dXNlcjpwYXNz" matched nothing. The
header shape is what carries the intent, so this rule owns the pair.
"""


def _http_basic_header_template(match: re.Match[str]) -> str:
    """Keep an Authorization header and its scheme, redact the credential.

    Args:
        match: Match of the header name, its separator, the scheme, and the value.

    Returns:
        The header, its separator, the scheme, and the placeholder.
    """
    placeholder = _placeholder("basic_auth")
    return f"{match.group(1)}{match.group(2)}{match.group(3)} {placeholder}"


_DEFAULT_RULES: tuple[_Rule, ...] = (
    _Rule(
        "url_secret",
        re.compile(
            r"([?&](password|passwd|token|access_token|api_key|apikey|secret)=)"
            r"[^&#\s\"']+",
            re.IGNORECASE,
        ),
        r"\1<SECRET:\2>",
    ),
    _Rule(
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+={0,2}", re.IGNORECASE),
        "Bearer " + _placeholder("bearer_token"),
    ),
    _Rule(
        "api_key",
        re.compile(r"\bsk-[A-Za-z0-9_\-]{3,}={0,2}"),
        _placeholder("api_key"),
    ),
    _Rule(
        "github_token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{4,}"),
        _placeholder("github_token"),
    ),
    _Rule(
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{3,}"),
        _placeholder("slack_token"),
    ),
    _Rule(
        "aws_access_key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{4,}"),
        _placeholder("aws_access_key"),
    ),
    _Rule(
        "private_key",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"
            r"(?:[ \t]*\r?\n[ \t]*[A-Za-z0-9+/=]{4,})*"
        ),
        _placeholder("private_key"),
    ),
    _Rule(
        "url_password",
        _URL_CREDENTIAL_RE,
        _url_credential_template,
    ),
    _Rule(
        "basic_auth",
        re.compile(
            r"\bBasic\s+(?=[A-Za-z0-9+/=]{8,})(?=[A-Za-z0-9+/=]*[0-9+/=])"
            r"[A-Za-z0-9+/=]{8,}",
            re.IGNORECASE,
        ),
        "Basic " + _placeholder("basic_auth"),
    ),
    _Rule(
        "password",
        re.compile(
            r"\b((?:mysql|mysqldump|mariadb(?:-dump)?|mysqladmin|mysqlshow|mysqlimport)"
            r"\b[^\n]*?(?<!\S)-p)\S+",
            re.IGNORECASE,
        ),
        r"\1<SECRET:password>",
    ),
    _Rule(
        "curl_password",
        re.compile(r"(?<!\S)(--user=?|-u)(\s*)([^\s:@]+):(\S+)"),
        r"\1\2\3:<SECRET:curl_password>",
    ),
    _Rule(
        "aws_secret_key",
        re.compile(
            r"\b((?:aws_)?secret_access_key)(\s*[:=]\s*[\"']?)"
            r"[A-Za-z0-9/+=]{40}",
            re.IGNORECASE,
        ),
        r"\1\2<SECRET:aws_secret_key>",
    ),
    _Rule(
        "aws_secret_key",
        re.compile(
            r"\b(?=[A-Za-z0-9/+=]{40}\b)"
            r"(?=[A-Za-z0-9/+=]*[a-z])(?=[A-Za-z0-9/+=]*[A-Z])"
            r"(?=[A-Za-z0-9/+=]*[0-9])(?=[A-Za-z0-9/+=]*[/+])"
            r"[A-Za-z0-9/+=]{40}\b"
        ),
        _placeholder("aws_secret_key"),
    ),
    _Rule(
        "github_token",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{4,}"),
        _placeholder("github_token"),
    ),
    _Rule(
        "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"),
        _placeholder("google_api_key"),
    ),
    _Rule(
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]*={0,2}"
        ),
        _placeholder("jwt"),
    ),
    _Rule(
        "password",
        _PASSWORD_KEY_RE,
        _key_value_template,
    ),
    _Rule(
        "authorization",
        _AUTHORIZATION_KEY_RE,
        _key_value_template,
    ),
    _Rule(
        "token",
        _TOKEN_KEY_RE,
        _key_value_template,
    ),
    _Rule(
        "password",
        _ENV_PASSWORD_KEY_RE,
        _key_value_template,
    ),
    _Rule(
        "basic_auth",
        _HTTP_BASIC_HEADER_RE,
        _http_basic_header_template,
    ),
    _Rule(
        "binding",
        re.compile(
            r"(?i)(?<![A-Za-z0-9<])"
            r"(api_key|apikey|access_key|secret_key|secret|password|passwd|token|key)"
            r"([\"']?\s*[:=]\s*[\"']?)"
            r"[^\s,;&\"'<>]{6,}"
        ),
        r"\1\2<SECRET:\1>",
    ),
)
"""Built-in patterns; each one covers a secret class named by the spec.

Order matters: the operator-independent rules run before the loose
key/value binding rule, and that last rule only matches a value that is
not already a placeholder, so the earlier classes keep their names.
"""

_HOME_PLACEHOLDER = "<HOME>"
"""Replacement of the administrator home prefix."""

_EXT_PLACEHOLDER = "<EXT>"
"""Replacement of an absolute path that lives outside every configured root."""

_QUOTE_LEFT = "\"'([{"
_QUOTE_RIGHT = "\"')]};,"
"""Characters trimmed off a token before it is inspected as a path."""

_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _is_absolute_path(text: str) -> bool:
    """Report whether a normalised token is an absolute path.

    Args:
        text: Token with backslashes already folded to forward slashes.

    Returns:
        True for a Windows drive path, a UNC path, or a POSIX path.
    """
    if not text:
        return False
    if _DRIVE_RE.match(text):
        return True
    if text.startswith("//"):
        return True
    return text.startswith("/") and len(text) > 1


class PathRedactor:
    """Replace home paths and out-of-root absolute paths in text.

    Requirement: Sanitized Persistence.

    A path inside the administrator home becomes <HOME> plus the remaining
    relative part; an absolute path outside every configured root becomes
    <EXT>/<basename>; a path under a root, a relative path, and any token that is
    not a path are returned untouched. With no root configured every absolute
    path outside home still reduces, because the default deployment configures
    no roots and Sanitized Persistence forbids leaking directory structure.

    The redactor works on whitespace-separated tokens, so a path keeps the
    surrounding quotes, brackets, and punctuation of the original text.

    Args:
        home: Administrator home directory; ignored unless absolute.
        roots: Absolute directories that count as inside the workspace.
    """

    def __init__(self, home: str | None = None, roots: Sequence[str] = ()) -> None:
        """Normalise the home prefix and the root allowlist.

        Args:
            home: Administrator home directory, optional.
            roots: Absolute workspace directories, optional.
        """
        home_text = self._normalise(home)
        self._home = home_text if _is_absolute_path(home_text) else ""
        accepted: list[str] = []
        for root in roots or ():
            candidate = self._normalise(root)
            if _is_absolute_path(candidate):
                accepted.append(candidate.casefold())
        self._roots: tuple[str, ...] = tuple(accepted)

    @property
    def home(self) -> str:
        """Return the accepted home prefix, empty when unusable.

        Returns:
            The normalised absolute home directory, or an empty string.
        """
        return self._home

    @property
    def roots(self) -> tuple[str, ...]:
        """Return the accepted roots, case-folded for comparison.

        Returns:
            The normalised absolute roots.
        """
        return self._roots

    @staticmethod
    def _normalise(value: Any) -> str:
        """Fold one path into the comparison form used by this redactor.

        Args:
            value: Configured path, possibly with quotes or backslashes.

        Returns:
            A forward-slash path without a trailing separator, or "".
        """
        text = _stringify(value).strip().strip("\"'")
        if not text:
            return ""
        text = text.replace("\\", "/")
        while len(text) > 1 and text.endswith("/"):
            text = text[:-1]
        return text

    def redact(self, text: str) -> str:
        """Return the text with home and out-of-root absolute paths replaced.

        Requirement: Sanitized Persistence.

        Args:
            text: Raw text; a non-string value is stringified first.

        Returns:
            The rewritten text, or the input unchanged when nothing applies.
        """
        raw = _stringify(text)
        if not raw:
            return raw
        try:
            pieces = re.split(r"(\s+)", raw)
            for index, piece in enumerate(pieces):
                if piece and not piece.isspace():
                    pieces[index] = self._redact_token(piece)
            return "".join(pieces)
        except Exception:  # noqa: BLE001 - redaction must never break a caller
            return raw

    def _redact_token(self, token: str) -> str:
        """Redact one whitespace-delimited token while keeping its trimming.

        Args:
            token: One token of the original text, punctuation included.

        Returns:
            The token with its path part replaced when a rule applies.
        """
        lead = ""
        trail = ""
        core = token
        while core and core[0] in _QUOTE_LEFT:
            lead += core[0]
            core = core[1:]
        while core and core[-1] in _QUOTE_RIGHT:
            trail = core[-1] + trail
            core = core[:-1]
        if not core:
            return token
        return lead + self._redact_path(core) + trail

    def _redact_path(self, candidate: str) -> str:
        """Return the placeholder form of one candidate path.

        Args:
            candidate: Token content without surrounding punctuation.

        Returns:
            <HOME>/<relative>, <EXT>/<basename>, or the candidate unchanged.
        """
        normalised = candidate.replace("\\", "/")
        while len(normalised) > 1 and normalised.endswith("/"):
            normalised = normalised[:-1]
        if not _is_absolute_path(normalised):
            return candidate
        folded = normalised.casefold()
        if self._home:
            home = self._home.casefold()
            if folded == home:
                return _HOME_PLACEHOLDER
            if folded.startswith(home + "/"):
                return _HOME_PLACEHOLDER + "/" + normalised[len(self._home) + 1 :]
        for root in self._roots:
            if folded == root or folded.startswith(root + "/"):
                return candidate
        name = normalised.rsplit("/", 1)[-1]
        return f"{_EXT_PLACEHOLDER}/{name}" if name else candidate


class Anonymizer:
    """Redact secrets from text, mappings, and truncated excerpts.

    Requirement: Sanitized Persistence; Notification Content.

    Args:
        patterns: Extra regular expressions, typically
            GatewayConfig.secret_patterns. An expression that does not compile
            is ignored, so a bad configuration can never disable redaction.
        paths: Path redactor applied after the secret rules, optional. Omit it
            and the text output is byte-identical to the secret-only behaviour.
    """

    def __init__(
        self,
        patterns: Sequence[str] | None = None,
        *,
        paths: PathRedactor | None = None,
    ) -> None:
        """Compile the built-in rules plus the accepted operator patterns.

        Args:
            patterns: Extra regular expressions, optional.
            paths: Path redactor for home and out-of-root absolute paths,
                optional.
        """
        rules = list(_DEFAULT_RULES)
        accepted: list[str] = []
        for entry in patterns or ():
            if validate_secret_pattern(entry) is not None:
                continue
            accepted.append(entry)
            rules.append(_Rule("custom", re.compile(entry), CUSTOM_PLACEHOLDER))
        self._rules: tuple[_Rule, ...] = tuple(rules)
        self._patterns: tuple[str, ...] = tuple(accepted)
        self._paths = paths

    @property
    def patterns(self) -> tuple[str, ...]:
        """Return the operator patterns that were accepted.

        Returns:
            The raw expressions still active, for diagnostics and tests.
        """
        return self._patterns

    @property
    def paths(self) -> PathRedactor | None:
        """Return the path redactor, None when only secrets are handled.

        Returns:
            The configured PathRedactor or None.
        """
        return self._paths

    def redact(self, text: str) -> str:
        """Return the text with every known secret replaced by a placeholder.

        Requirement: Sanitized Persistence.

        Args:
            text: Raw text; a non-string value is stringified first.

        Returns:
            The redacted text, equal to the input when nothing matched.
        """
        result = _stringify(text)[:MAX_REDACT_SCAN]
        result = _redact_pem_blocks(result)
        for rule in self._rules:
            result = rule.pattern.sub(rule.template, result)
        result = _PLACEHOLDER_RE.sub(
            lambda match: _placeholder(match.group(1).lower()), result
        )
        if self._paths is not None:
            result = self._paths.redact(result)
        return result

    def redact_mapping(self, arguments: Mapping[str, Any] | None) -> dict[str, Any]:
        """Return a copy of the arguments with every key and leaf redacted.

        Requirement: Notification Content; Sanitized Persistence.

        A dictionary key can be a secret itself ("{'sk-…': 'value'}"), so keys
        pass through the same rules as values. Redacting a key can collide with
        another key that was already emitted; the first occurrence keeps its
        name and every later one gains a "#2", "#3", … suffix in iteration
        order, so no value is dropped and no key is overwritten.

        Args:
            arguments: Tool arguments, optional; keys are turned into strings.

        Returns:
            A new dictionary with the same shape, redacted keys and values.
        """
        if not arguments:
            return {}
        if not isinstance(arguments, Mapping):
            return {"value": self.redact(_stringify(arguments))}
        redacted: dict[str, Any] = {}
        for key, value in arguments.items():
            name = self.redact(_stringify(key))
            candidate = name
            ordinal = 1
            while candidate in redacted:
                ordinal += 1
                candidate = f"{name}#{ordinal}"
            redacted[candidate] = self._redact_value(value)
        return redacted

    def redact_head(self, text: str, limit: int) -> str:
        """Redact first, then truncate to the limit in characters.

        Requirement: Notification Content; Sanitized Persistence.

        Args:
            text: Raw text.
            limit: Maximum number of characters kept; a non-positive limit
                yields an empty string.

        Returns:
            A prefix that never contains a partially redacted secret.
        """
        redacted = self.redact(text)
        try:
            cap = int(limit)
        except (TypeError, ValueError):
            return ""
        if cap <= 0:
            return ""
        return redacted[:cap]

    def _redact_value(self, value: Any) -> Any:
        """Redact one value while preserving its shape.

        Args:
            value: Any value taken from the arguments mapping.

        Returns:
            Redacted strings, lists, and maps; scalars are returned unchanged.
        """
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, Mapping):
            return self.redact_mapping(value)
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._redact_value(item) for item in value]
        if isinstance(value, (bytes, bytearray)):
            return self.redact(bytes(value).decode("utf-8", "replace"))
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.redact(_stringify(value))


def anonymize(value: Any, *, secret_patterns: Sequence[str] = ()) -> Any:
    """Return a redacted value before persistence, notification, or model use.

    Requirement: Sanitized Persistence.

    Args:
        value: A mapping is redacted key by key; anything else is stringified
            and redacted as text.
        secret_patterns: Extra expressions, see the Anonymizer class.

    Returns:
        A redacted mapping, or the redacted text form of the value.
    """
    anonymizer = Anonymizer(secret_patterns)
    if isinstance(value, Mapping):
        return anonymizer.redact_mapping(value)
    return anonymizer.redact(_stringify(value))


__all__ = [
    "MAX_REDACT_SCAN",
    "MAX_SECRET_PATTERN_LENGTH",
    "PATTERN_NESTED_QUANTIFIER",
    "PATTERN_TOO_LONG",
    "PATTERN_UNBOUNDED_WILDCARD",
    "PATTERN_UNCOMPILABLE",
    "Anonymizer",
    "PathRedactor",
    "anonymize",
    "validate_secret_pattern",
]
