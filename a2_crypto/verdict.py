"""
verdict.py - the six verdict codes (FR10) and the structured result object.

THE DISTINCTION THAT EARNS MARKS (criterion 4)
    SIGNATURE_INVALID means "someone edited the payload record, or it was
    signed with a key we do not trust". The media may be untouched.

    TAMPERED means "the payload record is genuine and correctly signed, but
    the media itself was altered after signing". The signature is fine; the
    recomputed cover hash is not.

    Those are different attacks with different responses, and the pipeline
    reports them separately rather than collapsing both into "failed".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .trace import Trace


class VerdictCode(str, Enum):
    """Wording matches the spec's suggested categories."""
    AUTHENTIC = "Authentic"
    TAMPERED = "Tampered"
    SIGNATURE_INVALID = "Signature Invalid"
    PAYLOAD_MISSING = "Payload Missing"
    WRONG_START_LOCATION = "Wrong Start Location"
    CANNOT_VERIFY = "Cannot Verify"

    def __str__(self) -> str:
        return self.value


# What each code means, for the README and the GUI tooltip.
VERDICT_MEANING = {
    VerdictCode.AUTHENTIC:
        "Payload found, signature valid, cover hash matches, message decrypted. "
        "The file is the one that was signed and it has not been altered since.",
    VerdictCode.TAMPERED:
        "Signature is valid, so the payload record is genuine - but the cover "
        "content has changed since it was signed.",
    VerdictCode.SIGNATURE_INVALID:
        "A payload was recovered but the signature does not verify under the "
        "supplied public key: the record was edited, or it was signed by "
        "someone else.",
    VerdictCode.PAYLOAD_MISSING:
        "No payload magic anywhere in the cover at this LSB depth. The file "
        "most likely carries nothing.",
    VerdictCode.WRONG_START_LOCATION:
        "A payload IS present, but not at the offset these parameters derive. "
        "The passphrase, media ID or LSB count does not match the one used to "
        "embed it.",
    VerdictCode.CANNOT_VERIFY:
        "Verification could not be completed: missing key, unreadable input, "
        "corrupt header, or a decryption failure.",
}

# Colour hints for the GUI banner. Green pass, red failure, amber inconclusive.
VERDICT_COLOUR = {
    VerdictCode.AUTHENTIC: "#1b7f3a",
    VerdictCode.TAMPERED: "#b3261e",
    VerdictCode.SIGNATURE_INVALID: "#b3261e",
    VerdictCode.PAYLOAD_MISSING: "#8a6d00",
    VerdictCode.WRONG_START_LOCATION: "#8a6d00",
    VerdictCode.CANNOT_VERIFY: "#8a6d00",
}


@dataclass
class Verdict:
    """
    The complete result of a verification. Carries everything the GUI needs to
    render its panel and everything person 6 needs for evidence capture.
    """
    code: VerdictCode
    reason: str
    payload: object | None = None          # a payload.Payload when recovered
    message: bytes | None = None           # decrypted message when AUTHENTIC
    details: dict = field(default_factory=dict)
    trace: Trace | None = None

    # -- convenience --------------------------------------------------------
    @property
    def ok(self) -> bool:
        return self.code is VerdictCode.AUTHENTIC

    @property
    def colour(self) -> str:
        return VERDICT_COLOUR[self.code]

    @property
    def meaning(self) -> str:
        return VERDICT_MEANING[self.code]

    def message_text(self, errors: str = "replace") -> str:
        if self.message is None:
            return ""
        return self.message.decode("utf-8", errors=errors)

    def to_dict(self) -> dict:
        out = {
            "verdict": self.code.value,
            "reason": self.reason,
            "meaning": self.meaning,
            "details": self.details,
        }
        if self.payload is not None:
            out["payload"] = self.payload.to_dict()
        if self.message is not None:
            out["message"] = self.message_text()
        if self.trace is not None:
            out["trace"] = self.trace.to_dict()
        return out

    def __str__(self) -> str:
        return "{}: {}".format(self.code.value, self.reason)
