"""Bounded, non-destructive payload selection primitives."""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from enum import Enum
from urllib.parse import quote


class PayloadContext(str, Enum):
    HTML_TEXT = "html_text"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class PayloadObservation:
    """Facts observed in a response; not a vulnerability verdict."""

    reflected: bool
    exact_match: bool
    transformation: str
    context: PayloadContext
    observed_value: str | None


@dataclass(frozen=True)
class ProbeDecision:
    """A bounded next-probe choice with its rationale."""

    payload: str
    hypothesis: str
    rationale: str


class AdaptivePayloadEngine:
    """Classify reflected-marker context and generate bounded probes.

    This class performs no network I/O. Reflection alone is not proof
    of a vulnerability.
    """

    def __init__(
        self,
        *,
        max_candidates: int = 8,
        max_payload_bytes: int = 512,
    ) -> None:
        if (
            isinstance(max_candidates, bool)
            or not isinstance(max_candidates, int)
            or max_candidates < 1
        ):
            raise ValueError("max_candidates must be a positive integer")
        if (
            isinstance(max_payload_bytes, bool)
            or not isinstance(max_payload_bytes, int)
            or max_payload_bytes < 1
        ):
            raise ValueError("max_payload_bytes must be a positive integer")

        self.max_candidates = max_candidates
        self.max_payload_bytes = max_payload_bytes

    @staticmethod
    def classify_reflection(body: str, marker: str) -> PayloadContext:
        """Classify obvious contexts conservatively; this is not an HTML parser."""
        if not isinstance(body, str) or not isinstance(marker, str) or not marker:
            return PayloadContext.UNKNOWN

        position = body.find(marker)
        if position < 0:
            return PayloadContext.UNKNOWN

        try:
            json.loads(body)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        else:
            return PayloadContext.JSON

        before = body[:position]
        lower_before = before.lower()

        # Ignore comments and contexts where lexical HTML checks are unreliable.
        if lower_before.rfind("<!--") > lower_before.rfind("-->"):
            return PayloadContext.UNKNOWN

        for tag in ("script", "style", "textarea", "title"):
            opening = lower_before.rfind(f"<{tag}")
            closing = lower_before.rfind(f"</{tag}")
            if opening > closing:
                return PayloadContext.UNKNOWN

        if before.rfind("<") > before.rfind(">"):
            return PayloadContext.HTML_ATTRIBUTE

        if "<" in body and ">" in body:
            return PayloadContext.HTML_TEXT

        return PayloadContext.UNKNOWN

    def observe(self, *, body: str, marker: str) -> PayloadObservation:
        """Identify exact or common encoded reflection without claiming exploitability."""
        if not isinstance(body, str) or not isinstance(marker, str) or not marker:
            raise ValueError("body must be text and marker must be non-empty text")

        candidates = (
            ("exact", marker),
            ("html_entity", html.escape(marker, quote=True)),
            ("url_percent", quote(marker, safe="")),
            ("json_escape", json.dumps(marker, ensure_ascii=True)[1:-1]),
        )

        # Prefer the exact form; otherwise choose the first transformed form found.
        found = next(
            ((kind, value) for kind, value in candidates
             if value and value in body),
            None,
        )

        if found is None:
            return PayloadObservation(
                reflected=False,
                exact_match=False,
                transformation="absent",
                context=PayloadContext.UNKNOWN,
                observed_value=None,
            )

        transformation, observed_value = found
        normalized_body = body.replace(observed_value, marker, 1)
        context = self.classify_reflection(normalized_body, marker)

        return PayloadObservation(
            reflected=True,
            exact_match=transformation == "exact",
            transformation=transformation,
            context=context,
            observed_value=observed_value,
        )

    def select_next(
        self,
        observation: PayloadObservation,
        *,
        marker: str,
    ) -> ProbeDecision | None:
        """Choose one distinct representation probe based on observed evidence."""
        if not isinstance(observation, PayloadObservation):
            raise TypeError("observation must be a PayloadObservation")
        if not observation.reflected:
            return None
        if not isinstance(marker, str) or not marker:
            raise ValueError("marker must be non-empty text")

        context = observation.context
        if context == PayloadContext.UNKNOWN:
            hypothesis = "The input is reflected, but its output context is uncertain."
            rationale = (
                "Use a conservative representation comparison; do not infer "
                "executable behavior from reflection alone."
            )
        else:
            hypothesis = (
                f"The input is reflected in a {context.value} context; "
                "output handling may affect security."
            )
            rationale = (
                f"The response showed {observation.transformation} reflection. "
                f"Compare a different representation for the inferred {context.value} "
                "context; this is diagnostic evidence, not proof of exploitability."
            )

        for candidate in self.generate(marker=marker, context=context):
            if candidate != observation.observed_value:
                return ProbeDecision(
                    payload=candidate,
                    hypothesis=hypothesis,
                    rationale=rationale,
                )

        return None

    def generate(
        self,
        *,
        marker: str,
        context: PayloadContext,
    ) -> list[str]:
        """Generate unique, size-bounded, non-executing representation probes."""
        if not isinstance(marker, str) or not marker:
            raise ValueError("marker must be a non-empty string")

        if not isinstance(context, PayloadContext):
            try:
                context = PayloadContext(context)
            except (TypeError, ValueError) as exc:
                raise ValueError("unsupported payload context") from exc

        html_encoded = html.escape(marker, quote=True)
        url_encoded = quote(marker, safe="")
        json_encoded = json.dumps(marker, ensure_ascii=True)
        js_string_content = json_encoded[1:-1]

        if context == PayloadContext.HTML_TEXT:
            proposed = [
                marker,
                html_encoded,
                f"<!--{marker}-->",
                url_encoded,
            ]
        elif context == PayloadContext.HTML_ATTRIBUTE:
            proposed = [
                marker,
                html_encoded,
                url_encoded,
                json_encoded,
            ]
        elif context == PayloadContext.JAVASCRIPT:
            proposed = [
                marker,
                js_string_content,
                json_encoded,
                url_encoded,
            ]
        elif context == PayloadContext.JSON:
            proposed = [
                marker,
                json_encoded,
                js_string_content,
                url_encoded,
            ]
        else:
            proposed = [
                marker,
                html_encoded,
                url_encoded,
                json_encoded,
            ]

        candidates = []
        seen = set()

        for candidate in proposed:
            if candidate in seen:
                continue
            seen.add(candidate)

            if len(candidate.encode("utf-8")) > self.max_payload_bytes:
                continue

            candidates.append(candidate)
            if len(candidates) >= self.max_candidates:
                break

        if not candidates:
            raise ValueError("marker cannot fit within max_payload_bytes")

        return candidates

class ProbeSession:
    """Track distinct payload selections under a cumulative session budget."""

    def __init__(
        self,
        engine: AdaptivePayloadEngine,
        *,
        max_probes: int = 8,
    ) -> None:
        if not isinstance(engine, AdaptivePayloadEngine):
            raise TypeError("engine must be an AdaptivePayloadEngine")
        if (
            isinstance(max_probes, bool)
            or not isinstance(max_probes, int)
            or max_probes < 1
        ):
            raise ValueError("max_probes must be a positive integer")

        self.engine = engine
        self.max_probes = max_probes
        self.selected_payloads: list[str] = []

    def select_next(
        self,
        observation: PayloadObservation,
        *,
        marker: str,
    ) -> ProbeDecision | None:
        """Select an untried payload, or stop when no budget/candidates remain."""
        if len(self.selected_payloads) >= self.max_probes:
            return None

        if not isinstance(observation, PayloadObservation):
            raise TypeError("observation must be a PayloadObservation")
        if not observation.reflected:
            return None
        if not isinstance(marker, str) or not marker:
            raise ValueError("marker must be non-empty text")

        candidates = self.engine.generate(
            marker=marker,
            context=observation.context,
        )
        attempted = set(self.selected_payloads)

        # Preserve the engine's evidence-based explanation while advancing
        # through its ordered candidates to find the next untried payload.
        first_decision = self.engine.select_next(observation, marker=marker)
        if first_decision is None:
            return None

        for payload in candidates:
            if payload in attempted:
                continue
            if payload == observation.observed_value:
                continue

            decision = ProbeDecision(
                payload=payload,
                hypothesis=first_decision.hypothesis,
                rationale=first_decision.rationale,
            )
            self.selected_payloads.append(payload)
            return decision

        return None

