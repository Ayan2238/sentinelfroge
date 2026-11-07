import pytest

from sentinelforge.modules.payload_engine import (
    AdaptivePayloadEngine,
    PayloadContext,
    ProbeSession,
)


@pytest.mark.parametrize(
    ("body", "marker", "expected"),
    [
        (
            "<p>sf-probe-71</p>",
            "sf-probe-71",
            PayloadContext.HTML_TEXT,
        ),
        (
            '<input value="sf-probe-71">',
            "sf-probe-71",
            PayloadContext.HTML_ATTRIBUTE,
        ),
        (
            '<script>const value = "sf-probe-71";</script>',
            "sf-probe-71",
            PayloadContext.UNKNOWN,
        ),
        (
            '{"value":"sf-probe-71"}',
            "sf-probe-71",
            PayloadContext.JSON,
        ),
    ],
)
def test_classifies_reflection_context(body, marker, expected):
    engine = AdaptivePayloadEngine()
    assert engine.classify_reflection(body, marker) == expected


def test_unreflected_marker_has_unknown_context():
    engine = AdaptivePayloadEngine()
    assert engine.classify_reflection(
        "<p>ordinary response</p>", "sf-probe-71"
    ) == PayloadContext.UNKNOWN


def test_generation_respects_candidate_and_size_limits():
    engine = AdaptivePayloadEngine(
        max_candidates=4,
        max_payload_bytes=128,
    )

    candidates = engine.generate(
        marker="sf-probe-71",
        context=PayloadContext.HTML_TEXT,
    )

    assert 1 <= len(candidates) <= 4
    assert all(isinstance(item, str) for item in candidates)
    assert all(len(item.encode("utf-8")) <= 128 for item in candidates)
    assert len(candidates) == len(set(candidates))


def test_generation_rejects_empty_marker():
    engine = AdaptivePayloadEngine()

    with pytest.raises(ValueError):
        engine.generate(marker="", context=PayloadContext.HTML_TEXT)


def test_marker_inside_html_comment_is_not_classified_as_html_text():
    engine = AdaptivePayloadEngine()
    assert engine.classify_reflection(
        "<!-- sf-probe-71 -->", "sf-probe-71"
    ) == PayloadContext.UNKNOWN


def test_observation_records_html_encoding():
    engine = AdaptivePayloadEngine()
    observation = engine.observe(
        body="<p>&lt;sf-probe-71&gt;</p>",
        marker="<sf-probe-71>",
    )

    assert observation.reflected is True
    assert observation.exact_match is False
    assert observation.transformation == "html_entity"
    assert observation.context == PayloadContext.HTML_TEXT


def test_observation_does_not_claim_missing_marker_was_reflected():
    engine = AdaptivePayloadEngine()
    observation = engine.observe(
        body="<p>ordinary response</p>",
        marker="sf-probe-71",
    )

    assert observation.reflected is False
    assert observation.context == PayloadContext.UNKNOWN


def test_adaptive_decision_explains_why_next_probe_was_selected():
    engine = AdaptivePayloadEngine()
    observation = engine.observe(
        body='<input value="sf-probe-71">',
        marker="sf-probe-71",
    )

    decision = engine.select_next(
        observation,
        marker="sf-probe-71",
    )

    assert decision is not None
    assert decision.payload
    assert decision.hypothesis
    assert decision.rationale
    assert "sf-probe-71" in decision.payload


def test_no_reflection_does_not_invent_a_contextual_decision():
    engine = AdaptivePayloadEngine()
    observation = engine.observe(
        body="ordinary response",
        marker="sf-probe-71",
    )

    assert engine.select_next(
        observation,
        marker="sf-probe-71",
    ) is None


def test_probe_session_does_not_select_the_same_payload_twice():
    engine = AdaptivePayloadEngine()
    session = ProbeSession(engine, max_probes=5)
    observation = engine.observe(
        body="<p><sf-probe-71></p>",
        marker="<sf-probe-71>",
    )

    first = session.select_next(observation, marker="<sf-probe-71>")
    second = session.select_next(observation, marker="<sf-probe-71>")

    assert first is not None
    assert second is not None
    assert first.payload != second.payload
    assert len(session.selected_payloads) == 2


def test_probe_session_stops_at_selection_budget():
    engine = AdaptivePayloadEngine()
    session = ProbeSession(engine, max_probes=1)
    observation = engine.observe(
        body="<p><sf-probe-71></p>",
        marker="<sf-probe-71>",
    )

    first = session.select_next(observation, marker="<sf-probe-71>")
    second = session.select_next(observation, marker="<sf-probe-71>")

    assert first is not None
    assert second is None
    assert len(session.selected_payloads) == 1


def test_probe_session_rejects_invalid_budget():
    engine = AdaptivePayloadEngine()

    with pytest.raises(ValueError):
        ProbeSession(engine, max_probes=0)


@pytest.mark.parametrize(
    "body",
    [
        "<!-- sf-probe-71 -->",
        '<script>const note = "<p>sf-probe-71</p>";</script>',
        '<textarea><p>sf-probe-71</p></textarea>',
    ],
)
def test_classifier_is_conservative_for_non_html_text_contexts(body):
    engine = AdaptivePayloadEngine()
    assert engine.classify_reflection(
        body, "sf-probe-71"
    ) == PayloadContext.UNKNOWN


def test_probe_session_does_not_select_when_reflection_is_absent():
    engine = AdaptivePayloadEngine()
    session = ProbeSession(engine, max_probes=3)
    observation = engine.observe(
        body="ordinary response",
        marker="sf-probe-71",
    )

    assert session.select_next(
        observation, marker="sf-probe-71"
    ) is None
    assert session.selected_payloads == []
