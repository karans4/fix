import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock

from server.judge import Evidence, JudgeRuling, VALID_OUTCOMES, AIJudge, PanelJudge


# --- Fixtures ---

def make_evidence(**overrides):
    defaults = dict(
        contract={"task": "fix the widget", "price": 100},
        messages=[{"role": "agent", "text": "done"}],
        hash_chain="abc123",
        arguments={"agent": "I fixed it", "principal": "No you didn't"},
    )
    defaults.update(overrides)
    return Evidence(**defaults)


# --- Evidence ---

class TestEvidence:
    def test_summary_contains_contract(self):
        ev = make_evidence()
        s = ev.summary()
        assert "## Contract" in s
        assert '"fix the widget"' in s

    def test_summary_contains_transcript(self):
        ev = make_evidence()
        s = ev.summary()
        assert "## Transcript" in s
        assert '"agent"' in s

    def test_summary_contains_hash_chain(self):
        ev = make_evidence()
        assert "## Hash Chain: abc123" in ev.summary()

    def test_summary_contains_arguments(self):
        ev = make_evidence()
        s = ev.summary()
        assert "### agent" in s
        assert "I fixed it" in s
        assert "### principal" in s


# --- JudgeRuling ---

class TestJudgeRuling:
    def test_valid_outcomes_accepted(self):
        for outcome in VALID_OUTCOMES:
            r = JudgeRuling(outcome=outcome, reasoning="ok")
            assert r.outcome == outcome

    def test_invalid_outcome_raises(self):
        with pytest.raises(ValueError, match="Invalid outcome"):
            JudgeRuling(outcome="bogus", reasoning="nope")

    def test_flag_derivation_evil_agent(self):
        r = JudgeRuling(outcome="evil_agent", reasoning="bad")
        assert r.flags == ["evil_agent"]

    def test_flag_derivation_evil_principal(self):
        r = JudgeRuling(outcome="evil_principal", reasoning="bad")
        assert r.flags == ["evil_principal"]

    def test_flag_derivation_evil_both(self):
        r = JudgeRuling(outcome="evil_both", reasoning="bad")
        assert sorted(r.flags) == ["evil_agent", "evil_principal"]

    def test_flag_derivation_fulfilled_empty(self):
        r = JudgeRuling(outcome="fulfilled", reasoning="good")
        assert r.flags == []

    def test_explicit_flags_not_overwritten(self):
        r = JudgeRuling(outcome="evil_agent", reasoning="bad", flags=["custom"])
        assert r.flags == ["custom"]


# --- AIJudge._parse_ruling ---

class TestParseRuling:
    def test_valid_json(self):
        raw = '{"outcome": "fulfilled", "reasoning": "Good job"}'
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "fulfilled"
        assert r.reasoning == "Good job"

    def test_json_in_code_block(self):
        raw = 'Here is my ruling:\n```json\n{"outcome": "canceled", "reasoning": "Not done"}\n```'
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "canceled"
        assert r.reasoning == "Not done"

    def test_json_in_bare_code_block(self):
        raw = '```\n{"outcome": "impossible", "reasoning": "Can\'t do"}\n```'
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "impossible"

    def test_bare_json_with_surrounding_text(self):
        raw = 'After careful review, {"outcome": "evil_agent", "reasoning": "Sabotage"} is my ruling.'
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "evil_agent"
        assert r.reasoning == "Sabotage"

    def test_invalid_json_returns_impossible(self):
        """Parse failure -> impossible (no penalty to either side), not canceled."""
        raw = "I have no idea what format you want"
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "impossible"
        assert "Could not parse" in r.reasoning

    def test_invalid_outcome_in_json_defaults_to_impossible(self):
        """Invalid outcome -> impossible (judge malfunction), not canceled."""
        raw = '{"outcome": "maybe", "reasoning": "unsure"}'
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "impossible"

    def test_missing_fields_returns_impossible(self):
        """Empty JSON -> impossible (no valid outcome), not canceled."""
        raw = "{}"
        r = AIJudge._parse_ruling(raw)
        assert r.outcome == "impossible"


# --- AIJudge.rule ---

class TestAIJudgeRule:
    @pytest.mark.asyncio
    async def test_rule_with_mock_llm(self):
        mock_llm = AsyncMock(return_value='{"outcome": "fulfilled", "reasoning": "All good"}')
        judge = AIJudge(llm_call=mock_llm)
        ev = make_evidence()
        ruling = await judge.rule(ev)
        assert ruling.outcome == "fulfilled"
        assert ruling.reasoning == "All good"
        mock_llm.assert_awaited_once()
        # Verify evidence summary was passed as second arg
        call_args = mock_llm.call_args
        assert call_args[0][0] == AIJudge.SYSTEM_PROMPT
        assert "## Contract" in call_args[0][1]

    @pytest.mark.asyncio
    async def test_rule_without_llm_or_api_key_raises(self):
        """Without llm_call and without OPENROUTER_API_KEY, raises about missing key."""
        judge = AIJudge()
        ev = make_evidence()
        with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
            await judge.rule(ev)


# --- PanelJudge ---

class TestPanelJudge:
    @pytest.mark.asyncio
    async def test_majority_vote(self):
        """3 judges, 2 say fulfilled, 1 says canceled -> fulfilled wins."""
        async def make_judge(outcome):
            mock = AsyncMock(return_value='{"outcome": "' + outcome + '", "reasoning": "reason"}')
            return AIJudge(llm_call=mock)

        j1 = await make_judge("fulfilled")
        j2 = await make_judge("fulfilled")
        j3 = await make_judge("canceled")
        panel = PanelJudge([j1, j2, j3])
        ev = make_evidence()
        ruling = await panel.rule(ev)
        assert ruling.outcome == "fulfilled"
        assert "2/3" in ruling.reasoning

    @pytest.mark.asyncio
    async def test_all_judges_fail_returns_impossible(self):
        """If every judge raises, return impossible (no penalty to either side)."""
        class FailJudge(AIJudge):
            async def rule(self, evidence):
                raise RuntimeError("kaboom")

        panel = PanelJudge([FailJudge(), FailJudge()])
        ev = make_evidence()
        ruling = await panel.rule(ev)
        assert ruling.outcome == "impossible"
        assert "All judges failed" in ruling.reasoning

    def test_requires_at_least_two_judges(self):
        mock = AsyncMock()
        with pytest.raises(ValueError, match="at least 2"):
            PanelJudge([AIJudge(llm_call=mock)])
