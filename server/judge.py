"""AI judge system for fix platform.

Provides pluggable judge backends for dispute resolution.
Default: AIJudge (LLM-based). Also: PanelJudge (majority vote).
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Evidence:
    """Evidence bundle for judge review."""
    contract: dict
    messages: list[dict]
    hash_chain: str
    arguments: dict[str, str]  # side -> argument text

    def summary(self) -> str:
        """Human-readable summary for LLM prompt."""
        parts = [
            "## Contract",
            json.dumps(self.contract, indent=2),
            "",
            "## Transcript",
        ]
        for msg in self.messages:
            parts.append(json.dumps(msg, separators=(",", ":")))
        parts.append("")
        parts.append(f"## Hash Chain: {self.hash_chain}")
        parts.append("")
        parts.append("## Arguments")
        for side, text in self.arguments.items():
            parts.append(f"### {side}")
            parts.append(text)
        return "\n".join(parts)


VALID_OUTCOMES = {"fulfilled", "canceled", "impossible", "evil_agent", "evil_principal", "evil_both"}


@dataclass
class JudgeRuling:
    """Structured ruling from a judge."""
    outcome: str  # one of VALID_OUTCOMES
    reasoning: str
    flags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError(f"Invalid outcome: {self.outcome}")
        # Derive flags from outcome
        if not self.flags:
            if self.outcome == "evil_agent":
                self.flags = ["evil_agent"]
            elif self.outcome == "evil_principal":
                self.flags = ["evil_principal"]
            elif self.outcome == "evil_both":
                self.flags = ["evil_agent", "evil_principal"]


class JudgeBackend(ABC):
    """Abstract base for judge implementations."""

    @abstractmethod
    async def rule(self, evidence: Evidence) -> JudgeRuling:
        ...


class AIJudge(JudgeBackend):
    """LLM-based judge. Sends evidence to an LLM and parses structured ruling."""

    SYSTEM_PROMPT = """You are an impartial judge for a fix-it contract dispute.
Review the evidence and rule on the outcome.

Possible rulings:
- fulfilled: The agent completed the work satisfactorily.
- canceled: The work was not completed, normal cancellation.
- impossible: The task was genuinely impossible to complete.
- evil_agent: The agent acted in bad faith (malicious fix, sabotage, etc.)
- evil_principal: The principal acted in bad faith (moved goalposts, false rejection, etc.)
- evil_both: Both parties acted in bad faith.

Respond with a JSON object:
{"outcome": "...", "reasoning": "one paragraph explaining your ruling"}"""

    def __init__(self, model: str = "claude-sonnet-4-6", llm_call=None):
        """
        Args:
            model: Model identifier (for reference).
            llm_call: Async callable(system_prompt, user_prompt) -> str.
                      Must be injected. No default LLM client built in.
        """
        self.model = model
        self._llm_call = llm_call

    async def rule(self, evidence: Evidence) -> JudgeRuling:
        if not self._llm_call:
            raise RuntimeError("AIJudge requires an llm_call function")

        raw = await self._llm_call(self.SYSTEM_PROMPT, evidence.summary())
        return self._parse_ruling(raw)

    @staticmethod
    def _parse_ruling(raw: str) -> JudgeRuling:
        """Parse LLM response into a JudgeRuling."""
        text = raw.strip()
        # Try to extract JSON from markdown code blocks
        if "```" in text:
            import re
            m = re.search(r'```(?:json)?\s*\n?({.*?})\s*\n?```', text, re.DOTALL)
            if m:
                text = m.group(1)
        # Try to find bare JSON
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]
        try:
            data = json.loads(text)
            outcome = data.get("outcome", "canceled")
            reasoning = data.get("reasoning", "No reasoning provided")
            if outcome not in VALID_OUTCOMES:
                outcome = "canceled"
            return JudgeRuling(outcome=outcome, reasoning=reasoning)
        except (json.JSONDecodeError, KeyError):
            return JudgeRuling(outcome="canceled", reasoning=f"Could not parse judge response: {raw[:200]}")


class PanelJudge(JudgeBackend):
    """Panel of N judges — majority vote wins."""

    def __init__(self, judges: list[JudgeBackend]):
        if len(judges) < 2:
            raise ValueError("PanelJudge needs at least 2 judges")
        self.judges = judges

    async def rule(self, evidence: Evidence) -> JudgeRuling:
        import asyncio
        results = await asyncio.gather(
            *(j.rule(evidence) for j in self.judges),
            return_exceptions=True,
        )

        # Count votes, skip exceptions
        votes: dict[str, int] = {}
        rulings: list[JudgeRuling] = []
        for r in results:
            if isinstance(r, JudgeRuling):
                votes[r.outcome] = votes.get(r.outcome, 0) + 1
                rulings.append(r)

        if not rulings:
            return JudgeRuling(outcome="canceled", reasoning="All judges failed")

        # Find majority
        winner = max(votes, key=votes.get)
        count = votes[winner]
        total = len(rulings)

        # Use the first ruling with the winning outcome for reasoning
        winning_ruling = next(r for r in rulings if r.outcome == winner)
        return JudgeRuling(
            outcome=winner,
            reasoning=f"Panel vote: {count}/{total} for {winner}. {winning_ruling.reasoning}",
            flags=winning_ruling.flags,
        )
