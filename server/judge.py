"""AI judge system for fix platform.

Provides pluggable judge backends for dispute resolution.
Three-tier court system: district (Haiku), appeals (Sonnet), supreme (Opus).
Each tier costs more. Supreme court rulings are final.
"""

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from protocol import COURT_TIERS, MAX_DISPUTE_LEVEL


@dataclass
class Evidence:
    """Evidence bundle for judge review."""
    contract: dict
    messages: list[dict]
    hash_chain: str
    arguments: dict[str, str]  # side -> argument text
    prior_rulings: list[dict] = field(default_factory=list)  # previous tier rulings

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
        if self.prior_rulings:
            parts.append("")
            parts.append("## Prior Rulings (lower courts)")
            for r in self.prior_rulings:
                parts.append(f"### {r.get('court', '?')} court")
                parts.append(f"Outcome: {r.get('outcome', '?')}")
                parts.append(f"Reasoning: {r.get('reasoning', '?')}")
                if r.get("appeal_argument"):
                    parts.append(f"Appeal argument: {r['appeal_argument']}")
        return "\n".join(parts)


VALID_OUTCOMES = {"fulfilled", "canceled", "impossible", "evil_agent", "evil_principal", "evil_both"}


@dataclass
class JudgeRuling:
    """Structured ruling from a judge."""
    outcome: str  # one of VALID_OUTCOMES
    reasoning: str
    court: str = ""  # "district", "appeals", "supreme"
    level: int = 0  # 0, 1, 2
    final: bool = False  # True if supreme court (no further appeal)
    flags: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.outcome not in VALID_OUTCOMES:
            raise ValueError(f"Invalid outcome: {self.outcome}")
        if not self.flags:
            if self.outcome == "evil_agent":
                self.flags = ["evil_agent"]
            elif self.outcome == "evil_principal":
                self.flags = ["evil_principal"]
            elif self.outcome == "evil_both":
                self.flags = ["evil_agent", "evil_principal"]

    def to_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "reasoning": self.reasoning,
            "court": self.court,
            "level": self.level,
            "final": self.final,
            "flags": self.flags,
        }


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

    APPEAL_SYSTEM_PROMPT = """You are a {court} court judge reviewing an appeal of a lower court ruling.
The losing party is appealing. Review ALL evidence and the lower court's reasoning.
You may affirm or overturn the lower ruling. Give your own independent assessment.

{prior_context}

Possible rulings:
- fulfilled: The agent completed the work satisfactorily.
- canceled: The work was not completed, normal cancellation.
- impossible: The task was genuinely impossible to complete.
- evil_agent: The agent acted in bad faith (malicious fix, sabotage, etc.)
- evil_principal: The principal acted in bad faith (moved goalposts, false rejection, etc.)
- evil_both: Both parties acted in bad faith.

Respond with a JSON object:
{{"outcome": "...", "reasoning": "one paragraph explaining your ruling"}}"""

    def __init__(self, model: str = "claude-haiku-4-5-20251001", llm_call=None):
        """
        Args:
            model: Model identifier (for reference).
            llm_call: Async callable(system_prompt, user_prompt, model=None) -> str.
                      Must be injected. If model kwarg is supported, tiered courts
                      use different models. Otherwise falls back to default.
        """
        self.model = model
        self._llm_call = llm_call

    async def rule(self, evidence: Evidence, level: int = 0) -> JudgeRuling:
        if not self._llm_call:
            raise RuntimeError("AIJudge requires an llm_call function")

        tier = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]
        model = tier["model"]
        court_name = tier["name"]

        # Build prompt based on whether this is an appeal
        if level == 0:
            system = self.SYSTEM_PROMPT
        else:
            prior_context = ""
            if evidence.prior_rulings:
                lines = []
                for r in evidence.prior_rulings:
                    lines.append(f"The {r.get('court', 'lower')} court ruled: {r.get('outcome', '?')}")
                    lines.append(f"Reasoning: {r.get('reasoning', '?')}")
                prior_context = "\n".join(lines)
            system = self.APPEAL_SYSTEM_PROMPT.format(
                court=court_name,
                prior_context=prior_context,
            )

        # Try passing model to llm_call; fall back if it doesn't accept it
        try:
            raw = await self._llm_call(system, evidence.summary(), model=model)
        except TypeError:
            raw = await self._llm_call(system, evidence.summary())

        ruling = self._parse_ruling(raw)
        ruling.court = court_name
        ruling.level = level
        ruling.final = (level >= MAX_DISPUTE_LEVEL)
        return ruling

    @staticmethod
    def _parse_ruling(raw: str) -> JudgeRuling:
        """Parse LLM response into a JudgeRuling."""
        text = raw.strip()
        if "```" in text:
            import re
            m = re.search(r'```(?:json)?\s*\n?({.*?})\s*\n?```', text, re.DOTALL)
            if m:
                text = m.group(1)
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


class TieredCourt:
    """Three-tier court system: district -> appeals -> supreme.

    Wraps an AIJudge and manages escalation. Each level uses a bigger model.
    The losing party can appeal to the next level. Supreme is final.
    """

    def __init__(self, llm_call=None):
        """
        Args:
            llm_call: Async callable(system_prompt, user_prompt, model=None) -> str.
        """
        self.judge = AIJudge(llm_call=llm_call)

    async def rule(self, evidence: Evidence, level: int = 0) -> JudgeRuling:
        """Rule at the given tier level."""
        return await self.judge.rule(evidence, level=level)

    @staticmethod
    def fee_for_level(level: int) -> str:
        """Get the judge fee for a dispute level."""
        tier = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]
        return tier["fee"]

    @staticmethod
    def court_name(level: int) -> str:
        tier = COURT_TIERS[min(level, MAX_DISPUTE_LEVEL)]
        return tier["name"]

    @staticmethod
    def can_appeal(level: int) -> bool:
        return level < MAX_DISPUTE_LEVEL


class PanelJudge(JudgeBackend):
    """Panel of N judges -- majority vote wins."""

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

        votes: dict[str, int] = {}
        rulings: list[JudgeRuling] = []
        for r in results:
            if isinstance(r, JudgeRuling):
                votes[r.outcome] = votes.get(r.outcome, 0) + 1
                rulings.append(r)

        if not rulings:
            return JudgeRuling(outcome="canceled", reasoning="All judges failed")

        winner = max(votes, key=votes.get)
        count = votes[winner]
        total = len(rulings)

        winning_ruling = next(r for r in rulings if r.outcome == winner)
        return JudgeRuling(
            outcome=winner,
            reasoning=f"Panel vote: {count}/{total} for {winner}. {winning_ruling.reasoning}",
            flags=winning_ruling.flags,
        )
