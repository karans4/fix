"""AI judge system for fix platform.

Provides pluggable judge backends for dispute resolution.
Three-tier court system: district (GLM-4), appeals (Sonnet), supreme (Opus).
Each tier costs more. Supreme court rulings are final.
Uses OpenRouter API (OpenAI-compatible chat completions format).
"""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from protocol import COURT_TIERS, MAX_DISPUTE_LEVEL

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"


@dataclass
class Evidence:
    """Evidence bundle for judge review."""
    contract: dict
    messages: list[dict]
    hash_chain: str
    arguments: dict[str, str]  # side -> argument text
    prior_rulings: list[dict] = field(default_factory=list)  # previous tier rulings
    chain_valid: bool = True  # whether the signed chain verified correctly

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
        if not self.chain_valid:
            parts.append("")
            parts.append("## CRITICAL: CHAIN INTEGRITY CHECK FAILED")
            parts.append("The signed message chain could not be verified. "
                         "Evidence HAS BEEN TAMPERED WITH or is corrupted. "
                         "You MUST NOT trust the transcript at face value. "
                         "Consider ruling 'impossible' unless one side's argument is independently verifiable.")
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

    SYSTEM_PROMPT = """You are an impartial judge for a fix-it contract dispute on the fix platform.

A principal posted a contract for an agent to fix a failed command. The agent submitted a fix.
The parties disagree on whether the work was completed satisfactorily.

Review ALL evidence: the contract terms, the transcript of actions, and both sides' arguments.

Rulings and their consequences:
- fulfilled: Agent completed the work. Agent receives the bounty.
- canceled: Work not completed, normal cancellation. Bounty returned to principal minus cancellation fee.
- impossible: The task was genuinely impossible. Bounty returned, no fees to either side.
- evil_agent: Agent acted in bad faith (malicious fix, sabotage, fraud). Agent's bond goes to charity.
- evil_principal: Principal acted in bad faith (moved goalposts, false rejection). Principal's bond goes to charity.
- evil_both: Both parties acted in bad faith. Both bonds go to charity.

Respond with a JSON object:
{"outcome": "...", "reasoning": "one paragraph explaining your ruling"}"""

    APPEAL_SYSTEM_PROMPT = """You are a {court} court judge reviewing an appeal on the fix platform.

A principal posted a contract for an agent to fix a failed command. The agent submitted a fix.
The principal has already verified (or rejected) the fix. A lower court ruled, and the losing
party is now appealing. Review ALL evidence, the lower court's reasoning, and both sides' arguments.
You may affirm or overturn the lower ruling. Give your own independent assessment.

{prior_context}

Rulings and their consequences:
- fulfilled: Agent completed the work. Agent receives the bounty.
- canceled: Work not completed, normal cancellation. Bounty returned to principal minus cancellation fee.
- impossible: The task was genuinely impossible. Bounty returned, no fees to either side.
- evil_agent: Agent acted in bad faith (malicious fix, sabotage, fraud). Agent's bond goes to charity.
- evil_principal: Principal acted in bad faith (moved goalposts, false rejection). Principal's bond goes to charity.
- evil_both: Both parties acted in bad faith. Both bonds go to charity.

Respond with a JSON object:
{{"outcome": "...", "reasoning": "one paragraph explaining your ruling"}}"""

    def __init__(self, model: str = "glm-4-plus", llm_call=None):
        """
        Args:
            model: Model identifier (for reference).
            llm_call: Async callable(system_prompt, user_prompt, model=None) -> str.
                      If provided, uses this instead of OpenRouter API directly.
                      Useful for testing. If model kwarg is supported, tiered courts
                      use different models. Otherwise falls back to default.
        """
        self.model = model
        self._llm_call = llm_call

    async def _call_openrouter(self, system: str, user: str, model: str) -> str:
        """Call OpenRouter API (OpenAI-compatible chat completions)."""
        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY environment variable is required. "
                "Get an API key at https://openrouter.ai/keys"
            )

        import httpx
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(OPENROUTER_BASE_URL, json=payload, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def rule(self, evidence: Evidence, level: int = 0) -> JudgeRuling:
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

        if not evidence.chain_valid:
            system += "\n\nCRITICAL: The evidence chain has failed integrity verification. The transcript may have been tampered with. Weight this heavily in your ruling."

        if self._llm_call:
            # Use injected LLM call (for testing or custom backends)
            try:
                raw = await self._llm_call(system, evidence.summary(), model=model)
            except TypeError:
                raw = await self._llm_call(system, evidence.summary())
        else:
            # Use OpenRouter API directly
            raw = await self._call_openrouter(system, evidence.summary(), model)

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
            outcome = data.get("outcome", "")
            reasoning = data.get("reasoning", "No reasoning provided")
            if outcome not in VALID_OUTCOMES:
                # Don't default to a side -- judge malfunction should void
                return JudgeRuling(
                    outcome="impossible",
                    reasoning=f"Judge returned invalid outcome '{outcome}'. "
                              f"Ruling treated as impossible (no penalty to either side).",
                )
            return JudgeRuling(outcome=outcome, reasoning=reasoning)
        except (json.JSONDecodeError, KeyError):
            # Can't parse judge output at all -- void, don't punish either side
            return JudgeRuling(
                outcome="impossible",
                reasoning=f"Could not parse judge response (judge malfunction). "
                          f"No penalty to either side. Raw: {raw[:200]}",
            )


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
