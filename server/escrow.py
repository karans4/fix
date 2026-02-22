"""Escrow management for fix platform — inclusive bond model.

Both sides deposit the same amount: bounty + judge_fee (the "inclusive bond").
Total in escrow: 2 * (bounty + judge_fee).

Payment routing on resolution:
- Platform fee: 10% of bounty on all completed contracts where an agent bonded.
- Cancel fee: 20% of bounty, split 10% to counterparty + 10% to platform.
- Judge tier fees: paid from loser's judge_fee portion.
- Evil rulings: loser's bounty portion (excess bond) goes to charity.
  Judge_fee minus tier_fee is ALWAYS returned (insurance, not punishment).
"""

import sqlite3
import json
import threading
from decimal import Decimal
from pathlib import Path

from protocol import (
    DEFAULT_JUDGE_FEE, GRACE_PERIOD_SECONDS, PLATFORM_FEE_RATE,
    PLATFORM_FEE_MIN, CANCEL_FEE_RATE, Ruling,
)
from server.nano import validate_nano_address


class Escrow:
    """Payment routing logic for a single contract (inclusive bond model).

    Both sides pay inclusive_bond = bounty + judge_fee.
    Bounty is the "excess bond" — the real stake beyond dispute insurance.
    """

    def __init__(self, bounty: str, terms: dict):
        self.bounty = Decimal(bounty)
        self.terms = terms
        self.judge_fee = Decimal(terms.get("judge_fee", DEFAULT_JUDGE_FEE))
        self.inclusive_bond = self.bounty + self.judge_fee
        self.locked = False
        self.resolved = False
        self.resolution: dict | None = None
        self.principal_locked = False
        self.agent_locked = False

    def lock(self) -> dict:
        """Lock escrow — principal deposits inclusive_bond."""
        self.locked = True
        self.principal_locked = True
        return {
            "status": "locked",
            "bounty": str(self.bounty),
            "judge_fee": str(self.judge_fee),
            "inclusive_bond": str(self.inclusive_bond),
        }

    def lock_agent(self) -> dict:
        """Lock agent's matching deposit (inclusive_bond)."""
        self.agent_locked = True
        return {
            "status": "agent_locked",
            "inclusive_bond": str(self.inclusive_bond),
        }

    def release_agent(self) -> dict:
        """Return agent's deposit if they decline after investigating."""
        self.agent_locked = False
        return {
            "status": "agent_released",
            "inclusive_bond": str(self.inclusive_bond),
        }

    def resolve(self, ruling: str, flags: list[str] | None = None,
                in_grace: bool = False, backed_out_by: str | None = None,
                dispute_loser: str | None = None,
                tier_fee: Decimal | None = None) -> dict:
        """Route funds based on ruling under the inclusive bond model.

        Returns a dict describing all payment actions.
        """
        flags = set(flags or [])
        bounty = self.bounty
        judge_fee = self.judge_fee

        if ruling == "voided":
            return self._void()

        # --- Compute base result ---
        result = {}
        has_evil = bool(flags & {"evil_agent", "evil_principal"})

        if ruling == "fulfilled":
            result = self._base_fulfilled(flags)
        elif ruling == "canceled":
            result = self._base_canceled(flags)
        elif ruling == "impossible":
            result = self._base_impossible()
        elif ruling == "backed_out":
            result = self._base_backed_out(in_grace, backed_out_by)
        else:
            raise ValueError(f"unknown ruling: {ruling}")

        self.resolved = True
        self.resolution = result

        # --- Judge fee routing ---
        self._route_judge_fees(result, flags, dispute_loser, tier_fee)

        # --- Platform fee: 10% of excess bond (bounty - judge_fee) ---
        if result.get("action") != "grace_return":
            excess = max(bounty - judge_fee, Decimal("0"))
            fee = max(excess * PLATFORM_FEE_RATE, PLATFORM_FEE_MIN) if excess > 0 else Decimal("0")
            result["platform_fee"] = str(fee)
        else:
            result["platform_fee"] = "0"

        return result

    def _base_fulfilled(self, flags: set) -> dict:
        """Fulfilled: agent gets principal's bounty."""
        if "evil_principal" in flags:
            return {
                "action": "fulfilled_evil_principal",
                "agent_gets_bounty": str(self.bounty),
                "principal_bounty_to_charity": str(self.bounty),
                "details": "fulfilled but principal evil — principal's bounty to charity",
            }
        return {
            "action": "release_to_agent",
            "agent_gets_bounty": str(self.bounty),
            "details": "bounty released to agent",
        }

    def _base_canceled(self, flags: set) -> dict:
        """Canceled (dispute outcome): bounty back to principal."""
        if "evil_agent" in flags and "evil_principal" in flags:
            return {
                "action": "canceled_both_evil",
                "agent_bounty_to_charity": str(self.bounty),
                "principal_bounty_to_charity": str(self.bounty),
                "details": "both evil — both bounties to charity",
            }
        elif "evil_agent" in flags:
            return {
                "action": "canceled_evil_agent",
                "principal_gets_bounty": str(self.bounty),
                "agent_bounty_to_charity": str(self.bounty),
                "details": "agent evil — agent's bounty to charity, principal's returned",
            }
        elif "evil_principal" in flags:
            return {
                "action": "canceled_evil_principal",
                "principal_bounty_to_charity": str(self.bounty),
                "details": "principal evil on canceled — bounty to charity",
            }
        return {
            "action": "return_to_principal",
            "principal_gets_bounty": str(self.bounty),
            "details": "canceled, bounty returned to principal",
        }

    def _base_impossible(self) -> dict:
        """Impossible: bounty back to principal, no penalties."""
        return {
            "action": "return_to_principal",
            "principal_gets_bounty": str(self.bounty),
            "details": "contract ruled impossible, bounty returned",
        }

    def _base_backed_out(self, in_grace: bool, backed_out_by: str | None) -> dict:
        """Backed out: cancel fee logic."""
        bounty = self.bounty

        if in_grace:
            return {
                "action": "grace_return",
                "details": "backed out during grace period, no fees",
            }

        excess = max(bounty - self.judge_fee, Decimal("0"))
        cancel_fee = excess * CANCEL_FEE_RATE   # 20% of excess bond
        reimburse = cancel_fee / 2              # 10% to counterparty
        platform_cancel = cancel_fee / 2        # 10% to platform

        if backed_out_by == "agent":
            return {
                "action": "agent_canceled",
                "principal_gets_bounty": str(bounty),
                "principal_gets_reimburse": str(reimburse),
                "agent_gets_back": str(bounty - cancel_fee),
                "cancel_fee_to_platform": str(platform_cancel),
                "details": "agent backed out post-grace, 20% cancel fee on excess bond",
            }
        else:  # principal backed out
            return {
                "action": "principal_canceled",
                "principal_gets_back": str(bounty - cancel_fee),
                "agent_gets_bounty_back": str(bounty),
                "agent_gets_reimburse": str(reimburse),
                "cancel_fee_to_platform": str(platform_cancel),
                "details": "principal backed out post-grace, 20% cancel fee on excess bond",
            }

    def _void(self) -> dict:
        """Judge timeout. Everything returned."""
        self.resolved = True
        result = {
            "action": "voided",
            "bounty": str(self.bounty),
            "inclusive_bond": str(self.inclusive_bond),
            "details": "judge timeout, contract voided, all funds returned",
            "principal_returned": str(self.inclusive_bond) if self.principal_locked else None,
            "agent_returned": str(self.inclusive_bond) if self.agent_locked else None,
            "platform_fee": "0",
        }
        self.resolution = result
        return result

    def _route_judge_fees(self, result: dict, flags: set,
                          dispute_loser: str | None,
                          tier_fee: Decimal | None):
        """Route judge fees from both sides' judge_fee portions.

        Normal dispute: loser pays tier_fee to platform (platform runs the judge),
        loser gets (judge_fee - tier_fee) back.
        Evil: same — judge_fee is insurance, not punishment. Only excess bond is punished.
        No dispute: both get judge_fee back.
        """
        judge_fee = self.judge_fee

        if dispute_loser:
            actual_tier_fee = tier_fee if tier_fee is not None else judge_fee
            loser_remainder = max(judge_fee - actual_tier_fee, Decimal("0"))
            winner = "principal" if dispute_loser == "agent" else "agent"

            result["dispute_loser"] = dispute_loser
            result["tier_fee_to_platform"] = str(actual_tier_fee)
            result["loser_judge_fee_returned"] = str(loser_remainder)
            result["winner_judge_fee_returned"] = str(judge_fee)
            result["winner"] = winner

            # Evil: loser's bounty (excess bond) to charity
            # But judge_fee portion is always returned minus tier_fee
            has_evil = bool(flags & {"evil_agent", "evil_principal"})
            if has_evil:
                result["loser_bounty_to_charity"] = str(self.bounty)
            else:
                result["loser_bounty_to_charity"] = None

            # evil_both: winner's bounty also to charity
            if "evil_agent" in flags and "evil_principal" in flags:
                result["winner_bounty_to_charity"] = str(self.bounty)
                result["winner"] = None  # nobody "wins"
            else:
                result["winner_bounty_to_charity"] = None

        else:
            # No dispute — both judge fees returned
            result["dispute_loser"] = None
            result["tier_fee_to_platform"] = None
            result["loser_judge_fee_returned"] = None
            result["winner_judge_fee_returned"] = None
            result["winner"] = None
            result["loser_bounty_to_charity"] = None
            result["winner_bounty_to_charity"] = None

    # --- Convenience methods (backwards compat) ---

    def release_to_agent(self) -> dict:
        return self.resolve("fulfilled")

    def return_to_principal(self, reason: str = "canceled") -> dict:
        return self.resolve("canceled")

    def send_to_charity(self, reason: str = "") -> dict:
        result = {
            "action": "send_to_charity",
            "bounty": str(self.bounty),
            "charity_amount": str(self.bounty),
            "details": reason or "forced to charity",
            "platform_fee": "0",
        }
        self.resolved = True
        self.resolution = result
        return result


class EscrowManager:
    """SQLite-backed escrow manager with pluggable payment backend.

    Inclusive bond model: both sides deposit bounty + judge_fee.
    """

    def __init__(self, db_path: str = ":memory:", payment_backend=None, platform_account: str = ""):
        from protocol import PLATFORM_ADDRESS
        if payment_backend is None:
            raise ValueError("payment_backend is required (use NanoBackend)")
        self.payment = payment_backend
        self.platform_account = platform_account or PLATFORM_ADDRESS
        if self.platform_account:
            valid, err = validate_nano_address(self.platform_account)
            if not valid:
                raise ValueError(f"Invalid platform Nano address: {err}")
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS escrows (
                contract_id TEXT PRIMARY KEY,
                bounty TEXT NOT NULL,
                terms TEXT NOT NULL,
                locked INTEGER DEFAULT 0,
                resolved INTEGER DEFAULT 0,
                resolution TEXT,
                escrow_account TEXT,
                principal_account TEXT,
                agent_account TEXT,
                judge_fee TEXT,
                inclusive_bond TEXT,
                principal_locked INTEGER DEFAULT 0,
                agent_locked INTEGER DEFAULT 0
            )
        """)
        self.db.commit()

    def lock(self, contract_id: str, bounty: str, terms: dict,
             judge_fee: str = "") -> dict:
        """Lock escrow for a contract. Principal deposits inclusive_bond."""
        escrow = Escrow(bounty, terms)
        result = escrow.lock()

        account_info = self.payment.create_escrow_account(contract_id)
        escrow_account = account_info.get("account", "")

        actual_judge_fee = judge_fee or str(escrow.judge_fee)
        inclusive_bond = str(Decimal(bounty) + Decimal(actual_judge_fee))

        self.db.execute(
            "INSERT INTO escrows (contract_id, bounty, terms, locked, escrow_account, judge_fee, inclusive_bond, principal_locked) VALUES (?, ?, ?, 1, ?, ?, ?, 1)",
            (contract_id, bounty, json.dumps(terms), escrow_account, actual_judge_fee, inclusive_bond),
        )
        self.db.commit()

        result["escrow_account"] = escrow_account
        return result

    def lock_agent(self, contract_id: str) -> dict:
        """Lock agent's matching deposit (inclusive_bond) when they start investigating."""
        row = self.db.execute("SELECT judge_fee, inclusive_bond FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            raise ValueError(f"No escrow for contract {contract_id}")
        self.db.execute(
            "UPDATE escrows SET agent_locked = 1 WHERE contract_id = ?",
            (contract_id,),
        )
        self.db.commit()
        return {
            "status": "agent_locked",
            "inclusive_bond": row["inclusive_bond"],
            "judge_fee": row["judge_fee"],
        }

    def release_agent(self, contract_id: str) -> dict:
        """Return agent's deposit if they decline after investigating."""
        row = self.db.execute("SELECT inclusive_bond FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            raise ValueError(f"No escrow for contract {contract_id}")
        self.db.execute(
            "UPDATE escrows SET agent_locked = 0 WHERE contract_id = ?",
            (contract_id,),
        )
        self.db.commit()
        return {"status": "agent_released", "inclusive_bond": row["inclusive_bond"]}

    def set_accounts(self, contract_id: str, principal_account: str = "",
                     agent_account: str = "") -> bool:
        """Set participant Nano addresses for a contract."""
        with self._lock:
            row = self.db.execute(
                "SELECT resolved FROM escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                return False
            if row["resolved"]:
                return False

            if principal_account:
                valid, err = validate_nano_address(principal_account)
                if not valid:
                    raise ValueError(f"Invalid principal Nano address: {err}")
            if agent_account:
                valid, err = validate_nano_address(agent_account)
                if not valid:
                    raise ValueError(f"Invalid agent Nano address: {err}")

            updates = []
            params = []
            if principal_account:
                updates.append("principal_account = ?")
                params.append(principal_account)
            if agent_account:
                updates.append("agent_account = ?")
                params.append(agent_account)
            if not updates:
                return False
            params.append(contract_id)
            cursor = self.db.execute(
                f"UPDATE escrows SET {', '.join(updates)} WHERE contract_id = ? AND resolved = 0",
                params,
            )
            self.db.commit()
            return cursor.rowcount > 0

    def check_deposit(self, contract_id: str) -> bool:
        """Check if escrow deposit has been received (inclusive_bond amount)."""
        row = self.db.execute("SELECT inclusive_bond FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            return False
        return self.payment.check_deposit(contract_id, row["inclusive_bond"])

    def resolve(self, contract_id: str, ruling: str, flags: list[str] | None = None,
                dispute_loser: str | None = None, tier_fee: str | None = None,
                **kwargs) -> dict:
        """Resolve escrow. Routes funds via payment backend.

        Inclusive bond model: each side deposited bounty + judge_fee.
        Resolution routes bounty portions and judge_fee portions separately.
        """
        with self._lock:
            row = self.db.execute("SELECT * FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
            if not row:
                raise ValueError(f"No escrow for contract {contract_id}")

            if row["resolved"]:
                return json.loads(row["resolution"]) if row["resolution"] else {"error": "already resolved"}

            if not row["locked"]:
                raise ValueError(f"Escrow for {contract_id} was never locked")

            terms = json.loads(row["terms"])
            escrow = Escrow(row["bounty"], terms)
            escrow.locked = bool(row["locked"])
            escrow.principal_locked = bool(row["principal_locked"])
            escrow.agent_locked = bool(row["agent_locked"])

            tier_fee_dec = Decimal(tier_fee) if tier_fee else None

            result = escrow.resolve(
                ruling, flags=flags,
                dispute_loser=dispute_loser,
                tier_fee=tier_fee_dec,
                **kwargs,
            )

            bounty = Decimal(row["bounty"])
            judge_fee = Decimal(row["judge_fee"] or DEFAULT_JUDGE_FEE)
            inclusive_bond = bounty + judge_fee
            platform_fee = Decimal(result.get("platform_fee", "0"))
            action = result.get("action")

            # --- Build payment list ---
            pending_payments = []

            if action == "voided":
                # Everything returned
                if row["principal_locked"] and row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(inclusive_bond), "principal_full_return"))
                if row["agent_locked"] and row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(inclusive_bond), "agent_full_return"))

            elif action == "grace_return":
                # Grace period: everything returned, no fees
                if row["principal_locked"] and row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(inclusive_bond), "principal_grace_return"))
                if row["agent_locked"] and row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(inclusive_bond), "agent_grace_return"))

            elif action == "release_to_agent":
                # Agent gets: principal's bounty - platform_fee + their own inclusive_bond back
                agent_payout = bounty - platform_fee + inclusive_bond
                if row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(agent_payout), "agent_payout"))
                # Principal gets: their judge_fee back
                if row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(judge_fee), "principal_judge_fee_return"))
                # Platform fee
                if self.platform_account and platform_fee > 0:
                    pending_payments.append((self.platform_account, str(platform_fee), "platform_fee"))
                # Handle dispute judge routing if present
                self._add_dispute_payments(pending_payments, result, row, bounty, judge_fee, inclusive_bond)

            elif action == "return_to_principal":
                # Principal gets: their bounty back - platform_fee + judge_fee
                principal_payout = bounty - platform_fee + judge_fee
                if row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(principal_payout), "principal_payout"))
                # Agent gets: their inclusive_bond back
                if row["agent_locked"] and row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(inclusive_bond), "agent_bond_return"))
                # Platform fee
                if self.platform_account and platform_fee > 0:
                    pending_payments.append((self.platform_account, str(platform_fee), "platform_fee"))
                # Handle dispute judge routing if present
                self._add_dispute_payments(pending_payments, result, row, bounty, judge_fee, inclusive_bond)

            elif action == "agent_canceled":
                # Agent backed out post-grace
                excess = max(bounty - judge_fee, Decimal("0"))
                cancel_fee = excess * CANCEL_FEE_RATE
                reimburse = cancel_fee / 2
                platform_cancel = cancel_fee / 2
                total_platform = platform_fee + platform_cancel

                # Principal gets: their bounty back - platform_fee + reimburse + judge_fee
                principal_payout = bounty - platform_fee + reimburse + judge_fee
                if row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(principal_payout), "principal_payout"))
                # Agent gets: their bounty - cancel_fee + judge_fee
                agent_payout = bounty - cancel_fee + judge_fee
                if row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(agent_payout), "agent_payout"))
                # Platform gets: posting fee + cancel platform share
                if self.platform_account and total_platform > 0:
                    pending_payments.append((self.platform_account, str(total_platform), "platform_fee"))

            elif action == "principal_canceled":
                # Principal backed out post-grace
                excess = max(bounty - judge_fee, Decimal("0"))
                cancel_fee = excess * CANCEL_FEE_RATE
                reimburse = cancel_fee / 2
                platform_cancel = cancel_fee / 2
                total_platform = platform_fee + platform_cancel

                # Principal gets: their bounty - platform_fee - cancel_fee + judge_fee
                principal_payout = bounty - platform_fee - cancel_fee + judge_fee
                if row["principal_account"]:
                    pending_payments.append((row["principal_account"], str(principal_payout), "principal_payout"))
                # Agent gets: their inclusive_bond back + reimburse
                agent_payout = inclusive_bond + reimburse
                if row["agent_account"]:
                    pending_payments.append((row["agent_account"], str(agent_payout), "agent_payout"))
                # Platform
                if self.platform_account and total_platform > 0:
                    pending_payments.append((self.platform_account, str(total_platform), "platform_fee"))

            elif action in ("fulfilled_evil_principal", "canceled_evil_agent",
                            "canceled_evil_principal", "canceled_both_evil"):
                self._route_evil_payments(pending_payments, result, row, bounty, judge_fee,
                                          inclusive_bond, platform_fee, action)

            elif action == "send_to_charity":
                if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                    pending_payments.append((self.payment.charity_account, str(bounty), "charity"))

            result["inclusive_bond"] = str(inclusive_bond)

            # Execute payments
            prior_resolution = json.loads(row["resolution"]) if row["resolution"] else {}
            completed_labels = set()
            if prior_resolution.get("completed_payments"):
                completed_labels = {p[0] if isinstance(p, (list, tuple)) else p
                                    for p in prior_resolution["completed_payments"]}

            block_hashes = list(prior_resolution.get("completed_payments", []))
            try:
                for to_account, amount, label in pending_payments:
                    if label in completed_labels:
                        continue
                    if Decimal(amount) <= 0:
                        continue
                    bh = self.payment.send(contract_id, to_account, amount)
                    block_hashes.append((label, bh))
            except Exception as e:
                result["payment_error"] = str(e)
                result["payment_failed"] = True
                result["completed_payments"] = block_hashes
                self.db.execute(
                    "UPDATE escrows SET resolved = 1, resolution = ? WHERE contract_id = ?",
                    (json.dumps(result), contract_id),
                )
                self.db.commit()
                return result

            if block_hashes:
                result["block_hashes"] = {label: bh for label, bh in block_hashes}

            self.db.execute(
                "UPDATE escrows SET resolved = 1, resolution = ? WHERE contract_id = ?",
                (json.dumps(result), contract_id),
            )
            self.db.commit()
            return result

    def _add_dispute_payments(self, pending_payments: list, result: dict, row,
                              bounty: Decimal, judge_fee: Decimal, inclusive_bond: Decimal):
        """Add judge fee routing payments for disputes. Adjusts existing payments."""
        if not result.get("dispute_loser"):
            return

        tier_fee = Decimal(result.get("tier_fee_to_platform", "0"))
        loser = result["dispute_loser"]
        winner = result.get("winner")

        # Tier fee goes to platform (platform runs the judge)
        if tier_fee > 0 and self.platform_account:
            pending_payments.append((self.platform_account, str(tier_fee), "judge_tier_fee"))

        # Loser gets (judge_fee - tier_fee) back — already included in main payout for
        # non-evil cases. For evil cases, they lose bounty but keep judge remainder.
        # Winner's judge_fee is already included in their payout.

        # Evil: loser's bounty to charity
        charity_amount = Decimal(result.get("loser_bounty_to_charity") or "0")
        winner_charity = Decimal(result.get("winner_bounty_to_charity") or "0")
        total_charity = charity_amount + winner_charity
        if total_charity > 0 and hasattr(self.payment, 'charity_account') and self.payment.charity_account:
            pending_payments.append((self.payment.charity_account, str(total_charity), "evil_bond_charity"))

    def _route_evil_payments(self, pending_payments: list, result: dict, row,
                             bounty: Decimal, judge_fee: Decimal,
                             inclusive_bond: Decimal, platform_fee: Decimal,
                             action: str):
        """Route payments for evil rulings."""
        tier_fee = Decimal(result.get("tier_fee_to_platform", "0"))
        loser_judge_return = max(judge_fee - tier_fee, Decimal("0"))

        if action == "fulfilled_evil_principal":
            # Agent wins bounty. Principal's bounty to charity. Both judge fees handled.
            agent_payout = bounty - platform_fee + inclusive_bond  # their bond + bounty won
            if row["agent_account"]:
                pending_payments.append((row["agent_account"], str(agent_payout), "agent_payout"))
            # Principal's bounty to charity (not their judge_fee remainder)
            if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                pending_payments.append((self.payment.charity_account, str(bounty), "evil_bond_charity"))
            # Principal gets judge_fee remainder back (insurance)
            if row["principal_account"] and loser_judge_return > 0:
                pending_payments.append((row["principal_account"], str(loser_judge_return), "loser_judge_fee_return"))

        elif action == "canceled_evil_agent":
            # Principal gets their bounty back. Agent's bounty to charity.
            principal_payout = bounty - platform_fee + judge_fee  # their judge_fee back
            if row["principal_account"]:
                pending_payments.append((row["principal_account"], str(principal_payout), "principal_payout"))
            # Agent's bounty to charity
            if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                pending_payments.append((self.payment.charity_account, str(bounty), "evil_bond_charity"))
            # Agent gets judge_fee remainder back (insurance)
            if row["agent_account"] and loser_judge_return > 0:
                pending_payments.append((row["agent_account"], str(loser_judge_return), "loser_judge_fee_return"))

        elif action == "canceled_evil_principal":
            # Bounty to charity. Agent gets their bond back.
            if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                pending_payments.append((self.payment.charity_account, str(bounty), "evil_bond_charity"))
            if row["agent_account"]:
                pending_payments.append((row["agent_account"], str(inclusive_bond), "agent_bond_return"))
            # Principal gets judge_fee remainder (insurance)
            if row["principal_account"] and loser_judge_return > 0:
                pending_payments.append((row["principal_account"], str(loser_judge_return), "loser_judge_fee_return"))

        elif action == "canceled_both_evil":
            # Both bounties to charity. Both get judge_fee remainder.
            total_charity = bounty * 2
            if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                pending_payments.append((self.payment.charity_account, str(total_charity), "evil_bond_charity"))
            # Both get judge_fee remainder back
            if row["principal_account"] and loser_judge_return > 0:
                pending_payments.append((row["principal_account"], str(loser_judge_return), "principal_judge_fee_return"))
            if row["agent_account"] and loser_judge_return > 0:
                pending_payments.append((row["agent_account"], str(loser_judge_return), "agent_judge_fee_return"))

        # Tier fee + platform fee both go to platform (combined)
        total_platform = platform_fee + tier_fee
        if self.platform_account and total_platform > 0:
            pending_payments.append((self.platform_account, str(total_platform), "platform_fee"))

    def get(self, contract_id: str) -> dict | None:
        """Get escrow state for a contract."""
        row = self.db.execute("SELECT * FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            return None
        return {
            "contract_id": row["contract_id"],
            "bounty": row["bounty"],
            "locked": bool(row["locked"]),
            "resolved": bool(row["resolved"]),
            "resolution": json.loads(row["resolution"]) if row["resolution"] else None,
            "escrow_account": row["escrow_account"],
            "principal_account": row["principal_account"],
            "agent_account": row["agent_account"],
            "judge_fee": row["judge_fee"],
            "inclusive_bond": row["inclusive_bond"],
            "principal_locked": bool(row["principal_locked"]),
            "agent_locked": bool(row["agent_locked"]),
        }

    def close(self):
        self.db.close()
