"""Escrow management for fix platform.

Handles payment routing: lock, resolve, persist state in SQLite.
PaymentBackend (Nano or stub) handles actual fund movement.

Dispute bonds: both sides stake a bond upfront. On dispute, loser's bond
pays the judge. Winner's bond is returned.
"""

import sqlite3
import json
import threading
from decimal import Decimal
from pathlib import Path

from protocol import DEFAULT_CANCEL_FEE, DEFAULT_JUDGE_FEE, GRACE_PERIOD_SECONDS, PLATFORM_FEE_RATE, PLATFORM_FEE_MIN, Ruling
from server.nano import validate_nano_address


def calculate_fee(bounty: Decimal, fee: Decimal) -> Decimal:
    """Fee is absolute (not percentage). Capped at bounty."""
    return min(fee, bounty)


class Escrow:
    """Payment routing logic for a single contract.

    Tracks lock state and computes where funds go based on rulings/flags.
    Now includes dispute bond tracking and judge fee routing.
    """

    def __init__(self, bounty: str, terms: dict):
        self.bounty = Decimal(bounty)
        self.terms = terms
        self.cancel_fee_agent = Decimal(
            terms.get("cancellation", {}).get("agent_fee", DEFAULT_CANCEL_FEE)
        )
        self.cancel_fee_principal = Decimal(
            terms.get("cancellation", {}).get("principal_fee", DEFAULT_CANCEL_FEE)
        )
        self.judge_fee = Decimal(terms.get("judge_fee", DEFAULT_JUDGE_FEE))
        self.locked = False
        self.resolved = False
        self.resolution: dict | None = None
        self.principal_bond_locked = False
        self.agent_bond_locked = False

    def lock(self) -> dict:
        """Lock escrow (bounty + principal's dispute bond)."""
        self.locked = True
        self.principal_bond_locked = True
        return {"status": "locked", "amount": str(self.bounty), "principal_bond": str(self.judge_fee)}

    def lock_agent_bond(self) -> dict:
        """Lock agent's dispute bond when they start investigating."""
        self.agent_bond_locked = True
        return {"status": "agent_bond_locked", "bond": str(self.judge_fee)}

    def release_agent_bond(self) -> dict:
        """Return agent's bond if they decline after investigating."""
        self.agent_bond_locked = False
        return {"status": "agent_bond_released", "bond": str(self.judge_fee)}

    def resolve(self, ruling: str, flags: list[str] | None = None,
                in_grace: bool = False, backed_out_by: str | None = None,
                dispute_loser: str | None = None, judge_account: str | None = None) -> dict:
        """Route funds based on ruling. Returns dict describing payment actions.

        dispute_loser: "agent" or "principal" -- whose bond pays the judge.
        judge_account: where to send the judge fee.
        """
        flags = set(flags or [])

        if ruling == "voided":
            return self._void()

        if ruling == "fulfilled":
            if "evil_principal" in flags:
                result = self._charity(self.bounty, "principal flagged as evil on fulfilled contract")
            else:
                result = self._release_agent(self.bounty)
            self._apply_bond_routing(result, dispute_loser, judge_account)
            return result

        elif ruling == "canceled":
            if "evil_agent" in flags and "evil_principal" in flags:
                result = self._charity(self.bounty, "both parties flagged as evil")
            elif "evil_agent" in flags:
                result = self._return_principal(
                    self.bounty, fee_from=None, fee_amount=None,
                    details="agent flagged as evil, forfeits all",
                )
            elif "evil_principal" in flags:
                result = self._charity(self.bounty, "principal flagged as evil")
            else:
                fee = calculate_fee(self.bounty, self.cancel_fee_agent)
                result = self._return_principal(
                    self.bounty, fee_from="agent", fee_amount=fee,
                    details="canceled, agent pays cancellation fee",
                )
            self._apply_bond_routing(result, dispute_loser, judge_account)
            return result

        elif ruling == "impossible":
            result = self._return_principal(
                self.bounty, fee_from=None, fee_amount=None,
                details="contract ruled impossible, no fees",
            )
            self._apply_bond_routing(result, dispute_loser, judge_account)
            return result

        elif ruling == "backed_out":
            if in_grace:
                result = self._return_principal(
                    self.bounty, fee_from=None, fee_amount=None,
                    details="backed out during grace period, no fees",
                )
            elif backed_out_by == "principal":
                fee = calculate_fee(self.bounty, self.cancel_fee_principal)
                result = self._return_principal(
                    self.bounty, fee_from="principal", fee_amount=fee,
                    details="principal backed out post-grace, pays cancellation fee",
                )
            else:
                fee = calculate_fee(self.bounty, self.cancel_fee_agent)
                result = self._return_principal(
                    self.bounty, fee_from="agent", fee_amount=fee,
                    details="agent backed out post-grace, pays cancellation fee",
                )
            self._apply_bond_routing(result, dispute_loser, judge_account)
            return result

        else:
            raise ValueError(f"unknown ruling: {ruling}")

    def _apply_bond_routing(self, result: dict, dispute_loser: str | None, judge_account: str | None):
        """Add bond routing info to result. Loser's bond -> judge, winner's bond returned."""
        result["judge_fee"] = str(self.judge_fee)
        if dispute_loser and judge_account:
            result["bond_loser"] = dispute_loser
            result["bond_to_judge"] = str(self.judge_fee)
            result["judge_account"] = judge_account
            winner = "principal" if dispute_loser == "agent" else "agent"
            result["bond_returned_to"] = winner
        else:
            # No dispute -- both bonds returned
            result["bond_loser"] = None
            result["bond_to_judge"] = None
            result["judge_account"] = None
            result["bond_returned_to"] = None
        # Platform fee: 10% of bounty per side, min 0.005 XNO
        bounty = Decimal(result.get("amount", "0"))
        fee = max(bounty * PLATFORM_FEE_RATE, PLATFORM_FEE_MIN)
        result["platform_fee_per_side"] = str(fee)

    def _void(self) -> dict:
        """Judge didn't show. Everything returned: bounty to principal, both bonds returned."""
        self.resolved = True
        result = {
            "action": "voided",
            "amount": str(self.bounty),
            "fee_from": None,
            "fee_amount": None,
            "charity_amount": None,
            "details": "judge timeout, contract voided, all funds returned",
            "principal_bond_returned": str(self.judge_fee) if self.principal_bond_locked else None,
            "agent_bond_returned": str(self.judge_fee) if self.agent_bond_locked else None,
        }
        self.resolution = result
        return result

    def release_to_agent(self) -> dict:
        return self.resolve("fulfilled")

    def return_to_principal(self, reason: str = "canceled") -> dict:
        return self.resolve("canceled")

    def send_to_charity(self, reason: str = "") -> dict:
        result = self._charity(self.bounty, reason or "forced to charity")
        self.resolved = True
        self.resolution = result
        return result

    def pay_cancellation_fee(self, who: str) -> dict:
        if who == "agent":
            fee = calculate_fee(self.bounty, self.cancel_fee_agent)
        elif who == "principal":
            fee = calculate_fee(self.bounty, self.cancel_fee_principal)
        else:
            raise ValueError(f"who must be 'agent' or 'principal', got: {who}")
        return {"action": "pay_fee", "fee_from": who, "fee_amount": str(fee), "details": f"{who} pays cancellation fee"}

    def _release_agent(self, amount: Decimal) -> dict:
        self.resolved = True
        result = {"action": "release_to_agent", "amount": str(amount), "fee_from": None, "fee_amount": None, "charity_amount": None, "details": "bounty released to agent"}
        self.resolution = result
        return result

    def _return_principal(self, amount: Decimal, fee_from, fee_amount, details: str) -> dict:
        self.resolved = True
        result = {"action": "return_to_principal", "amount": str(amount), "fee_from": fee_from, "fee_amount": str(fee_amount) if fee_amount is not None else None, "charity_amount": None, "details": details}
        self.resolution = result
        return result

    def _charity(self, amount: Decimal, details: str) -> dict:
        self.resolved = True
        result = {"action": "send_to_charity", "amount": str(amount), "fee_from": None, "fee_amount": None, "charity_amount": str(amount), "details": details}
        self.resolution = result
        return result


class EscrowManager:
    """SQLite-backed escrow manager with pluggable payment backend."""

    def __init__(self, db_path: str = ":memory:", payment_backend=None, platform_account: str = ""):
        from server.nano import StubBackend
        from protocol import PLATFORM_ADDRESS
        self.payment = payment_backend or StubBackend()
        self.platform_account = platform_account or PLATFORM_ADDRESS
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
                judge_account TEXT,
                judge_fee TEXT,
                principal_bond_locked INTEGER DEFAULT 0,
                agent_bond_locked INTEGER DEFAULT 0,
                min_bond TEXT DEFAULT '0'
            )
        """)
        self.db.commit()

    def lock(self, contract_id: str, bounty: str, terms: dict, judge_account: str = "",
             judge_fee: str = "", min_bond: str = "0") -> dict:
        """Lock escrow for a contract. Creates escrow account via payment backend.
        Also locks principal's dispute bond upfront.
        min_bond: minimum bond agents must post (bond-as-reputation). Actual bond = max(judge_fee, min_bond).
        """
        escrow = Escrow(bounty, terms)
        result = escrow.lock()

        # Create escrow account
        account_info = self.payment.create_escrow_account(contract_id)
        escrow_account = account_info.get("account", "")

        actual_judge_fee = judge_fee or str(escrow.judge_fee)

        self.db.execute(
            "INSERT INTO escrows (contract_id, bounty, terms, locked, escrow_account, judge_account, judge_fee, principal_bond_locked, min_bond) VALUES (?, ?, ?, 1, ?, ?, ?, 1, ?)",
            (contract_id, bounty, json.dumps(terms), escrow_account, judge_account, actual_judge_fee, min_bond),
        )
        self.db.commit()

        result["escrow_account"] = escrow_account
        return result

    def lock_agent_bond(self, contract_id: str) -> dict:
        """Lock agent's dispute bond when they start investigating.
        Bond amount = max(judge_fee, min_bond). min_bond is the principal's
        trust requirement (bond-as-reputation)."""
        row = self.db.execute("SELECT judge_fee, min_bond FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            raise ValueError(f"No escrow for contract {contract_id}")
        judge_fee = Decimal(row["judge_fee"] or DEFAULT_JUDGE_FEE)
        min_bond = Decimal(row["min_bond"] or "0")
        actual_bond = max(judge_fee, min_bond)
        self.db.execute(
            "UPDATE escrows SET agent_bond_locked = 1 WHERE contract_id = ?",
            (contract_id,),
        )
        self.db.commit()
        return {"status": "agent_bond_locked", "bond": str(actual_bond), "judge_fee": str(judge_fee), "min_bond": str(min_bond)}

    def release_agent_bond(self, contract_id: str) -> dict:
        """Return agent's bond if they decline after investigating."""
        row = self.db.execute("SELECT judge_fee FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            raise ValueError(f"No escrow for contract {contract_id}")
        self.db.execute(
            "UPDATE escrows SET agent_bond_locked = 0 WHERE contract_id = ?",
            (contract_id,),
        )
        self.db.commit()
        return {"status": "agent_bond_released", "bond": row["judge_fee"] or DEFAULT_JUDGE_FEE}

    def set_accounts(self, contract_id: str, principal_account: str = "",
                     agent_account: str = "") -> bool:
        """Set participant Nano addresses for a contract.
        Can only set your own account (enforced by caller in app.py).
        Cannot change after escrow resolution (defense in depth)."""
        with self._lock:
            # Check not already resolved
            row = self.db.execute(
                "SELECT resolved FROM escrows WHERE contract_id = ?",
                (contract_id,),
            ).fetchone()
            if not row:
                return False
            if row["resolved"]:
                return False  # Cannot change accounts after resolution

            # Validate Nano addresses
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
        """Check if escrow deposit has been received."""
        row = self.db.execute("SELECT bounty FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
        if not row:
            return False
        return self.payment.check_deposit(contract_id, row["bounty"])

    def resolve(self, contract_id: str, ruling: str, flags: list[str] | None = None,
                dispute_loser: str | None = None, **kwargs) -> dict:
        """Resolve escrow for a contract. Moves funds via payment backend.

        For disputes: dispute_loser's bond goes to judge, winner's bond returned.
        For voided: everything returned.

        CRITICAL: If payment fails, escrow is NOT marked resolved -- funds stay
        in escrow for manual recovery. Only marks resolved on successful payment.
        """
        with self._lock:
            row = self.db.execute("SELECT * FROM escrows WHERE contract_id = ?", (contract_id,)).fetchone()
            if not row:
                raise ValueError(f"No escrow for contract {contract_id}")

            # Double-resolution guard
            if row["resolved"]:
                return json.loads(row["resolution"]) if row["resolution"] else {"error": "already resolved"}

            # Must be locked before resolving
            if not row["locked"]:
                raise ValueError(f"Escrow for {contract_id} was never locked")

            escrow = Escrow(row["bounty"], json.loads(row["terms"]))
            escrow.locked = bool(row["locked"])
            escrow.principal_bond_locked = bool(row["principal_bond_locked"])
            escrow.agent_bond_locked = bool(row["agent_bond_locked"])

            result = escrow.resolve(
                ruling, flags=flags,
                dispute_loser=dispute_loser,
                judge_account=row["judge_account"],
                **kwargs,
            )

            # Calculate actual payment amounts after fee deductions
            action = result.get("action")
            bounty = Decimal(row["bounty"])
            platform_fee = Decimal(result.get("platform_fee_per_side", "0"))
            # Total platform fee from both sides
            total_platform_fee = platform_fee * 2

            # Deduct fees from the payout
            fee_amount = Decimal(result["fee_amount"]) if result.get("fee_amount") else Decimal("0")
            if action == "release_to_agent":
                payout = bounty - total_platform_fee
            elif action == "return_to_principal":
                payout = bounty - fee_amount - total_platform_fee
            elif action == "voided":
                payout = bounty  # No fees on void
            elif action == "send_to_charity":
                payout = bounty
            else:
                payout = bounty

            payout = max(payout, Decimal("0"))
            result["actual_payout"] = str(payout)
            result["total_platform_fee"] = str(total_platform_fee)

            # Require payout address for non-charity resolutions
            if action == "release_to_agent" and not row["agent_account"]:
                raise ValueError(f"Cannot resolve: agent has not set a payout address")
            if action == "return_to_principal" and not row["principal_account"]:
                raise ValueError(f"Cannot resolve: principal has not set a payout address")
            if action == "voided" and not row["principal_account"]:
                raise ValueError(f"Cannot resolve (void): principal has not set a payout address")

            # Collect all pending payments
            pending_payments = []
            payout_str = str(payout)
            if action == "release_to_agent" and row["agent_account"]:
                pending_payments.append((row["agent_account"], payout_str, "main_payout"))
            elif action == "return_to_principal" and row["principal_account"]:
                pending_payments.append((row["principal_account"], payout_str, "main_payout"))
            elif action == "voided" and row["principal_account"]:
                pending_payments.append((row["principal_account"], payout_str, "main_payout"))
            elif action == "send_to_charity":
                if hasattr(self.payment, 'charity_account') and self.payment.charity_account:
                    pending_payments.append((self.payment.charity_account, payout_str, "charity"))

            # Route dispute bond to judge if applicable
            if result.get("bond_to_judge") and row["judge_account"]:
                pending_payments.append((row["judge_account"], result["bond_to_judge"], "judge_bond"))

            # Platform fee: send to platform treasury if configured
            if self.platform_account and total_platform_fee > 0 and action != "voided":
                pending_payments.append((self.platform_account, str(total_platform_fee), "platform_fee"))

            # Execute all payments — if any fail, none are committed as resolved
            block_hashes = []
            try:
                for to_account, amount, label in pending_payments:
                    bh = self.payment.send(contract_id, to_account, amount)
                    block_hashes.append((label, bh))
            except Exception as e:
                result["payment_error"] = str(e)
                result["payment_failed"] = True
                result["completed_payments"] = block_hashes  # for manual recovery
                self.db.execute(
                    "UPDATE escrows SET resolution = ? WHERE contract_id = ?",
                    (json.dumps(result), contract_id),
                )
                self.db.commit()
                return result

            if block_hashes:
                result["block_hashes"] = {label: bh for label, bh in block_hashes}

            # Payment succeeded -- now mark as resolved
            self.db.execute(
                "UPDATE escrows SET resolved = 1, resolution = ? WHERE contract_id = ?",
                (json.dumps(result), contract_id),
            )
            self.db.commit()
            return result

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
            "judge_account": row["judge_account"],
            "judge_fee": row["judge_fee"],
            "principal_bond_locked": bool(row["principal_bond_locked"]),
            "agent_bond_locked": bool(row["agent_bond_locked"]),
        }

    def close(self):
        self.db.close()
