"""Tests for server/escrow.py -- payment routing logic + dispute bonds."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "server"))

import unittest
from decimal import Decimal
from server.escrow import Escrow, EscrowManager, calculate_fee


TERMS = {"cancellation": {"agent_fee": "0.002", "principal_fee": "0.003", "grace_period": 30}}
TERMS_WITH_JUDGE = {**TERMS, "judge_fee": "0.005"}


def _set_stub_accounts(mgr, cid, principal="stub_principal", agent="stub_agent"):
    """Set test accounts directly, bypassing nano address validation."""
    mgr.db.execute(
        "UPDATE escrows SET principal_account = ?, agent_account = ? WHERE contract_id = ?",
        (principal, agent, cid),
    )
    mgr.db.commit()


class TestCalculateFee(unittest.TestCase):
    def test_normal_fee(self):
        self.assertEqual(calculate_fee(Decimal("1.0"), Decimal("0.002")), Decimal("0.002"))

    def test_fee_exceeds_bounty(self):
        self.assertEqual(calculate_fee(Decimal("0.001"), Decimal("0.002")), Decimal("0.001"))

    def test_fee_equals_bounty(self):
        self.assertEqual(calculate_fee(Decimal("0.002"), Decimal("0.002")), Decimal("0.002"))


class TestEscrowLock(unittest.TestCase):
    def test_lock(self):
        e = Escrow("0.05", TERMS)
        self.assertFalse(e.locked)
        result = e.lock()
        self.assertTrue(e.locked)
        self.assertEqual(result["status"], "locked")
        self.assertEqual(result["amount"], "0.05")

    def test_lock_sets_principal_bond(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.lock()
        self.assertTrue(e.principal_bond_locked)
        self.assertEqual(result["principal_bond"], "0.005")


class TestEscrowAgentBond(unittest.TestCase):
    def test_lock_agent_bond(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.lock_agent_bond()
        self.assertTrue(e.agent_bond_locked)
        self.assertEqual(result["status"], "agent_bond_locked")
        self.assertEqual(result["bond"], "0.005")

    def test_release_agent_bond(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock_agent_bond()
        result = e.release_agent_bond()
        self.assertFalse(e.agent_bond_locked)
        self.assertEqual(result["status"], "agent_bond_released")


class TestEscrowResolveFulfilled(unittest.TestCase):
    def test_fulfilled_agent_gets_bounty(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["amount"], "0.05")
        self.assertIsNone(result["fee_from"])
        self.assertIsNone(result["fee_amount"])
        self.assertTrue(e.resolved)

    def test_fulfilled_evil_principal_goes_to_charity(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("fulfilled", flags=["evil_principal"])
        self.assertEqual(result["action"], "send_to_charity")
        self.assertEqual(result["charity_amount"], "0.05")
        self.assertTrue(e.resolved)


class TestEscrowResolveCanceled(unittest.TestCase):
    def test_canceled_return_to_principal_agent_fee(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("canceled")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["amount"], "0.05")
        self.assertEqual(result["fee_from"], "agent")
        self.assertEqual(result["fee_amount"], "0.002")
        self.assertTrue(e.resolved)

    def test_canceled_evil_agent_forfeits(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("canceled", flags=["evil_agent"])
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIsNone(result["fee_from"])
        self.assertIsNone(result["fee_amount"])
        self.assertIn("forfeits", result["details"])

    def test_canceled_evil_principal_charity(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("canceled", flags=["evil_principal"])
        self.assertEqual(result["action"], "send_to_charity")
        self.assertEqual(result["charity_amount"], "0.05")

    def test_canceled_both_evil_charity(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("canceled", flags=["evil_agent", "evil_principal"])
        self.assertEqual(result["action"], "send_to_charity")
        self.assertEqual(result["charity_amount"], "0.05")
        self.assertIn("both", result["details"])


class TestEscrowResolveImpossible(unittest.TestCase):
    def test_impossible_return_no_fees(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("impossible")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIsNone(result["fee_from"])
        self.assertIsNone(result["fee_amount"])
        self.assertIn("impossible", result["details"])


class TestEscrowResolveBackedOut(unittest.TestCase):
    def test_backed_out_in_grace_no_fees(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("backed_out", in_grace=True)
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIsNone(result["fee_from"])
        self.assertIsNone(result["fee_amount"])
        self.assertIn("grace", result["details"])

    def test_backed_out_by_agent(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("backed_out", backed_out_by="agent")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["fee_from"], "agent")
        self.assertEqual(result["fee_amount"], "0.002")

    def test_backed_out_by_principal(self):
        e = Escrow("0.05", TERMS)
        result = e.resolve("backed_out", backed_out_by="principal")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["fee_from"], "principal")
        self.assertEqual(result["fee_amount"], "0.003")


class TestEscrowResolveVoided(unittest.TestCase):
    def test_voided_returns_everything(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["amount"], "0.05")
        self.assertIn("judge timeout", result["details"])
        self.assertEqual(result["principal_bond_returned"], "0.005")
        self.assertEqual(result["agent_bond_returned"], "0.005")
        self.assertTrue(e.resolved)

    def test_voided_no_agent_bond(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        # Agent never bonded
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["principal_bond_returned"], "0.005")
        self.assertIsNone(result["agent_bond_returned"])


class TestEscrowBondRouting(unittest.TestCase):
    def test_dispute_loser_bond_to_judge_tier_fee_only(self):
        """Loser pays only the tier fee, not the full bond."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("fulfilled", dispute_loser="principal", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_loser"], "principal")
        self.assertEqual(result["bond_to_judge"], "0.002")  # tier fee, not full 0.005
        self.assertEqual(result["judge_account"], "judge_abc")
        self.assertEqual(result["bond_returned_to"], "agent")
        self.assertEqual(result["bond_remainder_returned"], "0.003")  # 0.005 - 0.002
        self.assertIsNone(result["bond_to_charity"])

    def test_dispute_loser_no_tier_fee_falls_back_to_full_bond(self):
        """Without tier_fee param, falls back to full judge_fee (backwards compat)."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("fulfilled", dispute_loser="principal", judge_account="judge_abc")
        self.assertEqual(result["bond_to_judge"], "0.005")
        self.assertIsNone(result["bond_remainder_returned"])

    def test_dispute_agent_loses(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("canceled", dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_loser"], "agent")
        self.assertEqual(result["bond_returned_to"], "principal")
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_remainder_returned"], "0.003")

    def test_no_dispute_bonds_returned(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.resolve("fulfilled")
        self.assertIsNone(result["bond_loser"])
        self.assertIsNone(result["bond_to_judge"])
        self.assertIsNone(result["bond_returned_to"])

    def test_evil_agent_bond_remainder_to_charity(self):
        """Evil agent: tier fee to judge, remainder of bond to charity."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("canceled", flags=["evil_agent"],
                          dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")  # 0.005 - 0.002
        self.assertIsNone(result["bond_remainder_returned"])

    def test_evil_principal_bond_remainder_to_charity(self):
        """Evil principal: tier fee to judge, remainder of bond to charity."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("fulfilled", flags=["evil_principal"],
                          dispute_loser="principal", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")
        self.assertEqual(result["action"], "send_to_charity")  # bounty to charity too

    def test_evil_both_all_bonds_to_charity(self):
        """Evil both: both bonds (minus judge fees) to charity."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("canceled", flags=["evil_agent", "evil_principal"],
                          dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")  # agent's remainder
        self.assertEqual(result["other_evil_bond_to_charity"], "0.005")  # principal's full bond
        self.assertIsNone(result["bond_returned_to"])  # nobody gets bond back

    def test_evil_agent_with_high_min_bond(self):
        """Agent posted 2 XNO bond (min_bond), ruled evil at district (0.002).
        Judge gets 0.002, charity gets 1.998."""
        terms = {**TERMS_WITH_JUDGE, "min_bond": "2"}
        e = Escrow("0.05", terms)
        e.lock()
        e.lock_agent_bond(amount=Decimal("2"))
        result = e.resolve("canceled", flags=["evil_agent"],
                          dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "1.998")

    def test_platform_fee_principal_only(self):
        """Platform fee is 10% of bounty, from principal only (not both sides)."""
        e = Escrow("1.00", TERMS_WITH_JUDGE)
        result = e.resolve("fulfilled")
        self.assertEqual(Decimal(result["platform_fee"]), Decimal("0.1"))  # 10% of 1.00


class TestEscrowUnknownRuling(unittest.TestCase):
    def test_unknown_ruling_raises(self):
        e = Escrow("0.05", TERMS)
        with self.assertRaises(ValueError):
            e.resolve("nonsense")


class TestEscrowConvenienceMethods(unittest.TestCase):
    def test_release_to_agent(self):
        e = Escrow("0.05", TERMS)
        result = e.release_to_agent()
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["amount"], "0.05")

    def test_return_to_principal(self):
        e = Escrow("0.05", TERMS)
        result = e.return_to_principal()
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["fee_from"], "agent")

    def test_send_to_charity(self):
        e = Escrow("0.05", TERMS)
        result = e.send_to_charity("testing")
        self.assertEqual(result["action"], "send_to_charity")
        self.assertEqual(result["charity_amount"], "0.05")
        self.assertTrue(e.resolved)

    def test_send_to_charity_default_reason(self):
        e = Escrow("0.05", TERMS)
        result = e.send_to_charity()
        self.assertIn("forced to charity", result["details"])

    def test_pay_cancellation_fee_agent(self):
        e = Escrow("0.05", TERMS)
        result = e.pay_cancellation_fee("agent")
        self.assertEqual(result["action"], "pay_fee")
        self.assertEqual(result["fee_from"], "agent")
        self.assertEqual(result["fee_amount"], "0.002")

    def test_pay_cancellation_fee_principal(self):
        e = Escrow("0.05", TERMS)
        result = e.pay_cancellation_fee("principal")
        self.assertEqual(result["fee_from"], "principal")
        self.assertEqual(result["fee_amount"], "0.003")

    def test_pay_cancellation_fee_invalid(self):
        e = Escrow("0.05", TERMS)
        with self.assertRaises(ValueError):
            e.pay_cancellation_fee("judge")


class TestEscrowManager(unittest.TestCase):
    def setUp(self):
        self.mgr = EscrowManager(":memory:")

    def tearDown(self):
        self.mgr.close()

    def test_lock_and_get(self):
        result = self.mgr.lock("c1", "0.05", TERMS)
        self.assertEqual(result["status"], "locked")
        state = self.mgr.get("c1")
        self.assertIsNotNone(state)
        self.assertEqual(state["bounty"], "0.05")
        self.assertTrue(state["locked"])
        self.assertFalse(state["resolved"])
        self.assertIsNone(state["resolution"])

    def test_lock_sets_principal_bond(self):
        self.mgr.lock("c1", "0.05", TERMS)
        state = self.mgr.get("c1")
        self.assertTrue(state["principal_bond_locked"])

    def test_lock_with_judge(self):
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account="judge_abc", judge_fee="0.005")
        state = self.mgr.get("c1")
        self.assertEqual(state["judge_account"], "judge_abc")
        self.assertEqual(state["judge_fee"], "0.005")

    def test_lock_agent_bond(self):
        self.mgr.lock("c1", "0.05", TERMS)
        result = self.mgr.lock_agent_bond("c1")
        self.assertEqual(result["status"], "agent_bond_locked")
        state = self.mgr.get("c1")
        self.assertTrue(state["agent_bond_locked"])

    def test_release_agent_bond(self):
        self.mgr.lock("c1", "0.05", TERMS)
        self.mgr.lock_agent_bond("c1")
        result = self.mgr.release_agent_bond("c1")
        self.assertEqual(result["status"], "agent_bond_released")
        state = self.mgr.get("c1")
        self.assertFalse(state["agent_bond_locked"])

    def test_lock_agent_bond_nonexistent(self):
        with self.assertRaises(ValueError):
            self.mgr.lock_agent_bond("nope")

    def test_release_agent_bond_nonexistent(self):
        with self.assertRaises(ValueError):
            self.mgr.release_agent_bond("nope")

    def test_resolve(self):
        self.mgr.lock("c1", "0.05", TERMS)
        _set_stub_accounts(self.mgr, "c1")
        result = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])
        self.assertEqual(state["resolution"]["action"], "release_to_agent")

    def test_resolve_voided(self):
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account="judge_abc")
        self.mgr.lock_agent_bond("c1")
        _set_stub_accounts(self.mgr, "c1")
        result = self.mgr.resolve("c1", "voided")
        self.assertEqual(result["action"], "voided")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])

    def test_resolve_with_dispute_loser(self):
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account="judge_abc", judge_fee="0.005")
        self.mgr.lock_agent_bond("c1")
        _set_stub_accounts(self.mgr, "c1")
        result = self.mgr.resolve("c1", "fulfilled", dispute_loser="principal", tier_fee="0.002")
        self.assertEqual(result["bond_loser"], "principal")
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_remainder_returned"], "0.003")

    def test_resolve_nonexistent_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.resolve("nope", "fulfilled")

    def test_get_nonexistent(self):
        self.assertIsNone(self.mgr.get("nope"))

    def test_resolve_with_flags(self):
        self.mgr.lock("c2", "0.10", TERMS)
        _set_stub_accounts(self.mgr, "c2")
        result = self.mgr.resolve("c2", "canceled", flags=["evil_agent"])
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIn("forfeits", result["details"])

    def test_persistence_across_queries(self):
        self.mgr.lock("c1", "0.05", TERMS)
        _set_stub_accounts(self.mgr, "c1")
        self.mgr.resolve("c1", "fulfilled")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])
        self.assertEqual(state["resolution"]["action"], "release_to_agent")


class TestEscrowDoubleResolve(unittest.TestCase):
    def test_double_resolve_returns_same_result(self):
        """resolve() twice -- second call should return first result (idempotent via .resolved flag)."""
        e = Escrow("0.05", TERMS)
        first = e.resolve("fulfilled")
        second = e.resolve("fulfilled")
        self.assertEqual(first, second)

    def test_resolve_sets_resolved_flag(self):
        e = Escrow("0.05", TERMS)
        self.assertFalse(e.resolved)
        e.resolve("fulfilled")
        self.assertTrue(e.resolved)


class TestEscrowLockEdgeCases(unittest.TestCase):
    def test_double_lock(self):
        """lock() twice -- should still work (idempotent, locked stays True)."""
        e = Escrow("0.05", TERMS)
        e.lock()
        result = e.lock()
        self.assertTrue(e.locked)
        self.assertEqual(result["status"], "locked")

    def test_lock_agent_bond_with_custom_amount(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.lock_agent_bond(amount=Decimal("5"))
        self.assertEqual(e.agent_bond_amount, Decimal("5"))
        self.assertEqual(result["bond"], "5")

    def test_release_agent_bond_when_not_locked(self):
        """Releasing an unlocked bond should not crash."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        # Never locked agent bond -- release should still return cleanly
        result = e.release_agent_bond()
        self.assertFalse(e.agent_bond_locked)
        self.assertEqual(result["status"], "agent_bond_released")


class TestEscrowResolveEdgeCases(unittest.TestCase):
    def test_resolve_with_zero_bounty(self):
        """Escrow with 0 bounty should resolve without crashing, payout 0."""
        e = Escrow("0", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["amount"], "0")
        self.assertTrue(e.resolved)

    def test_resolve_tiny_bounty(self):
        """Tiny bounty: fee capped at bounty amount."""
        e = Escrow("0.001", TERMS)
        result = e.resolve("canceled")
        self.assertEqual(result["action"], "return_to_principal")
        # cancel_fee_agent is 0.002 but bounty is 0.001, so fee capped at 0.001
        self.assertEqual(result["fee_amount"], "0.001")

    def test_resolve_with_tier_fee_exceeding_bond(self):
        """tier_fee > bond -- bond_remainder should be 0, not negative."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond(amount=Decimal("0.005"))
        result = e.resolve("fulfilled", dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.01"))
        # bond is 0.005, tier_fee is 0.01 -- remainder clamped to 0
        bond_remainder = Decimal(result.get("bond_remainder_returned") or "0")
        self.assertGreaterEqual(bond_remainder, Decimal("0"))
        self.assertIsNone(result.get("bond_to_charity"))

    def test_resolve_voided_without_locking(self):
        """Escrow that was never locked -- should still void."""
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["amount"], "0.05")
        self.assertIsNone(result["principal_bond_returned"])
        self.assertIsNone(result["agent_bond_returned"])
        self.assertTrue(e.resolved)


class TestEscrowManagerDoubleResolve(unittest.TestCase):
    def setUp(self):
        self.mgr = EscrowManager(":memory:")

    def tearDown(self):
        self.mgr.close()

    def test_mgr_double_resolve_returns_cached(self):
        """manager.resolve() twice returns same result, second call doesn't re-execute payments."""
        self.mgr.lock("c1", "0.05", TERMS)
        _set_stub_accounts(self.mgr, "c1")
        first = self.mgr.resolve("c1", "fulfilled")
        second = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(first["action"], second["action"])
        self.assertEqual(first["amount"], second["amount"])

    def test_mgr_resolve_unlocked_raises(self):
        """Try to resolve without locking first -- should raise ValueError."""
        # Insert a row directly with locked=0 to simulate an unlocked escrow
        self.mgr.db.execute(
            "INSERT INTO escrows (contract_id, bounty, terms, locked) VALUES (?, ?, ?, 0)",
            ("c_unlocked", "0.05", '{"cancellation": {"agent_fee": "0.002"}}'),
        )
        self.mgr.db.commit()
        with self.assertRaises(ValueError) as ctx:
            self.mgr.resolve("c_unlocked", "fulfilled")
        self.assertIn("never locked", str(ctx.exception))


class TestEscrowManagerSetAccounts(unittest.TestCase):
    def setUp(self):
        self.mgr = EscrowManager(":memory:")

    def tearDown(self):
        self.mgr.close()

    def test_set_accounts_after_resolved_fails(self):
        """resolve, then try set_accounts -- returns False."""
        self.mgr.lock("c1", "0.05", TERMS)
        _set_stub_accounts(self.mgr, "c1")
        self.mgr.resolve("c1", "fulfilled")
        result = self.mgr.set_accounts("c1", principal_account="new_addr")
        self.assertFalse(result)

    def test_set_accounts_nonexistent_contract(self):
        """returns False for a contract that doesn't exist."""
        result = self.mgr.set_accounts("no_such_contract", principal_account="addr")
        self.assertFalse(result)

    def test_set_accounts_empty_both(self):
        """No principal or agent provided -- returns False."""
        self.mgr.lock("c1", "0.05", TERMS)
        result = self.mgr.set_accounts("c1")
        self.assertFalse(result)


class TestCalculateFeeEdgeCases(unittest.TestCase):
    def test_zero_bounty(self):
        self.assertEqual(calculate_fee(Decimal("0"), Decimal("0.002")), Decimal("0"))

    def test_zero_fee(self):
        self.assertEqual(calculate_fee(Decimal("1.0"), Decimal("0")), Decimal("0"))


if __name__ == "__main__":
    unittest.main()
