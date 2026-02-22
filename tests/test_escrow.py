"""Tests for server/escrow.py -- payment routing logic + dispute bonds."""

import sys
import os
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import unittest
from decimal import Decimal
from server.escrow import Escrow, EscrowManager, calculate_fee
from conftest import (
    make_nano_backend, fund_escrow, set_funded_accounts, fund_account,
    TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
)


TERMS = {"cancellation": {"agent_fee": "0.002", "principal_fee": "0.003", "grace_period": 30}}
TERMS_WITH_JUDGE = {**TERMS, "judge_fee": "0.005"}


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
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["principal_bond_returned"], "0.005")
        self.assertIsNone(result["agent_bond_returned"])


class TestEscrowBondRouting(unittest.TestCase):
    def test_dispute_loser_bond_to_judge_tier_fee_only(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("fulfilled", dispute_loser="principal", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_loser"], "principal")
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["judge_account"], "judge_abc")
        self.assertEqual(result["bond_returned_to"], "agent")
        self.assertEqual(result["bond_remainder_returned"], "0.003")
        self.assertIsNone(result["bond_to_charity"])

    def test_dispute_loser_no_tier_fee_falls_back_to_full_bond(self):
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
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("canceled", flags=["evil_agent"],
                          dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")
        self.assertIsNone(result["bond_remainder_returned"])

    def test_evil_principal_bond_remainder_to_charity(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("fulfilled", flags=["evil_principal"],
                          dispute_loser="principal", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")
        self.assertEqual(result["action"], "send_to_charity")

    def test_evil_both_all_bonds_to_charity(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond()
        result = e.resolve("canceled", flags=["evil_agent", "evil_principal"],
                          dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.002"))
        self.assertEqual(result["bond_to_judge"], "0.002")
        self.assertEqual(result["bond_to_charity"], "0.003")
        self.assertEqual(result["other_evil_bond_to_charity"], "0.005")
        self.assertIsNone(result["bond_returned_to"])

    def test_evil_agent_with_high_min_bond(self):
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
        e = Escrow("1.00", TERMS_WITH_JUDGE)
        result = e.resolve("fulfilled")
        self.assertEqual(Decimal(result["platform_fee"]), Decimal("0.1"))


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
        self.nano = make_nano_backend()
        self.mgr = EscrowManager(":memory:", payment_backend=self.nano)

    def tearDown(self):
        self.mgr.close()

    def _fund_and_set(self, cid, amount="0.67"):
        """Fund escrow and set real payout addresses."""
        fund_escrow(self.mgr, cid, amount)
        set_funded_accounts(self.mgr, cid, TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)

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
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account=TEST_AGENT_ADDR, judge_fee="0.005")
        state = self.mgr.get("c1")
        self.assertEqual(state["judge_account"], TEST_AGENT_ADDR)
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
        self._fund_and_set("c1")
        result = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])
        self.assertEqual(state["resolution"]["action"], "release_to_agent")

    def test_resolve_voided(self):
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account=TEST_AGENT_ADDR)
        self.mgr.lock_agent_bond("c1")
        self._fund_and_set("c1")
        result = self.mgr.resolve("c1", "voided")
        self.assertEqual(result["action"], "voided")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])

    def test_resolve_with_dispute_loser(self):
        self.mgr.lock("c1", "0.05", TERMS_WITH_JUDGE, judge_account=TEST_PRINCIPAL_ADDR, judge_fee="0.005")
        self.mgr.lock_agent_bond("c1")
        self._fund_and_set("c1")
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
        self._fund_and_set("c2")
        result = self.mgr.resolve("c2", "canceled", flags=["evil_agent"])
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIn("forfeits", result["details"])

    def test_persistence_across_queries(self):
        self.mgr.lock("c1", "0.05", TERMS)
        self._fund_and_set("c1")
        self.mgr.resolve("c1", "fulfilled")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])
        self.assertEqual(state["resolution"]["action"], "release_to_agent")


class TestEscrowDoubleResolve(unittest.TestCase):
    def test_double_resolve_returns_same_result(self):
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
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.release_agent_bond()
        self.assertFalse(e.agent_bond_locked)
        self.assertEqual(result["status"], "agent_bond_released")


class TestEscrowResolveEdgeCases(unittest.TestCase):
    def test_resolve_with_zero_bounty(self):
        e = Escrow("0", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["amount"], "0")
        self.assertTrue(e.resolved)

    def test_resolve_tiny_bounty(self):
        e = Escrow("0.001", TERMS)
        result = e.resolve("canceled")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["fee_amount"], "0.001")

    def test_resolve_with_tier_fee_exceeding_bond(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        e.lock()
        e.lock_agent_bond(amount=Decimal("0.005"))
        result = e.resolve("fulfilled", dispute_loser="agent", judge_account="judge_abc",
                          tier_fee=Decimal("0.01"))
        bond_remainder = Decimal(result.get("bond_remainder_returned") or "0")
        self.assertGreaterEqual(bond_remainder, Decimal("0"))
        self.assertIsNone(result.get("bond_to_charity"))

    def test_resolve_voided_without_locking(self):
        e = Escrow("0.05", TERMS_WITH_JUDGE)
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["amount"], "0.05")
        self.assertIsNone(result["principal_bond_returned"])
        self.assertIsNone(result["agent_bond_returned"])
        self.assertTrue(e.resolved)


class TestEscrowManagerDoubleResolve(unittest.TestCase):
    def setUp(self):
        self.nano = make_nano_backend()
        self.mgr = EscrowManager(":memory:", payment_backend=self.nano)

    def tearDown(self):
        self.mgr.close()

    def test_mgr_double_resolve_returns_cached(self):
        self.mgr.lock("c1", "0.05", TERMS)
        fund_escrow(self.mgr, "c1")
        set_funded_accounts(self.mgr, "c1", TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)
        first = self.mgr.resolve("c1", "fulfilled")
        second = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(first["action"], second["action"])
        self.assertEqual(first["amount"], second["amount"])

    def test_mgr_resolve_unlocked_raises(self):
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
        self.nano = make_nano_backend()
        self.mgr = EscrowManager(":memory:", payment_backend=self.nano)

    def tearDown(self):
        self.mgr.close()

    def test_set_accounts_after_resolved_fails(self):
        self.mgr.lock("c1", "0.05", TERMS)
        fund_escrow(self.mgr, "c1")
        set_funded_accounts(self.mgr, "c1", TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)
        self.mgr.resolve("c1", "fulfilled")
        result = self.mgr.set_accounts("c1", principal_account="new_addr")
        self.assertFalse(result)

    def test_set_accounts_nonexistent_contract(self):
        result = self.mgr.set_accounts("no_such_contract", principal_account="addr")
        self.assertFalse(result)

    def test_set_accounts_empty_both(self):
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
