"""Tests for server/escrow.py -- inclusive bond model payment routing."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.dirname(__file__))

import unittest
from decimal import Decimal
from server.escrow import Escrow, EscrowManager
from conftest import (
    make_nano_backend, fund_escrow, set_funded_accounts, fund_account,
    TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR,
)

# Terms with judge_fee for inclusive bond tests
TERMS = {"cancellation": {"grace_period": 30}, "judge_fee": "0.17"}
TERMS_NO_JUDGE = {"cancellation": {"grace_period": 30}}


class TestEscrowLock(unittest.TestCase):
    def test_lock(self):
        e = Escrow("0.50", TERMS)
        self.assertFalse(e.locked)
        result = e.lock()
        self.assertTrue(e.locked)
        self.assertEqual(result["status"], "locked")
        self.assertEqual(result["bounty"], "0.50")
        self.assertEqual(result["judge_fee"], "0.17")
        self.assertEqual(result["inclusive_bond"], "0.67")

    def test_lock_sets_principal_locked(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        self.assertTrue(e.principal_locked)

    def test_inclusive_bond_computed(self):
        e = Escrow("1.00", TERMS)
        self.assertEqual(e.inclusive_bond, Decimal("1.17"))


class TestEscrowAgent(unittest.TestCase):
    def test_lock_agent(self):
        e = Escrow("0.50", TERMS)
        result = e.lock_agent()
        self.assertTrue(e.agent_locked)
        self.assertEqual(result["status"], "agent_locked")
        self.assertEqual(result["inclusive_bond"], "0.67")

    def test_release_agent(self):
        e = Escrow("0.50", TERMS)
        e.lock_agent()
        result = e.release_agent()
        self.assertFalse(e.agent_locked)
        self.assertEqual(result["status"], "agent_released")


class TestEscrowFulfilled(unittest.TestCase):
    def test_fulfilled_agent_gets_bounty(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["agent_gets_bounty"], "0.50")
        self.assertTrue(e.resolved)

    def test_fulfilled_platform_fee(self):
        e = Escrow("1.00", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(Decimal(result["platform_fee"]), Decimal("0.10"))

    def test_fulfilled_no_dispute_judge_fees_returned(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("fulfilled")
        self.assertIsNone(result["dispute_loser"])
        self.assertIsNone(result["tier_fee_to_platform"])

    def test_fulfilled_evil_principal(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("fulfilled", flags=["evil_principal"])
        self.assertEqual(result["action"], "fulfilled_evil_principal")
        self.assertEqual(result["principal_bounty_to_charity"], "0.50")


class TestEscrowCanceled(unittest.TestCase):
    def test_canceled_return_to_principal(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("canceled")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertEqual(result["principal_gets_bounty"], "0.50")

    def test_canceled_evil_agent(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("canceled", flags=["evil_agent"])
        self.assertEqual(result["action"], "canceled_evil_agent")
        self.assertEqual(result["agent_bounty_to_charity"], "0.50")
        self.assertEqual(result["principal_gets_bounty"], "0.50")

    def test_canceled_evil_principal(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("canceled", flags=["evil_principal"])
        self.assertEqual(result["action"], "canceled_evil_principal")
        self.assertEqual(result["principal_bounty_to_charity"], "0.50")

    def test_canceled_both_evil(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("canceled", flags=["evil_agent", "evil_principal"])
        self.assertEqual(result["action"], "canceled_both_evil")
        self.assertEqual(result["agent_bounty_to_charity"], "0.50")
        self.assertEqual(result["principal_bounty_to_charity"], "0.50")


class TestEscrowImpossible(unittest.TestCase):
    def test_impossible_return_no_penalty(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("impossible")
        self.assertEqual(result["action"], "return_to_principal")
        self.assertIn("impossible", result["details"])


class TestEscrowBackedOut(unittest.TestCase):
    def test_grace_period_no_fees(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("backed_out", in_grace=True)
        self.assertEqual(result["action"], "grace_return")
        self.assertEqual(result["platform_fee"], "0")

    def test_agent_backs_out_post_grace(self):
        e = Escrow("1.00", TERMS)
        result = e.resolve("backed_out", backed_out_by="agent")
        self.assertEqual(result["action"], "agent_canceled")
        # 20% cancel fee = 0.20. 10% reimburse = 0.10, 10% platform = 0.10
        self.assertEqual(Decimal(result["principal_gets_bounty"]), Decimal("1.00"))
        self.assertEqual(Decimal(result["principal_gets_reimburse"]), Decimal("0.10"))
        self.assertEqual(Decimal(result["agent_gets_back"]), Decimal("0.80"))
        self.assertEqual(Decimal(result["cancel_fee_to_platform"]), Decimal("0.10"))

    def test_principal_backs_out_post_grace(self):
        e = Escrow("1.00", TERMS)
        result = e.resolve("backed_out", backed_out_by="principal")
        self.assertEqual(result["action"], "principal_canceled")
        self.assertEqual(Decimal(result["principal_gets_back"]), Decimal("0.80"))
        self.assertEqual(Decimal(result["agent_gets_bounty_back"]), Decimal("1.00"))
        self.assertEqual(Decimal(result["agent_gets_reimburse"]), Decimal("0.10"))
        self.assertEqual(Decimal(result["cancel_fee_to_platform"]), Decimal("0.10"))


class TestEscrowVoided(unittest.TestCase):
    def test_voided_returns_everything(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("voided")
        self.assertEqual(result["action"], "voided")
        self.assertEqual(result["inclusive_bond"], "0.67")
        self.assertEqual(result["principal_returned"], "0.67")
        self.assertEqual(result["agent_returned"], "0.67")
        self.assertEqual(result["platform_fee"], "0")

    def test_voided_no_agent(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        result = e.resolve("voided")
        self.assertEqual(result["principal_returned"], "0.67")
        self.assertIsNone(result["agent_returned"])


class TestEscrowDisputeRouting(unittest.TestCase):
    def test_dispute_loser_pays_tier_fee(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("fulfilled", dispute_loser="principal",
                          tier_fee=Decimal("0.02"))
        self.assertEqual(result["dispute_loser"], "principal")
        self.assertEqual(result["tier_fee_to_platform"], "0.02")
        self.assertEqual(result["loser_judge_fee_returned"], "0.15")
        self.assertEqual(result["winner_judge_fee_returned"], "0.17")
        self.assertEqual(result["winner"], "agent")
        self.assertIsNone(result["loser_bounty_to_charity"])

    def test_dispute_agent_loses(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("canceled", dispute_loser="agent",
                          tier_fee=Decimal("0.05"))
        self.assertEqual(result["dispute_loser"], "agent")
        self.assertEqual(result["winner"], "principal")
        self.assertEqual(result["loser_judge_fee_returned"], "0.12")

    def test_evil_agent_bounty_to_charity(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("canceled", flags=["evil_agent"],
                          dispute_loser="agent",
                          tier_fee=Decimal("0.02"))
        self.assertEqual(result["loser_bounty_to_charity"], "0.50")
        # Judge fee minus tier_fee still returned
        self.assertEqual(result["loser_judge_fee_returned"], "0.15")

    def test_evil_both_all_bounties_to_charity(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("canceled", flags=["evil_agent", "evil_principal"],
                          dispute_loser="agent",
                          tier_fee=Decimal("0.02"))
        self.assertEqual(result["loser_bounty_to_charity"], "0.50")
        self.assertEqual(result["winner_bounty_to_charity"], "0.50")
        self.assertIsNone(result["winner"])

    def test_no_dispute_no_judge_routing(self):
        e = Escrow("0.50", TERMS)
        result = e.resolve("fulfilled")
        self.assertIsNone(result["dispute_loser"])
        self.assertIsNone(result["tier_fee_to_platform"])


class TestEscrowConvenience(unittest.TestCase):
    def test_release_to_agent(self):
        e = Escrow("0.50", TERMS)
        result = e.release_to_agent()
        self.assertEqual(result["action"], "release_to_agent")

    def test_return_to_principal(self):
        e = Escrow("0.50", TERMS)
        result = e.return_to_principal()
        self.assertEqual(result["action"], "return_to_principal")

    def test_send_to_charity(self):
        e = Escrow("0.50", TERMS)
        result = e.send_to_charity("test reason")
        self.assertEqual(result["action"], "send_to_charity")
        self.assertEqual(result["charity_amount"], "0.50")
        self.assertTrue(e.resolved)


class TestEscrowUnknownRuling(unittest.TestCase):
    def test_unknown_ruling_raises(self):
        e = Escrow("0.50", TERMS)
        with self.assertRaises(ValueError):
            e.resolve("nonsense")


class TestEscrowEdgeCases(unittest.TestCase):
    def test_zero_bounty(self):
        e = Escrow("0", TERMS)
        result = e.resolve("fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        self.assertEqual(result["agent_gets_bounty"], "0")

    def test_double_lock(self):
        e = Escrow("0.50", TERMS)
        e.lock()
        result = e.lock()
        self.assertTrue(e.locked)

    def test_tier_fee_exceeds_judge_fee(self):
        """Tier fee > judge_fee: loser gets 0 back, not negative."""
        e = Escrow("0.50", TERMS)
        e.lock()
        e.lock_agent()
        result = e.resolve("fulfilled", dispute_loser="agent",
                          tier_fee=Decimal("0.20"))
        self.assertEqual(result["loser_judge_fee_returned"], "0")


class TestEscrowManager(unittest.TestCase):
    def setUp(self):
        self.nano = make_nano_backend()
        self.mgr = EscrowManager(":memory:", payment_backend=self.nano)

    def tearDown(self):
        self.mgr.close()

    def _fund_and_set(self, cid, amount="0.67"):
        fund_escrow(self.mgr, cid, amount)
        set_funded_accounts(self.mgr, cid, TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)

    def test_lock_and_get(self):
        result = self.mgr.lock("c1", "0.50", TERMS)
        self.assertEqual(result["status"], "locked")
        state = self.mgr.get("c1")
        self.assertIsNotNone(state)
        self.assertEqual(state["bounty"], "0.50")
        self.assertEqual(state["inclusive_bond"], "0.67")
        self.assertTrue(state["locked"])
        self.assertFalse(state["resolved"])

    def test_lock_sets_principal_locked(self):
        self.mgr.lock("c1", "0.50", TERMS)
        state = self.mgr.get("c1")
        self.assertTrue(state["principal_locked"])

    def test_lock_with_judge_fee(self):
        self.mgr.lock("c1", "0.50", TERMS, judge_fee="0.17")
        state = self.mgr.get("c1")
        self.assertEqual(state["judge_fee"], "0.17")
        self.assertEqual(state["inclusive_bond"], "0.67")

    def test_lock_agent(self):
        self.mgr.lock("c1", "0.50", TERMS)
        result = self.mgr.lock_agent("c1")
        self.assertEqual(result["status"], "agent_locked")
        self.assertEqual(result["inclusive_bond"], "0.67")
        state = self.mgr.get("c1")
        self.assertTrue(state["agent_locked"])

    def test_release_agent(self):
        self.mgr.lock("c1", "0.50", TERMS)
        self.mgr.lock_agent("c1")
        result = self.mgr.release_agent("c1")
        self.assertEqual(result["status"], "agent_released")
        state = self.mgr.get("c1")
        self.assertFalse(state["agent_locked"])

    def test_lock_agent_nonexistent(self):
        with self.assertRaises(ValueError):
            self.mgr.lock_agent("nope")

    def test_release_agent_nonexistent(self):
        with self.assertRaises(ValueError):
            self.mgr.release_agent("nope")

    def test_resolve_fulfilled(self):
        self.mgr.lock("c1", "0.50", TERMS)
        self._fund_and_set("c1")
        result = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(result["action"], "release_to_agent")
        state = self.mgr.get("c1")
        self.assertTrue(state["resolved"])

    def test_resolve_voided(self):
        self.mgr.lock("c1", "0.50", TERMS)
        self.mgr.lock_agent("c1")
        self._fund_and_set("c1", "1.34")  # 2 * inclusive_bond
        result = self.mgr.resolve("c1", "voided")
        self.assertEqual(result["action"], "voided")

    def test_resolve_with_dispute(self):
        self.mgr.lock("c1", "0.50", TERMS, judge_fee="0.17")
        self.mgr.lock_agent("c1")
        self._fund_and_set("c1", "1.34")
        result = self.mgr.resolve("c1", "fulfilled", dispute_loser="principal", tier_fee="0.02")
        self.assertEqual(result["dispute_loser"], "principal")
        self.assertEqual(result["tier_fee_to_platform"], "0.02")

    def test_resolve_nonexistent_raises(self):
        with self.assertRaises(ValueError):
            self.mgr.resolve("nope", "fulfilled")

    def test_get_nonexistent(self):
        self.assertIsNone(self.mgr.get("nope"))

    def test_double_resolve_returns_cached(self):
        self.mgr.lock("c1", "0.50", TERMS)
        self._fund_and_set("c1")
        first = self.mgr.resolve("c1", "fulfilled")
        second = self.mgr.resolve("c1", "fulfilled")
        self.assertEqual(first["action"], second["action"])

    def test_resolve_unlocked_raises(self):
        self.mgr.db.execute(
            "INSERT INTO escrows (contract_id, bounty, terms, locked, inclusive_bond) VALUES (?, ?, ?, 0, ?)",
            ("c_unlocked", "0.50", '{"cancellation": {"grace_period": 30}}', "0.67"),
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
        self.mgr.lock("c1", "0.50", TERMS)
        fund_escrow(self.mgr, "c1")
        set_funded_accounts(self.mgr, "c1", TEST_PRINCIPAL_ADDR, TEST_AGENT_ADDR)
        self.mgr.resolve("c1", "fulfilled")
        result = self.mgr.set_accounts("c1", principal_account="new_addr")
        self.assertFalse(result)

    def test_set_accounts_nonexistent(self):
        result = self.mgr.set_accounts("no_such", principal_account="addr")
        self.assertFalse(result)

    def test_set_accounts_empty_both(self):
        self.mgr.lock("c1", "0.50", TERMS)
        result = self.mgr.set_accounts("c1")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
