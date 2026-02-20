"""Tests for server/reputation.py — reputation tracking."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "server"))

import unittest
from decimal import Decimal
from server.reputation import ReputationStats, ReputationManager


class TestReputationStatsDefaults(unittest.TestCase):
    def test_defaults(self):
        s = ReputationStats()
        self.assertEqual(s.agent_fulfilled, 0)
        self.assertEqual(s.agent_canceled, 0)
        self.assertEqual(s.agent_backed_out, 0)
        self.assertEqual(s.principal_fulfilled, 0)
        self.assertEqual(s.principal_canceled, 0)
        self.assertEqual(s.disputes_won, 0)
        self.assertEqual(s.disputes_lost, 0)
        self.assertEqual(s.evil_flags, 0)
        self.assertEqual(s.total_earned, Decimal("0"))
        self.assertEqual(s.total_spent, Decimal("0"))


class TestReputationStatsSerialization(unittest.TestCase):
    def test_roundtrip(self):
        s = ReputationStats(
            agent_fulfilled=5, agent_canceled=1, agent_backed_out=2,
            principal_fulfilled=3, principal_canceled=1,
            disputes_won=2, disputes_lost=1,
            evil_flags=0,
            total_earned=Decimal("1.5"), total_spent=Decimal("0.8"),
        )
        d = s.to_dict()
        s2 = ReputationStats.from_dict(d)
        self.assertEqual(s2.agent_fulfilled, 5)
        self.assertEqual(s2.agent_canceled, 1)
        self.assertEqual(s2.agent_backed_out, 2)
        self.assertEqual(s2.principal_fulfilled, 3)
        self.assertEqual(s2.principal_canceled, 1)
        self.assertEqual(s2.disputes_won, 2)
        self.assertEqual(s2.disputes_lost, 1)
        self.assertEqual(s2.evil_flags, 0)
        self.assertEqual(s2.total_earned, Decimal("1.5"))
        self.assertEqual(s2.total_spent, Decimal("0.8"))

    def test_from_dict_empty(self):
        s = ReputationStats.from_dict({})
        self.assertEqual(s.agent_fulfilled, 0)
        self.assertEqual(s.total_earned, Decimal("0"))


class TestCompletionRate(unittest.TestCase):
    def test_no_history(self):
        s = ReputationStats()
        self.assertEqual(s.completion_rate(), 1.0)

    def test_perfect(self):
        s = ReputationStats(agent_fulfilled=10)
        self.assertEqual(s.completion_rate(), 1.0)

    def test_mixed(self):
        s = ReputationStats(agent_fulfilled=7, agent_canceled=2, agent_backed_out=1)
        self.assertAlmostEqual(s.completion_rate(), 0.7)

    def test_zero_fulfilled(self):
        s = ReputationStats(agent_canceled=3, agent_backed_out=2)
        self.assertEqual(s.completion_rate(), 0.0)


class TestTotalJobs(unittest.TestCase):
    def test_total_jobs(self):
        s = ReputationStats(agent_fulfilled=5, agent_canceled=2, agent_backed_out=1)
        self.assertEqual(s.total_jobs(), 8)

    def test_total_jobs_empty(self):
        s = ReputationStats()
        self.assertEqual(s.total_jobs(), 0)


class TestReputationManager(unittest.TestCase):
    def setUp(self):
        self.mgr = ReputationManager(":memory:")

    def tearDown(self):
        self.mgr.close()

    def test_nonexistent_pubkey_returns_defaults(self):
        s = self.mgr.query("unknown_key")
        self.assertEqual(s.agent_fulfilled, 0)
        self.assertEqual(s.total_earned, Decimal("0"))
        self.assertEqual(s.completion_rate(), 1.0)

    def test_record_agent_fulfilled(self):
        self.mgr.record("agent1", "agent", "fulfilled", amount=Decimal("0.05"))
        s = self.mgr.query("agent1")
        self.assertEqual(s.agent_fulfilled, 1)
        self.assertEqual(s.total_earned, Decimal("0.05"))

    def test_record_agent_canceled(self):
        self.mgr.record("agent1", "agent", "canceled")
        s = self.mgr.query("agent1")
        self.assertEqual(s.agent_canceled, 1)

    def test_record_agent_backed_out(self):
        self.mgr.record("agent1", "agent", "backed_out")
        s = self.mgr.query("agent1")
        self.assertEqual(s.agent_backed_out, 1)

    def test_record_agent_evil_flag(self):
        self.mgr.record("agent1", "agent", "evil_flag")
        s = self.mgr.query("agent1")
        self.assertEqual(s.evil_flags, 1)

    def test_record_agent_dispute_won(self):
        self.mgr.record("agent1", "agent", "dispute_won", amount=Decimal("0.03"))
        s = self.mgr.query("agent1")
        self.assertEqual(s.disputes_won, 1)
        self.assertEqual(s.total_earned, Decimal("0.03"))

    def test_record_agent_dispute_lost(self):
        self.mgr.record("agent1", "agent", "dispute_lost")
        s = self.mgr.query("agent1")
        self.assertEqual(s.disputes_lost, 1)

    def test_record_principal_fulfilled(self):
        self.mgr.record("p1", "principal", "fulfilled", amount=Decimal("0.10"))
        s = self.mgr.query("p1")
        self.assertEqual(s.principal_fulfilled, 1)
        self.assertEqual(s.total_spent, Decimal("0.10"))

    def test_record_principal_canceled(self):
        self.mgr.record("p1", "principal", "canceled")
        s = self.mgr.query("p1")
        self.assertEqual(s.principal_canceled, 1)

    def test_record_principal_dispute_won(self):
        self.mgr.record("p1", "principal", "dispute_won")
        s = self.mgr.query("p1")
        self.assertEqual(s.disputes_won, 1)

    def test_record_principal_dispute_lost(self):
        self.mgr.record("p1", "principal", "dispute_lost", amount=Decimal("0.05"))
        s = self.mgr.query("p1")
        self.assertEqual(s.disputes_lost, 1)
        self.assertEqual(s.total_spent, Decimal("0.05"))

    def test_record_principal_evil_flag(self):
        self.mgr.record("p1", "principal", "evil_flag")
        s = self.mgr.query("p1")
        self.assertEqual(s.evil_flags, 1)

    def test_meets_threshold_new_user(self):
        self.assertTrue(self.mgr.meets_threshold("new_user"))

    def test_meets_threshold_good_agent(self):
        for _ in range(9):
            self.mgr.record("good", "agent", "fulfilled")
        self.mgr.record("good", "agent", "canceled")
        self.assertTrue(self.mgr.meets_threshold("good", min_rate=0.9))

    def test_meets_threshold_bad_rate(self):
        for _ in range(5):
            self.mgr.record("bad", "agent", "fulfilled")
        for _ in range(5):
            self.mgr.record("bad", "agent", "canceled")
        self.assertFalse(self.mgr.meets_threshold("bad", min_rate=0.9))

    def test_meets_threshold_evil_flags(self):
        self.mgr.record("evil", "agent", "evil_flag")
        self.assertFalse(self.mgr.meets_threshold("evil", max_flags=0))
        self.assertTrue(self.mgr.meets_threshold("evil", max_flags=1))

    def test_persistence_across_records(self):
        self.mgr.record("a1", "agent", "fulfilled", amount=Decimal("0.01"))
        self.mgr.record("a1", "agent", "fulfilled", amount=Decimal("0.02"))
        self.mgr.record("a1", "agent", "canceled")
        s = self.mgr.query("a1")
        self.assertEqual(s.agent_fulfilled, 2)
        self.assertEqual(s.agent_canceled, 1)
        self.assertEqual(s.total_earned, Decimal("0.03"))


if __name__ == "__main__":
    unittest.main()
