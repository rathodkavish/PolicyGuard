"""Run from the project folder:  python -m unittest discover tests"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import checks

T = {"review_days": 90, "leaver_hours": 24, "dormant_days": 45}


def acct(**kw):
    base = {"account": "u1", "is_admin": False, "mfa": True, "review_days": 10, "login_days": 1,
            "enabled": True, "left": False, "disabled_after_hours": None}
    base.update(kw)
    return base


class CheckTests(unittest.TestCase):
    def test_r1_flags_admin_without_mfa(self):
        total, bad = checks.check_r1([acct(is_admin=True, mfa=False), acct(account="u2", is_admin=True)], T)
        self.assertEqual((total, len(bad)), (2, 1))

    def test_r2_flags_old_review(self):
        total, bad = checks.check_r2([acct(is_admin=True, review_days=120)], T)
        self.assertEqual(len(bad), 1)

    def test_r3_leaver_rules(self):
        accts = [acct(account="a", left=True, enabled=False, disabled_after_hours=5),
                 acct(account="b", left=True, enabled=False, disabled_after_hours=30),
                 acct(account="c", left=True, enabled=True)]
        total, bad = checks.check_r3(accts, T)
        self.assertEqual((total, sorted(x[0] for x in bad)), (3, ["b", "c"]))

    def test_r4_dormant(self):
        total, bad = checks.check_r4([acct(login_days=60), acct(account="u2", login_days=5)], T)
        self.assertEqual(len(bad), 1)

    def test_status(self):
        self.assertEqual(checks.status(100, 95), "GREEN")
        self.assertEqual(checks.status(96, 95), "AMBER")
        self.assertEqual(checks.status(80, 95), "RED")


if __name__ == "__main__":
    unittest.main()
