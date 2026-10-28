"""P1-P6 formal-property checks (unittest-discoverable)."""
import unittest, sys
sys.path.insert(0,".")
from bench import _pkg_for
from codec import (gen_key, make_quotation, make_amendment, verify_quotation,
                   statement_validity)

class FormalProps(unittest.TestCase):
    def _mk(self, valid=("2020-01-01","2021-01-01"), cspans=None):
        pkg, st, sp, rc, sk, rk = _pkg_for("A if B, though C.", cspans,
                                         valid=valid)
        return pkg, st, sp, rc
    def test_P1_expiry_preserves_signature(self):
        pkg, st, sp, rc = self._mk()
        st["body"]["valid_until"] = "2000-01-01"
        qt = make_quotation(rc, st, [[0, len("A if B, though C.")]],
                            "A if B, though C.", "pub")
        r = verify_quotation(pkg, qt, "2026-01-01")
        self.assertTrue(r["authenticity"])
        self.assertEqual(r["temporal"]["state"], "EXPIRED")
    def test_P3_as_known_deterministic(self):
        pkg, st, sp, rc = self._mk()
        a1 = statement_validity(pkg, st, "2020-06-01", "2020-06-15")
        a2 = statement_validity(pkg, st, "2020-06-01", "2020-06-15")
        self.assertEqual(a1, a2)
    def test_P4_retraction_not_retroactive(self):
        pkg, st, sp, rc = self._mk()
        r = make_amendment(sp, st["body"]["statement_id"], "retraction",
                           "x", "speaker", "2020-12-01", "2020-12-02")
        pkg["objects"].append(r)
        past = statement_validity(pkg, st, "2020-06-01", "2020-06-15")
        now = statement_validity(pkg, st, "2021-01-05", "2021-01-10")
        self.assertNotEqual(past["state"], "WITHDRAWN")
        self.assertEqual(now["state"], "WITHDRAWN")
if __name__ == "__main__":
    unittest.main()
